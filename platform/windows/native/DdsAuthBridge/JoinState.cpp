// JoinState.cpp
// Probe implementation. Mirrors the managed
// WindowsJoinStateProbe (DdsPolicyAgent/HostState/WindowsJoinStateProbe.cs)
// so the policy agent and the auth bridge agree on host
// classification on every box.

#include "JoinState.h"
#include "FileLog.h"

#include <lm.h>      // NetGetJoinInformation, NET_API_STATUS, NERR_Success
#include <lmjoin.h>  // DSREG_JOIN_INFO, NetGetAadJoinInformation
#include <mutex>

#pragma comment(lib, "netapi32.lib")

namespace dds {

namespace {

enum class AdSignal { Workgroup, Domain, ProbeFailed };
enum class EntraSignal { None, DeviceJoined, WorkplaceJoined, ProbeFailed };

AdSignal ProbeAdSignal()
{
    LPWSTR pBuffer = nullptr;
    NETSETUP_JOIN_STATUS status = NetSetupUnknownStatus;

    NET_API_STATUS rc = NetGetJoinInformation(nullptr, &pBuffer, &status);
    if (pBuffer) NetApiBufferFree(pBuffer);

    if (rc != NERR_Success)
        return AdSignal::ProbeFailed;

    switch (status)
    {
        case NetSetupDomainName:    return AdSignal::Domain;
        case NetSetupWorkgroupName: return AdSignal::Workgroup;
        case NetSetupUnjoined:      return AdSignal::Workgroup;
        case NetSetupUnknownStatus:
        default:
            return AdSignal::ProbeFailed;
    }
}

// Dynamically load NetGetAadJoinInformation / NetFreeAadJoinInformation
// so we degrade gracefully on hosts where the symbols are missing
// (very old SKUs, Server Core without the AAD module).
typedef HRESULT (WINAPI *PFN_NetGetAadJoinInformation)(LPCWSTR, PDSREG_JOIN_INFO*);
typedef VOID    (WINAPI *PFN_NetFreeAadJoinInformation)(PDSREG_JOIN_INFO);

struct EntraApi
{
    HMODULE hMod = nullptr;
    PFN_NetGetAadJoinInformation  pGet  = nullptr;
    PFN_NetFreeAadJoinInformation pFree = nullptr;
    bool resolved = false;

    void Resolve()
    {
        if (resolved) return;
        resolved = true;
        hMod = LoadLibraryW(L"netapi32.dll");
        if (!hMod) return;
        pGet  = reinterpret_cast<PFN_NetGetAadJoinInformation>(
            GetProcAddress(hMod, "NetGetAadJoinInformation"));
        pFree = reinterpret_cast<PFN_NetFreeAadJoinInformation>(
            GetProcAddress(hMod, "NetFreeAadJoinInformation"));
    }
};

EntraSignal ProbeEntraSignal()
{
    static EntraApi api;
    static std::once_flag onceResolve;
    std::call_once(onceResolve, [] { api.Resolve(); });

    if (!api.pGet)
    {
        // Symbol missing — treat as no Entra signal, NOT ProbeFailed.
        return EntraSignal::None;
    }

    PDSREG_JOIN_INFO pInfo = nullptr;
    HRESULT hr = api.pGet(nullptr, &pInfo);

    // Classification contract (spec §2.2, mirrored in
    // WindowsJoinStateProbe.ClassifyAadJoinResult): "device has no
    // Entra record" is a normal answer, not a malfunction, in all of
    // its wire shapes — DSREG_E_DEVICE_NOT_JOINED, or any success
    // code (S_OK, and S_FALSE as observed in the field on
    // never-Entra-registered workgroup machines) with NULL info.
    // Every other error HRESULT is a genuine probe failure and must
    // classify Unknown, fail-closed.
    if (FAILED(hr))
    {
        if (pInfo && api.pFree) api.pFree(pInfo);
        constexpr HRESULT kDsregEDeviceNotJoined =
            static_cast<HRESULT>(0x801C001DL);
        if (hr == kDsregEDeviceNotJoined)
            return EntraSignal::None;
        // ProbeFailed classifies the host Unknown, and AD-08 refuses
        // auth on Unknown — log the hr so a refusal is diagnosable from
        // authbridge.log. `host_state_probe_failed` is the token the
        // operator runbook (windows-ad-enrollment.md §2.4) greps for.
        FileLog::Writef("JoinState: host_state_probe_failed NetGetAadJoinInformation hr=0x%08lX\n",
                        static_cast<unsigned long>(hr));
        return EntraSignal::ProbeFailed;
    }
    if (!pInfo)
    {
        // Success (S_OK / S_FALSE) with NULL info = no Entra signal.
        return EntraSignal::None;
    }

    EntraSignal result;
    switch (pInfo->joinType)
    {
        case DSREG_DEVICE_JOIN:    result = EntraSignal::DeviceJoined;    break;
        case DSREG_WORKPLACE_JOIN: result = EntraSignal::WorkplaceJoined; break;
        case DSREG_UNKNOWN_JOIN:   result = EntraSignal::ProbeFailed;     break;
        default:                   result = EntraSignal::None;            break;
    }

    if (api.pFree) api.pFree(pInfo);
    return result;
}

JoinState ClassifyFromSignals(AdSignal ad, EntraSignal entra)
{
    if (ad == AdSignal::ProbeFailed || entra == EntraSignal::ProbeFailed)
        return JoinState::Unknown;

    const bool hasAd            = (ad == AdSignal::Domain);
    const bool hasEntraDevice   = (entra == EntraSignal::DeviceJoined);
    const bool hasWorkplaceOnly = (entra == EntraSignal::WorkplaceJoined);

    if (hasAd && (hasEntraDevice || hasWorkplaceOnly))
        return JoinState::HybridJoined;
    if (hasAd)
        return JoinState::AdJoined;
    if (hasEntraDevice)
        return JoinState::EntraOnlyJoined;

    // workplace-registered-only OR no signal — both classify as
    // Workgroup. Workplace registration alone does not disable normal
    // workgroup behavior (spec §2.2 / §L5).
    return JoinState::Workgroup;
}

// Cache state.
std::mutex      g_cacheMutex;
bool            g_cachePrimed = false;
JoinState       g_cached      = JoinState::Workgroup;
#ifdef DDS_TESTING
bool            g_testOverride = false;
#endif

} // namespace

const wchar_t* JoinStateName(JoinState state)
{
    switch (state)
    {
        case JoinState::Workgroup:       return L"Workgroup";
        case JoinState::AdJoined:        return L"AdJoined";
        case JoinState::HybridJoined:    return L"HybridJoined";
        case JoinState::EntraOnlyJoined: return L"EntraOnlyJoined";
        case JoinState::Unknown:         return L"Unknown";
    }
    return L"<invalid>";
}

JoinState DetectJoinState()
{
    return ClassifyFromSignals(ProbeAdSignal(), ProbeEntraSignal());
}

JoinState GetCachedJoinState()
{
    std::lock_guard<std::mutex> lk(g_cacheMutex);
#ifdef DDS_TESTING
    if (g_testOverride) return g_cached;
#endif
    if (!g_cachePrimed)
    {
        g_cached = DetectJoinState();
        // Do not latch Unknown: a transient dsreg/netapi hiccup at first
        // probe (often during early boot) must not refuse DDS sign-in for
        // the rest of the service lifetime. Leaving the cache unprimed
        // makes the next request re-probe; a classifiable result primes
        // the cache as before.
        g_cachePrimed = (g_cached != JoinState::Unknown);
    }
    return g_cached;
}

void RefreshJoinState()
{
    JoinState fresh = DetectJoinState();
    std::lock_guard<std::mutex> lk(g_cacheMutex);
#ifdef DDS_TESTING
    if (g_testOverride) return;  // tests pin a value; refresh does nothing
#endif
    g_cached = fresh;
    // Same no-latch rule as GetCachedJoinState.
    g_cachePrimed = (fresh != JoinState::Unknown);
}

#ifdef DDS_TESTING
void SetJoinStateForTest(JoinState state)
{
    std::lock_guard<std::mutex> lk(g_cacheMutex);
    g_cached = state;
    g_cachePrimed = true;
    g_testOverride = true;
}
#endif

} // namespace dds
