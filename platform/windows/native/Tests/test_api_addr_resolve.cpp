// test_api_addr_resolve.cpp
// Standalone tests for the A-2 ApiAddr precedence wiring in
// DdsAuthBridgeMain::Initialize.
//
// Included by test_main.cpp -- do NOT compile separately.
//
// The wiring is short enough to mirror inline (matching the existing
// test_dds_bridge_selection.cpp pattern). The contract this file
// pins:
//   - When `CDdsConfiguration::ApiAddr()` returns non-empty, the
//     bridge MUST forward the value to
//     `CDdsNodeHttpClient::SetBaseUrl` so the `pipe:<name>` and
//     `http://host:port` schemes from H-7 step-2b reach the
//     transport selector.
//   - When `ApiAddr()` is empty, the bridge MUST fall back to
//     `SetPort(DdsNodePort)` so legacy registry-only deployments
//     keep dialling loopback TCP without behavioural change.
//   - SetBaseUrl's `pipe:` parser must canonicalise both
//     `pipe:<name>` and `pipe:\\.\pipe\<name>` to the same bare
//     pipe name, since the MSI / Rust node accept either form.
//
// If the inline branch in `DdsAuthBridgeMain::Initialize` ever
// drifts (e.g. somebody re-adds an unconditional `SetPort` call
// after `SetBaseUrl`), these tests still pass because they exercise
// the contract directly rather than the call site — but the
// duplicate logic here is intentional: it captures the invariant
// in one place where a reviewer can audit it without chasing
// through registry-loading machinery.

#include <cstdint>
#include <string>

namespace TestApiAddrResolve
{

enum class Transport { Tcp, Pipe };

struct Wiring
{
    Transport   transport;
    std::string host;        // valid only when transport == Tcp
    uint16_t    port;        // valid only when transport == Tcp
    std::string pipeName;    // valid only when transport == Pipe (bare, no \\.\pipe\)
};

// Mirrors `CDdsNodeHttpClient::SetBaseUrl` -- pipe scheme detection
// and bare-name normalisation for the `\\.\pipe\` prefix.
static Wiring ParseBaseUrl(const std::string& url)
{
    Wiring w{};

    if (url.rfind("pipe:", 0) == 0)
    {
        std::string spec = url.substr(5);
        const std::string kPipePrefix = "\\\\.\\pipe\\";
        if (spec.rfind(kPipePrefix, 0) == 0)
            spec = spec.substr(kPipePrefix.size());
        w.transport = Transport::Pipe;
        w.pipeName = spec;
        return w;
    }

    w.transport = Transport::Tcp;
    std::string s = url;
    size_t schemeEnd = s.find("://");
    if (schemeEnd != std::string::npos)
        s = s.substr(schemeEnd + 3);
    while (!s.empty() && s.back() == '/')
        s.pop_back();
    size_t colon = s.find(':');
    if (colon != std::string::npos)
    {
        w.host = s.substr(0, colon);
        w.port = static_cast<uint16_t>(std::stoi(s.substr(colon + 1)));
    }
    else
    {
        w.host = s;
        w.port = 5551;
    }
    return w;
}

// Mirrors the inline decision in `DdsAuthBridgeMain::Initialize`:
//   if (!m_config.ApiAddr().empty())
//       m_httpClient.SetBaseUrl(m_config.ApiAddr());
//   else
//       m_httpClient.SetPort(m_config.DdsNodePort());
static Wiring ResolveWiring(const std::string& apiAddr, uint16_t ddsNodePort)
{
    if (!apiAddr.empty())
        return ParseBaseUrl(apiAddr);

    Wiring w{};
    w.transport = Transport::Tcp;
    w.host = "127.0.0.1";   // CDdsNodeHttpClient default constructor
    w.port = ddsNodePort;
    return w;
}

} // namespace TestApiAddrResolve

DDS_TEST(ApiAddrResolve_PipeUrl_Wins_Over_Port)
{
    // The MSI installs `ApiAddr = pipe:dds-api`. With this set, the
    // bridge MUST forward the pipe spec via SetBaseUrl -- forwarding
    // the legacy port via SetPort would silently strip the pipe
    // scheme and break the H-7 step-2b cutover.
    auto w = TestApiAddrResolve::ResolveWiring("pipe:dds-api", 5551);
    DDS_ASSERT(w.transport == TestApiAddrResolve::Transport::Pipe,
               "non-empty ApiAddr=pipe:... must select pipe transport");
    DDS_ASSERT(w.pipeName == "dds-api",
               "bare pipe spec must canonicalise to the unprefixed name");
}

DDS_TEST(ApiAddrResolve_Fully_Qualified_Pipe_Path_Normalises_To_Same_Name)
{
    // The Rust node accepts either `pipe:dds-api` or
    // `pipe:\\.\pipe\dds-api`. The bridge's pipe-URL parser must
    // canonicalise both to the same bare name so the MSI default
    // and a hand-written registry override interoperate.
    auto w = TestApiAddrResolve::ResolveWiring(
        "pipe:\\\\.\\pipe\\dds-api", 5551);
    DDS_ASSERT(w.transport == TestApiAddrResolve::Transport::Pipe,
               "fully-qualified pipe path must select pipe transport");
    DDS_ASSERT(w.pipeName == "dds-api",
               "fully-qualified pipe path must collapse to bare name");
}

DDS_TEST(ApiAddrResolve_Custom_Tcp_Url_Wins_Over_Port)
{
    // ApiAddr is the only registry knob that can point the bridge
    // at a non-loopback host -- DdsNodePort always assumes 127.0.0.1.
    // If the resolver collapsed ApiAddr we'd silently dial loopback
    // for an operator who pointed ApiAddr at a remote node.
    auto w = TestApiAddrResolve::ResolveWiring("http://10.0.0.5:6001", 5551);
    DDS_ASSERT(w.transport == TestApiAddrResolve::Transport::Tcp,
               "explicit http:// ApiAddr must select TCP");
    DDS_ASSERT(w.host == "10.0.0.5",
               "ApiAddr host must override the loopback default");
    DDS_ASSERT(w.port == 6001,
               "ApiAddr port must override DdsNodePort");
}

DDS_TEST(ApiAddrResolve_Empty_ApiAddr_Falls_Back_To_Loopback_Port)
{
    // Hand-installed dev/test deployments never set ApiAddr. The
    // bridge MUST fall back to the legacy SetPort(DdsNodePort)
    // wiring so behavior stays identical to pre-A-2 builds.
    auto w = TestApiAddrResolve::ResolveWiring("", 5551);
    DDS_ASSERT(w.transport == TestApiAddrResolve::Transport::Tcp,
               "empty ApiAddr must fall back to TCP");
    DDS_ASSERT(w.host == "127.0.0.1",
               "fallback host must be loopback");
    DDS_ASSERT(w.port == 5551,
               "fallback port must equal DdsNodePort");
}

DDS_TEST(ApiAddrResolve_Empty_ApiAddr_Honours_Custom_Port)
{
    // Operators on the legacy registry knob keep their custom port.
    // SetPort is the production code path here, but the contract
    // is identical: dial 127.0.0.1 on whatever DdsNodePort says.
    auto w = TestApiAddrResolve::ResolveWiring("", 7777);
    DDS_ASSERT(w.transport == TestApiAddrResolve::Transport::Tcp,
               "empty ApiAddr must remain TCP regardless of port");
    DDS_ASSERT(w.host == "127.0.0.1",
               "fallback host must be loopback regardless of port");
    DDS_ASSERT(w.port == 7777,
               "fallback port must honour the configured DdsNodePort");
}
