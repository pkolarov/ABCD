// ctaphid_transport.h
// CTAPHID (USB HID) transport for raw CTAP2 — the missing piece that lets the
// bridge (LocalSystem, session 0) talk to a FIDO2 authenticator directly,
// WITHOUT webauthn.dll's Interactive-User UX broker. This is the transport used
// by the pre-first-logon fallback and by the hmac-secret parity self-test.
//
// Reference: FIDO CTAP v2.1, §11.2 "USB HID (CTAPHID)".
//
// Framing (report data area is HID_RPT_SIZE = 64 bytes):
//   Initialization packet: CID(4) | CMD(1, high bit set) | BCNTH(1) | BCNTL(1) | data(0..57)
//   Continuation packet:   CID(4) | SEQ(1, 0..0x7f)                 | data(0..59)
// On Windows every HID report is prefixed with a 1-byte report ID (0x00 here),
// so the WriteFile/ReadFile buffers are 1 + 64 = 65 bytes.
//

#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>

// CTAPHID command bytes (high bit is set on the wire in the init packet).
namespace CTAPHID_CMD
{
    constexpr uint8_t PING      = 0x81;
    constexpr uint8_t MSG       = 0x83;
    constexpr uint8_t INIT      = 0x86;
    constexpr uint8_t CBOR      = 0x90;
    constexpr uint8_t CANCEL    = 0x91;
    constexpr uint8_t KEEPALIVE = 0xBB;
    constexpr uint8_t ERR       = 0xBF;  // CTAPHID_ERROR (ERROR is a Win32 macro)
}

// A single opened FIDO2 USB-HID authenticator plus its allocated CTAPHID channel.
// Not thread-safe; drive it from one thread. Non-copyable and non-movable (a
// user-declared destructor suppresses the implicit move operations); owns a file
// handle freed in the destructor.
class CCtapHidDevice
{
public:
    CCtapHidDevice() = default;
    ~CCtapHidDevice();

    CCtapHidDevice(const CCtapHidDevice&) = delete;
    CCtapHidDevice& operator=(const CCtapHidDevice&) = delete;

    // Enumerate present HID interfaces, open the first whose top-level collection
    // advertises the FIDO usage page (0xF1D0), and run CTAPHID_INIT to allocate a
    // channel. Returns false (with outError set) if no authenticator is found or
    // the INIT handshake fails.
    bool OpenFirst(std::string& outError);

    void Close();
    bool IsOpen() const { return m_handle != INVALID_HANDLE_VALUE; }

    // Optional caller-owned manual-reset event; when signaled, any in-flight or
    // subsequent blocking read/write aborts promptly (CancelIoEx) and the call
    // fails with a "cancelled" error. Lets a service cancel a getAssertion that
    // is waiting for the user's touch instead of blocking for the full timeout.
    void SetCancelEvent(HANDLE hCancel) { m_hCancel = hCancel; }
    bool WasCancelled() const { return m_cancelled; }

    // Send a CTAP2 command (command byte + CBOR params, exactly what
    // CCtap2Protocol::Build*Command produces) via CTAPHID_CBOR and return the raw
    // CTAP2 response (status byte + CBOR). Handles KEEPALIVE frames while the user
    // is being prompted for presence/verification, bounded by timeoutMs overall.
    // If pTimedOut is non-null it is set to true iff the failure was the overall
    // deadline expiring (e.g. the user never touched the key) rather than a
    // protocol/transport error — lets callers treat "no touch" as inconclusive.
    bool Cbor(const std::vector<uint8_t>& command,
              std::vector<uint8_t>& response,
              DWORD timeoutMs,
              std::string& outError,
              bool* pTimedOut = nullptr);

private:
    bool Init(std::string& outError);

    // Write one logical CTAPHID message (splitting into init + continuation
    // packets) on the current channel, bounded by an absolute GetTickCount64
    // deadline.
    bool WriteMessage(uint8_t cmd, const uint8_t* data, size_t len,
                      ULONGLONG deadlineTick, std::string& outError);

    // Read one logical CTAPHID message (reassembling continuation packets),
    // ignoring frames on other channels. Returns the full command byte (bit 7
    // included) and payload. deadlineTick is a GetTickCount64 absolute deadline.
    bool ReadMessage(uint8_t& outCmd, std::vector<uint8_t>& outData,
                     ULONGLONG deadlineTick, std::string& outError);

    // One raw 64-byte frame in / out (prepends/strips the report-ID byte),
    // bounded by an absolute GetTickCount64 deadline.
    bool WriteFrame(const uint8_t frame[64], ULONGLONG deadlineTick, std::string& outError);
    bool ReadFrame(uint8_t frame[64], ULONGLONG deadlineTick, std::string& outError);

    HANDLE   m_handle{ INVALID_HANDLE_VALUE };
    uint32_t m_cid{ 0xFFFFFFFF };   // broadcast until INIT allocates a channel
    USHORT   m_outLen{ 65 };        // OutputReportByteLength (report-ID + 64)
    USHORT   m_inLen{ 65 };         // InputReportByteLength
    HANDLE   m_hCancel{ nullptr };  // optional external cancel event (not owned)
    bool     m_cancelled{ false };  // set once a wait observed the cancel event
};
