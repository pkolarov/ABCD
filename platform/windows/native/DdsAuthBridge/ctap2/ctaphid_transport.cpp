// ctaphid_transport.cpp
// CTAPHID (USB HID) transport for raw CTAP2. See header for framing details.

#include "ctaphid_transport.h"
#include "../FileLog.h"

#include <setupapi.h>
#include <hidsdi.h>
#include <bcrypt.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")
#pragma comment(lib, "bcrypt.lib")

// FIDO Alliance HID usage page + usage for the CTAPHID top-level collection.
static const USHORT FIDO_USAGE_PAGE = 0xF1D0;
static const USHORT FIDO_USAGE      = 0x01;

// HID report data area for CTAPHID (excludes the Windows report-ID prefix byte).
static const size_t   HID_RPT_SIZE = 64;
static const uint32_t CTAPHID_BROADCAST_CID = 0xFFFFFFFF;
static const size_t   CTAP_MAX_MSG = 7609;  // CTAPHID max transaction size (spec §11.2)

static const uint8_t CTAPHID_KEEPALIVE_UPNEEDED = 0x02;   // "touch your key"

CCtapHidDevice::~CCtapHidDevice()
{
    Close();
}

void CCtapHidDevice::Close()
{
    if (m_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
    }
    m_cid = CTAPHID_BROADCAST_CID;
}

bool CCtapHidDevice::OpenFirst(std::string& outError)
{
    Close();

    GUID hidGuid;
    HidD_GetHidGuid(&hidGuid);

    HDEVINFO hDev = SetupDiGetClassDevsW(
        &hidGuid, nullptr, nullptr, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (hDev == INVALID_HANDLE_VALUE)
    {
        outError = "SetupDiGetClassDevs failed";
        return false;
    }

    bool opened = false;
    SP_DEVICE_INTERFACE_DATA ifData{};
    ifData.cbSize = sizeof(ifData);

    for (DWORD i = 0;
         !opened && SetupDiEnumDeviceInterfaces(hDev, nullptr, &hidGuid, i, &ifData);
         ++i)
    {
        DWORD reqSize = 0;
        SetupDiGetDeviceInterfaceDetailW(hDev, &ifData, nullptr, 0, &reqSize, nullptr);
        if (reqSize == 0) continue;

        std::vector<BYTE> buf(reqSize);
        auto* detail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buf.data());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        if (!SetupDiGetDeviceInterfaceDetailW(hDev, &ifData, detail, reqSize, nullptr, nullptr))
            continue;

        // Overlapped so reads/writes can honor a timeout (keys can take seconds
        // to be touched; a missing frame must not block forever).
        HANDLE h = CreateFileW(
            detail->DevicePath, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            continue;

        bool isFido = false;
        USHORT outLen = 65, inLen = 65;
        PHIDP_PREPARSED_DATA pd = nullptr;
        if (HidD_GetPreparsedData(h, &pd))
        {
            HIDP_CAPS caps{};
            if (HidP_GetCaps(pd, &caps) == HIDP_STATUS_SUCCESS &&
                caps.UsagePage == FIDO_USAGE_PAGE && caps.Usage == FIDO_USAGE)
            {
                isFido = true;
                outLen = caps.OutputReportByteLength;
                inLen  = caps.InputReportByteLength;
            }
            HidD_FreePreparsedData(pd);
        }

        if (!isFido)
        {
            CloseHandle(h);
            continue;
        }

        // A conformant CTAPHID report is report-ID(1) + 64 data bytes = 65.
        // CTAPHID mandates report ID 0, so we always write a 0x00 prefix byte and
        // strip the leading byte on read (see WriteFrame/ReadFrame).
        if (outLen < HID_RPT_SIZE + 1 || inLen < HID_RPT_SIZE + 1)
        {
            FileLog::Writef("ctaphid: skipping FIDO device with odd report lengths "
                            "(out=%u in=%u)\n", (unsigned)outLen, (unsigned)inLen);
            CloseHandle(h);
            continue;
        }

        m_handle = h;
        m_outLen = outLen;
        m_inLen  = inLen;
        opened   = true;
    }

    SetupDiDestroyDeviceInfoList(hDev);

    if (!opened)
    {
        outError = "no FIDO2 USB-HID authenticator found";
        return false;
    }

    if (!Init(outError))
    {
        Close();
        return false;
    }
    return true;
}

bool CCtapHidDevice::Init(std::string& outError)
{
    // CTAPHID_INIT on the broadcast channel with an 8-byte nonce; the response
    // echoes the nonce and carries the newly allocated 4-byte channel id.
    uint8_t nonce[8]{};
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, nonce, sizeof(nonce),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
        outError = "BCryptGenRandom(nonce) failed";
        return false;
    }

    const ULONGLONG deadline = GetTickCount64() + 3000;

    m_cid = CTAPHID_BROADCAST_CID;
    if (!WriteMessage(CTAPHID_CMD::INIT, nonce, sizeof(nonce), deadline, outError))
        return false;

    for (;;)
    {
        uint8_t cmd = 0;
        std::vector<uint8_t> data;
        if (!ReadMessage(cmd, data, deadline, outError))
            return false;

        if (cmd == CTAPHID_CMD::KEEPALIVE)
            continue; // unexpected during INIT, but tolerate

        if (cmd != CTAPHID_CMD::INIT)
        {
            // A stray response for another command — keep waiting until deadline.
            if (GetTickCount64() >= deadline) { outError = "INIT: timeout"; return false; }
            continue;
        }

        // INIT response: nonce(8) | newCID(4) | protoVer(1) | major | minor | build | caps
        if (data.size() < 17) { outError = "INIT: short response"; return false; }
        if (memcmp(data.data(), nonce, 8) != 0)
        {
            // Response to a different platform's INIT; ignore and keep waiting.
            if (GetTickCount64() >= deadline) { outError = "INIT: nonce never matched"; return false; }
            continue;
        }

        m_cid = (uint32_t)data[8] | ((uint32_t)data[9] << 8) |
                ((uint32_t)data[10] << 16) | ((uint32_t)data[11] << 24);
        FileLog::Writef("ctaphid: INIT ok, channel=0x%08lX\n", (unsigned long)m_cid);
        return true;
    }
}

bool CCtapHidDevice::Cbor(const std::vector<uint8_t>& command,
                          std::vector<uint8_t>& response,
                          DWORD timeoutMs,
                          std::string& outError,
                          bool* pTimedOut)
{
    if (pTimedOut) *pTimedOut = false;
    if (m_handle == INVALID_HANDLE_VALUE) { outError = "device not open"; return false; }

    const ULONGLONG deadline = GetTickCount64() + timeoutMs;

    if (!WriteMessage(CTAPHID_CMD::CBOR, command.data(), command.size(), deadline, outError))
        return false;

    for (;;)
    {
        uint8_t cmd = 0;
        std::vector<uint8_t> data;
        if (!ReadMessage(cmd, data, deadline, outError))
        {
            if (pTimedOut && GetTickCount64() >= deadline) *pTimedOut = true;
            // Best-effort: tell the authenticator to abandon the pending
            // getAssertion so the key stops blinking. Ignore any error.
            std::string ignore;
            ULONGLONG cancelDeadline = GetTickCount64() + 500;
            WriteMessage(CTAPHID_CMD::CANCEL, nullptr, 0, cancelDeadline, ignore);
            return false;
        }

        if (cmd == CTAPHID_CMD::KEEPALIVE)
        {
            if (!data.empty() && data[0] == CTAPHID_KEEPALIVE_UPNEEDED)
                FileLog::Write("ctaphid: KEEPALIVE — touch your security key\n");
            continue;
        }

        if (cmd == CTAPHID_CMD::ERR)
        {
            char msg[64];
            sprintf_s(msg, "CTAPHID_ERROR 0x%02X", data.empty() ? 0 : data[0]);
            outError = msg;
            return false;
        }

        if (cmd == CTAPHID_CMD::CBOR)
        {
            response = std::move(data);
            return true;
        }

        // Unrelated frame — ignore until the deadline.
        if (GetTickCount64() >= deadline) { outError = "CBOR: timeout waiting for response"; return false; }
    }
}

bool CCtapHidDevice::WriteMessage(uint8_t cmd, const uint8_t* data, size_t len,
                                  ULONGLONG deadlineTick, std::string& outError)
{
    uint8_t frame[64];

    // Initialization packet.
    memset(frame, 0, sizeof(frame));
    frame[0] = (uint8_t)(m_cid & 0xFF);
    frame[1] = (uint8_t)((m_cid >> 8) & 0xFF);
    frame[2] = (uint8_t)((m_cid >> 16) & 0xFF);
    frame[3] = (uint8_t)((m_cid >> 24) & 0xFF);
    frame[4] = (uint8_t)(cmd | 0x80);          // init packet: command, high bit set
    frame[5] = (uint8_t)((len >> 8) & 0xFF);   // BCNTH
    frame[6] = (uint8_t)(len & 0xFF);          // BCNTL

    const size_t initCap = HID_RPT_SIZE - 7; // 57
    size_t chunk = (len < initCap) ? len : initCap;
    if (chunk && data) memcpy(frame + 7, data, chunk);
    if (!WriteFrame(frame, deadlineTick, outError))
        return false;

    // Continuation packets.
    size_t offset = chunk;
    uint8_t seq = 0;
    const size_t contCap = HID_RPT_SIZE - 5; // 59
    while (offset < len)
    {
        memset(frame, 0, sizeof(frame));
        frame[0] = (uint8_t)(m_cid & 0xFF);
        frame[1] = (uint8_t)((m_cid >> 8) & 0xFF);
        frame[2] = (uint8_t)((m_cid >> 16) & 0xFF);
        frame[3] = (uint8_t)((m_cid >> 24) & 0xFF);
        frame[4] = (uint8_t)(seq & 0x7F);      // continuation: high bit clear
        size_t n = (len - offset < contCap) ? (len - offset) : contCap;
        memcpy(frame + 5, data + offset, n);
        if (!WriteFrame(frame, deadlineTick, outError))
            return false;
        offset += n;
        seq++;
    }
    return true;
}

bool CCtapHidDevice::ReadMessage(uint8_t& outCmd, std::vector<uint8_t>& outData,
                                 ULONGLONG deadlineTick, std::string& outError)
{
    uint8_t frame[64];

    // Read frames until an initialization packet addressed to our channel.
    // Init packets carry the command with bit 7 set (do NOT mask it off — the
    // CTAPHID_CMD constants include that bit); continuation packets have bit 7
    // clear and only their SEQ field uses the low 7 bits.
    for (;;)
    {
        if (!ReadFrame(frame, deadlineTick, outError))
            return false;

        uint32_t frameCid = (uint32_t)frame[0] | ((uint32_t)frame[1] << 8) |
                            ((uint32_t)frame[2] << 16) | ((uint32_t)frame[3] << 24);
        const bool isInitPacket = (frame[4] & 0x80) != 0;

        if (frameCid == m_cid && isInitPacket)
            break;

        if (GetTickCount64() >= deadlineTick)
        {
            outError = "read: timeout waiting for init packet";
            return false;
        }
    }

    outCmd = frame[4];  // full command byte, bit 7 included
    const size_t total = ((size_t)frame[5] << 8) | (size_t)frame[6];
    if (total > CTAP_MAX_MSG)
    {
        outError = "read: BCNT exceeds CTAP max message size";
        return false;
    }

    outData.clear();
    outData.reserve(total);
    const size_t initCap = HID_RPT_SIZE - 7; // 57
    size_t take = (total < initCap) ? total : initCap;
    outData.insert(outData.end(), frame + 7, frame + 7 + take);

    uint8_t expectSeq = 0;
    while (outData.size() < total)
    {
        if (!ReadFrame(frame, deadlineTick, outError))
            return false;

        uint32_t frameCid = (uint32_t)frame[0] | ((uint32_t)frame[1] << 8) |
                            ((uint32_t)frame[2] << 16) | ((uint32_t)frame[3] << 24);
        if (frameCid != m_cid)
            continue; // frame for another channel

        if (frame[4] & 0x80)
        {
            // A conformant authenticator never interleaves an init packet
            // (including KEEPALIVE) inside the continuation stream of the response
            // it is currently sending. Treat it as a protocol error rather than
            // silently dropping the partially reassembled message.
            outError = "read: unexpected init packet mid-message";
            return false;
        }
        if ((frame[4] & 0x7F) != expectSeq)
        {
            outError = "read: continuation sequence mismatch";
            return false;
        }
        const size_t contCap = HID_RPT_SIZE - 5; // 59
        size_t remaining = total - outData.size();
        size_t n = (remaining < contCap) ? remaining : contCap;
        outData.insert(outData.end(), frame + 5, frame + 5 + n);
        expectSeq++;
    }

    return true;
}

bool CCtapHidDevice::WriteFrame(const uint8_t frame[64], ULONGLONG deadlineTick,
                                std::string& outError)
{
    // Windows HID write buffer = report-ID(0x00) + 64 data bytes (m_outLen total).
    std::vector<uint8_t> buf(m_outLen, 0);
    buf[0] = 0x00; // report ID
    memcpy(buf.data() + 1, frame, HID_RPT_SIZE);

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) { outError = "CreateEvent(write) failed"; return false; }

    DWORD written = 0;
    BOOL ok = WriteFile(m_handle, buf.data(), m_outLen, &written, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING)
    {
        ULONGLONG now = GetTickCount64();
        DWORD waitMs = (now >= deadlineTick) ? 0 : (DWORD)(deadlineTick - now);
        HANDLE waits[2] = { ov.hEvent, m_hCancel };
        DWORD nWaits = m_hCancel ? 2 : 1;
        DWORD w = WaitForMultipleObjects(nWaits, waits, FALSE, waitMs);
        if (m_hCancel && w == WAIT_OBJECT_0 + 1)
        {
            m_cancelled = true;
            CancelIoEx(m_handle, &ov);
            GetOverlappedResult(m_handle, &ov, &written, TRUE); // drain
            CloseHandle(ov.hEvent);
            outError = "WriteFile(HID): cancelled";
            return false;
        }
        if (w != WAIT_OBJECT_0)
        {
            CancelIoEx(m_handle, &ov);
            GetOverlappedResult(m_handle, &ov, &written, TRUE); // drain the cancel
            CloseHandle(ov.hEvent);
            outError = "WriteFile(HID): timeout";
            return false;
        }
        ok = GetOverlappedResult(m_handle, &ov, &written, TRUE);
    }
    CloseHandle(ov.hEvent);

    if (!ok)
    {
        char msg[64];
        sprintf_s(msg, "WriteFile(HID) failed gle=%lu", (unsigned long)GetLastError());
        outError = msg;
        return false;
    }
    if (written != m_outLen)
    {
        outError = "WriteFile(HID): short write";
        return false;
    }
    return true;
}

bool CCtapHidDevice::ReadFrame(uint8_t frame[64], ULONGLONG deadlineTick,
                               std::string& outError)
{
    if (m_hCancel && WaitForSingleObject(m_hCancel, 0) == WAIT_OBJECT_0)
    { m_cancelled = true; outError = "read: cancelled"; return false; }

    ULONGLONG now = GetTickCount64();
    if (now >= deadlineTick) { outError = "read: deadline exceeded"; return false; }
    DWORD waitMs = (DWORD)(deadlineTick - now);

    std::vector<uint8_t> buf(m_inLen, 0);

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) { outError = "CreateEvent(read) failed"; return false; }

    DWORD read = 0;
    BOOL ok = ReadFile(m_handle, buf.data(), m_inLen, &read, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING)
    {
        HANDLE waits[2] = { ov.hEvent, m_hCancel };
        DWORD nWaits = m_hCancel ? 2 : 1;
        DWORD w = WaitForMultipleObjects(nWaits, waits, FALSE, waitMs);
        if (m_hCancel && w == WAIT_OBJECT_0 + 1)
        {
            // Cancel requested: abort the pending read and fail fast.
            m_cancelled = true;
            CancelIoEx(m_handle, &ov);
            GetOverlappedResult(m_handle, &ov, &read, TRUE); // drain
            CloseHandle(ov.hEvent);
            outError = "read: cancelled";
            return false;
        }
        if (w != WAIT_OBJECT_0)
        {
            // Timeout, WAIT_FAILED, or WAIT_ABANDONED: cancel and drain. If the
            // read actually completed in the race window, use its data.
            CancelIoEx(m_handle, &ov);
            BOOL got = GetOverlappedResult(m_handle, &ov, &read, TRUE);
            CloseHandle(ov.hEvent);
            if (got && read >= m_inLen)
            {
                memcpy(frame, buf.data() + 1, HID_RPT_SIZE);
                return true;
            }
            outError = "read: timeout";
            return false;
        }
        ok = GetOverlappedResult(m_handle, &ov, &read, TRUE);
    }
    CloseHandle(ov.hEvent);

    if (!ok)
    {
        char msg[64];
        sprintf_s(msg, "ReadFile(HID) failed gle=%lu", (unsigned long)GetLastError());
        outError = msg;
        return false;
    }
    if (read < m_inLen) { outError = "read: short HID report"; return false; }

    // Strip the leading report-ID byte; the 64-byte CTAPHID frame follows.
    memcpy(frame, buf.data() + 1, HID_RPT_SIZE);
    return true;
}
