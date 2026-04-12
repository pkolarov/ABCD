// ipc_protocol.cpp
// DDS Bridge IPC Protocol - serialization and utility functions.
//

#include "ipc_protocol.h"
#include <string.h>

// Thread-safe sequence ID generator.
static volatile LONG s_seqCounter = 0;

UINT32 IpcNextSeqId()
{
    return (UINT32)InterlockedIncrement(&s_seqCounter);
}

DWORD IpcSerializeMessage(
    _Out_writes_bytes_(outBufferSize) BYTE* pOutBuffer,
    _In_ DWORD outBufferSize,
    _In_ UINT16 msgType,
    _In_ UINT32 seqId,
    _In_reads_bytes_opt_(payloadLen) const BYTE* pPayload,
    _In_ DWORD payloadLen)
{
    if (pOutBuffer == nullptr)
    {
        return 0;
    }

    const DWORD totalLen = sizeof(IPC_MESSAGE_HEADER) + payloadLen;
    if (outBufferSize < totalLen)
    {
        return 0;
    }

    IPC_MESSAGE_HEADER header;
    header.msgType = msgType;
    header.seqId = seqId;
    header.length = payloadLen;

    memcpy(pOutBuffer, &header, sizeof(IPC_MESSAGE_HEADER));

    if (pPayload != nullptr && payloadLen > 0)
    {
        memcpy(pOutBuffer + sizeof(IPC_MESSAGE_HEADER), pPayload, payloadLen);
    }

    return totalLen;
}

BOOL IpcDeserializeHeader(
    _In_reads_bytes_(bufferLen) const BYTE* pBuffer,
    _In_ DWORD bufferLen,
    _Out_ IPC_MESSAGE_HEADER* pHeader,
    _Outptr_result_maybenull_ const BYTE** ppPayload)
{
    if (pBuffer == nullptr || pHeader == nullptr || ppPayload == nullptr)
    {
        return FALSE;
    }

    *ppPayload = nullptr;

    if (bufferLen < sizeof(IPC_MESSAGE_HEADER))
    {
        return FALSE;
    }

    memcpy(pHeader, pBuffer, sizeof(IPC_MESSAGE_HEADER));

    // SECURITY: validate payload length against remaining buffer WITHOUT
    // overflowing. Previously: sizeof(hdr) + length could wrap and pass
    // the check, allowing a crafted header to claim a multi-GB payload
    // inside a 10-byte buffer. Pinned by Tests/test_ipc_fuzz.cpp.
    const DWORD maxPayload = bufferLen - (DWORD)sizeof(IPC_MESSAGE_HEADER);
    if (pHeader->length > maxPayload)
    {
        return FALSE;
    }
    // Defense-in-depth: reject any payload larger than the pipe buffer,
    // regardless of what the caller allocated.
    if (pHeader->length > IPC_PIPE::BUFFER_SIZE)
    {
        return FALSE;
    }

    if (pHeader->length > 0)
    {
        *ppPayload = pBuffer + sizeof(IPC_MESSAGE_HEADER);
    }

    return TRUE;
}
