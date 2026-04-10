// cbor.h
// Lightweight CBOR (RFC 8949) encoder/decoder for CTAP2 messages.
//
// This is a minimal implementation covering the subset of CBOR needed for FIDO2:
//   - Unsigned integers (major type 0)
//   - Negative integers (major type 1)
//   - Byte strings (major type 2)
//   - Text strings (major type 3)
//   - Arrays (major type 4)
//   - Maps (major type 5)
//   - Simple values: true, false, null (major type 7)
//   - Booleans
//
// Does NOT support: floating point, tags, indefinite-length, nested indefinite.
//

#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <variant>
#include <optional>

// ============================================================================
// CBOR Value Type
// ============================================================================

enum class CborType : uint8_t
{
    UnsignedInt,    // uint64_t
    NegativeInt,    // int64_t (negative)
    ByteString,     // std::vector<uint8_t>
    TextString,     // std::string (UTF-8)
    Array,          // std::vector<CborValue>
    Map,            // std::vector<std::pair<CborValue, CborValue>>
    Boolean,        // bool
    Null,           // nullptr
};

// Forward declaration
struct CborValue;

using CborArray = std::vector<CborValue>;
using CborMapEntry = std::pair<CborValue, CborValue>;
using CborMap = std::vector<CborMapEntry>;

struct CborValue
{
    CborType type;

    // Storage — only the relevant field is valid based on type
    uint64_t                uintVal;
    int64_t                 intVal;
    std::vector<uint8_t>    bytesVal;
    std::string             strVal;
    CborArray               arrayVal;
    CborMap                 mapVal;
    bool                    boolVal;

    // Constructors
    CborValue() : type(CborType::Null), uintVal(0), intVal(0), boolVal(false) {}

    static CborValue Uint(uint64_t v);
    static CborValue NegInt(int64_t v);
    static CborValue Bytes(const uint8_t* data, size_t len);
    static CborValue Bytes(const std::vector<uint8_t>& v);
    static CborValue String(const char* s);
    static CborValue String(const std::string& s);
    static CborValue Array(const CborArray& a);
    static CborValue Map(const CborMap& m);
    static CborValue Bool(bool b);
    static CborValue Null();

    // Accessors (return default if wrong type)
    uint64_t                    AsUint() const;
    int64_t                     AsInt() const;
    const std::vector<uint8_t>& AsBytes() const;
    const std::string&          AsString() const;
    const CborArray&            AsArray() const;
    const CborMap&              AsMap() const;
    bool                        AsBool() const;

    // Map helpers — lookup by integer key (common in CTAP2)
    const CborValue* MapLookup(uint64_t key) const;
    const CborValue* MapLookup(const std::string& key) const;

    bool IsNull() const { return type == CborType::Null; }
};

// ============================================================================
// CBOR Encoder
// ============================================================================

class CborEncoder
{
public:
    CborEncoder();

    // Encode a CborValue tree into a byte buffer.
    bool Encode(const CborValue& value);

    // Get the encoded bytes.
    const std::vector<uint8_t>& GetBuffer() const { return m_buffer; }
    const uint8_t* GetData() const { return m_buffer.data(); }
    size_t GetSize() const { return m_buffer.size(); }

    // Reset for reuse.
    void Reset() { m_buffer.clear(); }

private:
    std::vector<uint8_t> m_buffer;

    void EncodeValue(const CborValue& val);
    void EncodeUint(uint8_t majorType, uint64_t value);
    void EncodeBytes(const uint8_t* data, size_t len);
    void EncodeString(const char* str, size_t len);
};

// ============================================================================
// CBOR Decoder
// ============================================================================

class CborDecoder
{
public:
    CborDecoder();

    // Decode CBOR bytes into a CborValue tree.
    // Returns true on success.
    bool Decode(const uint8_t* data, size_t len, CborValue& outValue);

    // Error description if Decode() fails.
    const char* GetError() const { return m_error; }

private:
    const uint8_t*  m_data;
    size_t          m_size;
    size_t          m_pos;
    const char*     m_error;

    bool DecodeValue(CborValue& outVal);
    bool DecodeHead(uint8_t& majorType, uint64_t& argument);
    bool ReadByte(uint8_t& b);
    bool ReadBytes(uint8_t* buf, size_t count);
    size_t Remaining() const { return m_size - m_pos; }
};
