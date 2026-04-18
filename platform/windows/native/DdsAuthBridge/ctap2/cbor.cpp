// cbor.cpp
// Lightweight CBOR encoder/decoder implementation.
//

#include "cbor.h"
#include <string.h>

// M-17 (security review): bound-checks on the decoder.
//
// CTAP2 messages come off USB-HID from hardware that is *usually*
// benign, but a malicious USB device can pass any bytes. Without caps,
// attacker-chosen length prefixes trivially turn into unbounded
// allocations (e.g., `major 4 / argument 2^63` → `vector::resize`).
//
// CTAP2 shapes are small — GetInfo responses and attestation objects
// sit well under 16 levels deep with order-of-dozens elements. These
// limits are generous relative to that.
static constexpr size_t kMaxCborDepth = 16;

// ============================================================================
// CborValue constructors
// ============================================================================

CborValue CborValue::Uint(uint64_t v)
{
    CborValue val;
    val.type = CborType::UnsignedInt;
    val.uintVal = v;
    return val;
}

CborValue CborValue::NegInt(int64_t v)
{
    CborValue val;
    val.type = CborType::NegativeInt;
    val.intVal = v;
    return val;
}

CborValue CborValue::Bytes(const uint8_t* data, size_t len)
{
    CborValue val;
    val.type = CborType::ByteString;
    if (data && len > 0)
        val.bytesVal.assign(data, data + len);
    return val;
}

CborValue CborValue::Bytes(const std::vector<uint8_t>& v)
{
    CborValue val;
    val.type = CborType::ByteString;
    val.bytesVal = v;
    return val;
}

CborValue CborValue::String(const char* s)
{
    CborValue val;
    val.type = CborType::TextString;
    if (s) val.strVal = s;
    return val;
}

CborValue CborValue::String(const std::string& s)
{
    CborValue val;
    val.type = CborType::TextString;
    val.strVal = s;
    return val;
}

CborValue CborValue::Array(const CborArray& a)
{
    CborValue val;
    val.type = CborType::Array;
    val.arrayVal = a;
    return val;
}

CborValue CborValue::Map(const CborMap& m)
{
    CborValue val;
    val.type = CborType::Map;
    val.mapVal = m;
    return val;
}

CborValue CborValue::Bool(bool b)
{
    CborValue val;
    val.type = CborType::Boolean;
    val.boolVal = b;
    return val;
}

CborValue CborValue::Null()
{
    CborValue val;
    val.type = CborType::Null;
    return val;
}

// ============================================================================
// CborValue accessors
// ============================================================================

uint64_t CborValue::AsUint() const
{
    return (type == CborType::UnsignedInt) ? uintVal : 0;
}

int64_t CborValue::AsInt() const
{
    if (type == CborType::NegativeInt) return intVal;
    if (type == CborType::UnsignedInt) return static_cast<int64_t>(uintVal);
    return 0;
}

const std::vector<uint8_t>& CborValue::AsBytes() const
{
    static const std::vector<uint8_t> empty;
    return (type == CborType::ByteString) ? bytesVal : empty;
}

const std::string& CborValue::AsString() const
{
    static const std::string empty;
    return (type == CborType::TextString) ? strVal : empty;
}

const CborArray& CborValue::AsArray() const
{
    static const CborArray empty;
    return (type == CborType::Array) ? arrayVal : empty;
}

const CborMap& CborValue::AsMap() const
{
    static const CborMap empty;
    return (type == CborType::Map) ? mapVal : empty;
}

bool CborValue::AsBool() const
{
    return (type == CborType::Boolean) ? boolVal : false;
}

const CborValue* CborValue::MapLookup(uint64_t key) const
{
    if (type != CborType::Map) return nullptr;
    for (const auto& entry : mapVal)
    {
        if (entry.first.type == CborType::UnsignedInt && entry.first.uintVal == key)
            return &entry.second;
    }
    return nullptr;
}

const CborValue* CborValue::MapLookup(const std::string& key) const
{
    if (type != CborType::Map) return nullptr;
    for (const auto& entry : mapVal)
    {
        if (entry.first.type == CborType::TextString && entry.first.strVal == key)
            return &entry.second;
    }
    return nullptr;
}

// ============================================================================
// CborEncoder
// ============================================================================

CborEncoder::CborEncoder()
{
    m_buffer.reserve(256);
}

bool CborEncoder::Encode(const CborValue& value)
{
    m_buffer.clear();
    EncodeValue(value);
    return true;
}

void CborEncoder::EncodeUint(uint8_t majorType, uint64_t value)
{
    uint8_t mt = majorType << 5;

    if (value <= 23)
    {
        m_buffer.push_back(mt | static_cast<uint8_t>(value));
    }
    else if (value <= 0xFF)
    {
        m_buffer.push_back(mt | 24);
        m_buffer.push_back(static_cast<uint8_t>(value));
    }
    else if (value <= 0xFFFF)
    {
        m_buffer.push_back(mt | 25);
        m_buffer.push_back(static_cast<uint8_t>(value >> 8));
        m_buffer.push_back(static_cast<uint8_t>(value));
    }
    else if (value <= 0xFFFFFFFF)
    {
        m_buffer.push_back(mt | 26);
        m_buffer.push_back(static_cast<uint8_t>(value >> 24));
        m_buffer.push_back(static_cast<uint8_t>(value >> 16));
        m_buffer.push_back(static_cast<uint8_t>(value >> 8));
        m_buffer.push_back(static_cast<uint8_t>(value));
    }
    else
    {
        m_buffer.push_back(mt | 27);
        m_buffer.push_back(static_cast<uint8_t>(value >> 56));
        m_buffer.push_back(static_cast<uint8_t>(value >> 48));
        m_buffer.push_back(static_cast<uint8_t>(value >> 40));
        m_buffer.push_back(static_cast<uint8_t>(value >> 32));
        m_buffer.push_back(static_cast<uint8_t>(value >> 24));
        m_buffer.push_back(static_cast<uint8_t>(value >> 16));
        m_buffer.push_back(static_cast<uint8_t>(value >> 8));
        m_buffer.push_back(static_cast<uint8_t>(value));
    }
}

void CborEncoder::EncodeBytes(const uint8_t* data, size_t len)
{
    EncodeUint(2, len);
    m_buffer.insert(m_buffer.end(), data, data + len);
}

void CborEncoder::EncodeString(const char* str, size_t len)
{
    EncodeUint(3, len);
    m_buffer.insert(m_buffer.end(), reinterpret_cast<const uint8_t*>(str),
        reinterpret_cast<const uint8_t*>(str) + len);
}

void CborEncoder::EncodeValue(const CborValue& val)
{
    switch (val.type)
    {
    case CborType::UnsignedInt:
        EncodeUint(0, val.uintVal);
        break;

    case CborType::NegativeInt:
        // CBOR negative: -1-n encoded as major type 1, argument n
        EncodeUint(1, static_cast<uint64_t>(-1 - val.intVal));
        break;

    case CborType::ByteString:
        EncodeBytes(val.bytesVal.data(), val.bytesVal.size());
        break;

    case CborType::TextString:
        EncodeString(val.strVal.c_str(), val.strVal.size());
        break;

    case CborType::Array:
        EncodeUint(4, val.arrayVal.size());
        for (const auto& item : val.arrayVal)
            EncodeValue(item);
        break;

    case CborType::Map:
        EncodeUint(5, val.mapVal.size());
        for (const auto& entry : val.mapVal)
        {
            EncodeValue(entry.first);
            EncodeValue(entry.second);
        }
        break;

    case CborType::Boolean:
        m_buffer.push_back(val.boolVal ? 0xF5 : 0xF4);
        break;

    case CborType::Null:
        m_buffer.push_back(0xF6);
        break;
    }
}

// ============================================================================
// CborDecoder
// ============================================================================

CborDecoder::CborDecoder()
    : m_data(nullptr), m_size(0), m_pos(0), m_error(nullptr)
{
}

bool CborDecoder::Decode(const uint8_t* data, size_t len, CborValue& outValue)
{
    m_data = data;
    m_size = len;
    m_pos = 0;
    m_error = nullptr;

    if (!DecodeValue(outValue, 0))
    {
        if (!m_error) m_error = "Unknown decode error";
        return false;
    }

    return true;
}

bool CborDecoder::ReadByte(uint8_t& b)
{
    if (m_pos >= m_size)
    {
        m_error = "Unexpected end of input";
        return false;
    }
    b = m_data[m_pos++];
    return true;
}

bool CborDecoder::ReadBytes(uint8_t* buf, size_t count)
{
    // Compare against Remaining() rather than computing m_pos + count,
    // which can wrap for attacker-chosen count.
    if (count > Remaining())
    {
        m_error = "Unexpected end of input reading bytes";
        return false;
    }
    memcpy(buf, m_data + m_pos, count);
    m_pos += count;
    return true;
}

bool CborDecoder::DecodeHead(uint8_t& majorType, uint64_t& argument)
{
    uint8_t initial;
    if (!ReadByte(initial))
        return false;

    majorType = initial >> 5;
    uint8_t additional = initial & 0x1F;

    if (additional <= 23)
    {
        argument = additional;
    }
    else if (additional == 24)
    {
        uint8_t b;
        if (!ReadByte(b)) return false;
        argument = b;
    }
    else if (additional == 25)
    {
        uint8_t buf[2];
        if (!ReadBytes(buf, 2)) return false;
        argument = (static_cast<uint64_t>(buf[0]) << 8) | buf[1];
    }
    else if (additional == 26)
    {
        uint8_t buf[4];
        if (!ReadBytes(buf, 4)) return false;
        argument = (static_cast<uint64_t>(buf[0]) << 24) |
                   (static_cast<uint64_t>(buf[1]) << 16) |
                   (static_cast<uint64_t>(buf[2]) << 8) |
                   buf[3];
    }
    else if (additional == 27)
    {
        uint8_t buf[8];
        if (!ReadBytes(buf, 8)) return false;
        argument = (static_cast<uint64_t>(buf[0]) << 56) |
                   (static_cast<uint64_t>(buf[1]) << 48) |
                   (static_cast<uint64_t>(buf[2]) << 40) |
                   (static_cast<uint64_t>(buf[3]) << 32) |
                   (static_cast<uint64_t>(buf[4]) << 24) |
                   (static_cast<uint64_t>(buf[5]) << 16) |
                   (static_cast<uint64_t>(buf[6]) << 8) |
                   buf[7];
    }
    else
    {
        m_error = "Unsupported additional info value (indefinite length not supported)";
        return false;
    }

    return true;
}

bool CborDecoder::DecodeValue(CborValue& outVal, size_t depth)
{
    if (depth >= kMaxCborDepth)
    {
        m_error = "CBOR nesting depth exceeded";
        return false;
    }

    uint8_t majorType;
    uint64_t argument;

    if (!DecodeHead(majorType, argument))
        return false;

    switch (majorType)
    {
    case 0: // Unsigned integer
        outVal = CborValue::Uint(argument);
        return true;

    case 1: // Negative integer
        outVal = CborValue::NegInt(-1 - static_cast<int64_t>(argument));
        return true;

    case 2: // Byte string
    {
        if (argument > Remaining())
        {
            m_error = "Byte string length exceeds remaining data";
            return false;
        }
        outVal.type = CborType::ByteString;
        outVal.bytesVal.resize(static_cast<size_t>(argument));
        if (argument > 0 && !ReadBytes(outVal.bytesVal.data(), static_cast<size_t>(argument)))
            return false;
        return true;
    }

    case 3: // Text string
    {
        if (argument > Remaining())
        {
            m_error = "Text string length exceeds remaining data";
            return false;
        }
        outVal.type = CborType::TextString;
        outVal.strVal.resize(static_cast<size_t>(argument));
        if (argument > 0 && !ReadBytes(reinterpret_cast<uint8_t*>(&outVal.strVal[0]), static_cast<size_t>(argument)))
            return false;
        return true;
    }

    case 4: // Array
    {
        // Each element consumes at least one byte, so reject element
        // counts that cannot possibly fit in what's left on the wire.
        if (argument > Remaining())
        {
            m_error = "Array element count exceeds remaining data";
            return false;
        }
        outVal.type = CborType::Array;
        outVal.arrayVal.resize(static_cast<size_t>(argument));
        for (size_t i = 0; i < static_cast<size_t>(argument); i++)
        {
            if (!DecodeValue(outVal.arrayVal[i], depth + 1))
                return false;
        }
        return true;
    }

    case 5: // Map
    {
        // Each entry is key + value, so a map of `argument` pairs needs
        // >= 2*argument bytes. Reject anything that obviously can't fit.
        if (argument > Remaining() / 2)
        {
            m_error = "Map entry count exceeds remaining data";
            return false;
        }
        outVal.type = CborType::Map;
        outVal.mapVal.resize(static_cast<size_t>(argument));
        for (size_t i = 0; i < static_cast<size_t>(argument); i++)
        {
            if (!DecodeValue(outVal.mapVal[i].first, depth + 1))
                return false;
            if (!DecodeValue(outVal.mapVal[i].second, depth + 1))
                return false;
        }
        return true;
    }

    case 7: // Simple values and floats
    {
        if (argument == 20) // false
        {
            outVal = CborValue::Bool(false);
            return true;
        }
        else if (argument == 21) // true
        {
            outVal = CborValue::Bool(true);
            return true;
        }
        else if (argument == 22) // null
        {
            outVal = CborValue::Null();
            return true;
        }
        else if (argument == 23) // undefined
        {
            outVal = CborValue::Null();
            return true;
        }
        m_error = "Unsupported simple value or float";
        return false;
    }

    default:
        m_error = "Unknown CBOR major type";
        return false;
    }
}
