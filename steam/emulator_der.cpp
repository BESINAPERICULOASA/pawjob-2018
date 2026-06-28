// emulator_der.cpp — see emulator_der.h.
//
// All routines here are pure data transforms; no CNG, no sockets. Kept in its
// own translation unit so the DER codec is easy to audit independently of the
// session/CNG machinery in emulator_core.cpp.
#include "emulator_der.h"

#include <cstring>

namespace emuder {

namespace {

constexpr char kB64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Precomputed decode table (built once on first use).
struct B64DecoderTable {
    int8_t map[256];
    B64DecoderTable() {
        for (int i = 0; i < 256; ++i) map[i] = -1;
        for (int i = 0; i < 64; ++i)
            map[static_cast<unsigned char>(kB64Alphabet[i])] = static_cast<int8_t>(i);
    }
};

const B64DecoderTable& b64_table() {
    static const B64DecoderTable t;
    return t;
}

// Append a DER length octet sequence (short form for < 0x80, else long form).
void append_der_len(std::vector<std::uint8_t>& out, std::size_t len) {
    if (len < 0x80) {
        out.push_back(static_cast<std::uint8_t>(len));
    } else if (len <= 0xff) {
        out.push_back(0x81);
        out.push_back(static_cast<std::uint8_t>(len));
    } else if (len <= 0xffff) {
        out.push_back(0x82);
        out.push_back(static_cast<std::uint8_t>(len >> 8));
        out.push_back(static_cast<std::uint8_t>(len));
    } else if (len <= 0xffffff) {
        out.push_back(0x83);
        out.push_back(static_cast<std::uint8_t>(len >> 16));
        out.push_back(static_cast<std::uint8_t>(len >> 8));
        out.push_back(static_cast<std::uint8_t>(len));
    } else {
        out.push_back(0x84);
        out.push_back(static_cast<std::uint8_t>(len >> 24));
        out.push_back(static_cast<std::uint8_t>(len >> 16));
        out.push_back(static_cast<std::uint8_t>(len >> 8));
        out.push_back(static_cast<std::uint8_t>(len));
    }
}

// DER INTEGER from a big-endian unsigned magnitude. The positive sign byte is
// inserted only when the high bit of the magnitude is set (matches the DER
// produced by cryptography's serialization APIs).
std::vector<std::uint8_t> der_integer(const std::uint8_t* be, std::size_t len) {
    while (len > 1 && be[0] == 0) { ++be; --len; }  // strip leading 0x00
    std::vector<std::uint8_t> content;
    if (len == 0) {
        content.push_back(0);
    } else if (be[0] & 0x80) {
        content.push_back(0x00);  // keep value positive
        content.insert(content.end(), be, be + len);
    } else {
        content.insert(content.end(), be, be + len);
    }
    std::vector<std::uint8_t> out;
    out.push_back(0x02);  // INTEGER tag
    append_der_len(out, content.size());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

std::vector<std::uint8_t> der_integer(const std::vector<std::uint8_t>& mag) {
    return der_integer(mag.data(), mag.size());
}

// Wrap a fully-formed TLV body (content) in a SEQUENCE tag+length.
std::vector<std::uint8_t> wrap_sequence(const std::vector<std::uint8_t>& content) {
    std::vector<std::uint8_t> out;
    out.push_back(0x30);
    append_der_len(out, content.size());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

// rsaEncryption OID 1.2.840.113549.1.1.1 + NULL params AlgorithmIdentifier.
std::vector<std::uint8_t> build_rsa_algorithm_identifier() {
    static const std::uint8_t kOid[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
    static const std::uint8_t kNull[] = {0x05, 0x00};
    std::vector<std::uint8_t> content;
    content.insert(content.end(), kOid, kOid + sizeof(kOid));
    content.insert(content.end(), kNull, kNull + sizeof(kNull));
    return wrap_sequence(content);
}

std::vector<std::uint8_t> build_pkcs1_public_der_inner(const RSAPublicComponents& pub) {
    std::vector<std::uint8_t> content;
    auto n = der_integer(pub.modulus_be);
    auto e = der_integer(pub.exponent_be);
    content.insert(content.end(), n.begin(), n.end());
    content.insert(content.end(), e.begin(), e.end());
    return wrap_sequence(content);
}

} // namespace

// ---- Base64 ----
std::string base64_encode(const std::uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        const std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                                (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                                data[i + 2];
        out.push_back(kB64Alphabet[(v >> 18) & 63]);
        out.push_back(kB64Alphabet[(v >> 12) & 63]);
        out.push_back(kB64Alphabet[(v >> 6) & 63]);
        out.push_back(kB64Alphabet[v & 63]);
    }
    if (i < len) {
        const std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16 |
                                (i + 1 < len ? (static_cast<std::uint32_t>(data[i + 1]) << 8) : 0);
        out.push_back(kB64Alphabet[(v >> 18) & 63]);
        out.push_back(kB64Alphabet[(v >> 12) & 63]);
        out.push_back(i + 1 < len ? kB64Alphabet[(v >> 6) & 63] : '=');
        out.push_back('=');
    }
    return out;
}

std::string base64_encode(const std::vector<std::uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}

bool base64_decode(std::string_view text, std::vector<std::uint8_t>& out) {
    const auto& tbl = b64_table();
    out.clear();
    if (text.empty()) return true;
    const std::size_t n = text.size();
    if (n % 4 != 0) return false;  // b64decode(validate=True) requires this implicit invariant

    std::size_t pad = 0;
    if (text[n - 1] == '=') {
        ++pad;
        if (n >= 2 && text[n - 2] == '=') ++pad;
    }
    out.reserve((n / 4) * 3);
    std::uint32_t v = 0;
    int bits = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (c == '=') continue;
        const int8_t d = tbl.map[c];
        if (d < 0) return false;  // non-alphabet character -> reject validate=True
        v = (v << 6) | static_cast<std::uint32_t>(d);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((v >> bits) & 0xFF));
        }
    }
    const std::size_t expected = (n / 4) * 3 - pad;
    if (out.size() > expected) out.resize(expected);
    return out.size() == expected;
}

// ---- PEM ----
std::string pem_armor_private_key(const std::vector<std::uint8_t>& der) {
    std::string out = "-----BEGIN PRIVATE KEY-----\n";
    const std::string b64 = base64_encode(der.data(), der.size());
    for (std::size_t i = 0; i < b64.size(); i += 64) {
        const std::size_t take = std::min<std::size_t>(64, b64.size() - i);
        out.append(b64, i, take);
        out.push_back('\n');
    }
    out += "-----END PRIVATE KEY-----\n";
    return out;
}

bool pem_unarmor(std::string_view pem, std::vector<std::uint8_t>& der) {
    const std::string::size_type b = pem.find("-----BEGIN");
    if (b == std::string::npos) return false;
    const std::string::size_type nl = pem.find('\n', b);
    if (nl == std::string::npos) return false;
    const std::string::size_type e = pem.find("-----END", nl + 1);
    if (e == std::string::npos) return false;
    const auto body = pem.substr(nl + 1, e - (nl + 1));
    std::string clean;
    clean.reserve(body.size());
    for (char ch : body) {
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=') {
            clean.push_back(ch);
        }
    }
    return base64_decode(clean, der);
}

// ---- DER building ----
std::vector<std::uint8_t> build_pkcs1_public_der(const RSAPublicComponents& pub) {
    return build_pkcs1_public_der_inner(pub);
}

std::vector<std::uint8_t> build_spki_der(const RSAPublicComponents& pub) {
    const std::vector<std::uint8_t> rsaPub = build_pkcs1_public_der_inner(pub);
    // BIT STRING: 0x00 unused-bits prefix, then the RSAPublicKey DER.
    std::vector<std::uint8_t> bitStringContent;
    bitStringContent.push_back(0x00);
    bitStringContent.insert(bitStringContent.end(), rsaPub.begin(), rsaPub.end());
    std::vector<std::uint8_t> bitString;
    bitString.push_back(0x03);  // BIT STRING
    append_der_len(bitString, bitStringContent.size());
    bitString.insert(bitString.end(), bitStringContent.begin(), bitStringContent.end());

    std::vector<std::uint8_t> content;
    const std::vector<std::uint8_t> algId = build_rsa_algorithm_identifier();
    content.insert(content.end(), algId.begin(), algId.end());
    content.insert(content.end(), bitString.begin(), bitString.end());
    return wrap_sequence(content);
}

std::vector<std::uint8_t> build_pkcs8_private_der(const RSAPrivateComponents& priv) {
    static const std::uint8_t kVersion0[] = {0x02, 0x01, 0x00};  // INTEGER 0

    // Each der_integer(...) result must be stored in a named local before
    // iterating; calling it twice for .begin() and .end() would construct two
    // distinct temporaries whose iterators belong to different containers —
    // undefined behavior that can corrupt the key blob or crash.
    const std::vector<std::uint8_t> n   = der_integer(priv.modulus_be);
    const std::vector<std::uint8_t> e   = der_integer(priv.exponent_be);
    const std::vector<std::uint8_t> d   = der_integer(priv.private_exponent_be);
    const std::vector<std::uint8_t> p1  = der_integer(priv.prime1_be);
    const std::vector<std::uint8_t> p2  = der_integer(priv.prime2_be);
    const std::vector<std::uint8_t> e1  = der_integer(priv.exponent1_be);
    const std::vector<std::uint8_t> e2  = der_integer(priv.exponent2_be);
    const std::vector<std::uint8_t> c   = der_integer(priv.coefficient_be);

    std::vector<std::uint8_t> rsaPrivContent;
    rsaPrivContent.insert(rsaPrivContent.end(), kVersion0, kVersion0 + sizeof(kVersion0));
    rsaPrivContent.insert(rsaPrivContent.end(), n.begin(), n.end());
    rsaPrivContent.insert(rsaPrivContent.end(), e.begin(), e.end());
    rsaPrivContent.insert(rsaPrivContent.end(), d.begin(), d.end());
    rsaPrivContent.insert(rsaPrivContent.end(), p1.begin(), p1.end());
    rsaPrivContent.insert(rsaPrivContent.end(), p2.begin(), p2.end());
    rsaPrivContent.insert(rsaPrivContent.end(), e1.begin(), e1.end());
    rsaPrivContent.insert(rsaPrivContent.end(), e2.begin(), e2.end());
    rsaPrivContent.insert(rsaPrivContent.end(), c.begin(), c.end());
    const std::vector<std::uint8_t> rsaPrivSeq = wrap_sequence(rsaPrivContent);

    // OCTET STRING wrapping the RSAPrivateKey DER.
    std::vector<std::uint8_t> octet;
    octet.push_back(0x04);
    append_der_len(octet, rsaPrivSeq.size());
    octet.insert(octet.end(), rsaPrivSeq.begin(), rsaPrivSeq.end());

    std::vector<std::uint8_t> content;
    content.insert(content.end(), kVersion0, kVersion0 + sizeof(kVersion0));
    const std::vector<std::uint8_t> algId = build_rsa_algorithm_identifier();
    content.insert(content.end(), algId.begin(), algId.end());
    content.insert(content.end(), octet.begin(), octet.end());
    return wrap_sequence(content);
}

// ---- DER parsing ----
namespace {

// Minimal cursor: walk a DER byte stream; on any structural problem ok=false.
struct DerCursor {
    const std::uint8_t* p = nullptr;
    const std::uint8_t* end = nullptr;
    bool ok = true;

    bool read_header(std::uint8_t& tag, std::size_t& len) {
        if (!ok || p + 2 > end) { ok = false; return false; }
        tag = *p++;
        const std::uint8_t b = *p++;
        if (b < 0x80) { len = b; return true; }
        const int n = b & 0x7f;
        if (n == 0 || n > 4 || p + n > end) { ok = false; return false; }
        std::size_t v = 0;
        for (int i = 0; i < n; ++i) v = (v << 8) | *p++;
        len = v;
        return true;
    }

    bool read_sequence(DerCursor& content) {
        std::uint8_t tag; std::size_t len;
        if (!read_header(tag, len) || tag != 0x30) { ok = false; return false; }
        if (p + len > end) { ok = false; return false; }
        content.p = p; content.end = p + len; content.ok = true;
        p += len;
        return true;
    }

    bool read_integer(std::vector<std::uint8_t>& mag) {
        std::uint8_t tag; std::size_t len;
        if (!read_header(tag, len) || tag != 0x02) { ok = false; return false; }
        if (p + len > end) { ok = false; return false; }
        const std::uint8_t* s = p;
        p += len;
        std::size_t start = 0;
        if (len > 1 && s[0] == 0x00) start = 1;  // strip DER sign byte
        mag.assign(s + start, s + len);
        if (mag.empty()) mag.push_back(0);
        return true;
    }

    bool read_tag(std::uint8_t expected, std::vector<std::uint8_t>& content) {
        std::uint8_t tag; std::size_t len;
        if (!read_header(tag, len) || tag != expected) { ok = false; return false; }
        if (p + len > end) { ok = false; return false; }
        content.assign(p, p + len);
        p += len;
        return true;
    }

    bool skip_expected(std::uint8_t expected) {
        std::uint8_t tag; std::size_t len;
        if (!read_header(tag, len) || tag != expected) { ok = false; return false; }
        if (p + len > end) { ok = false; return false; }
        p += len;
        return true;
    }
};

} // namespace

bool parse_spki_public_der(const std::vector<std::uint8_t>& der, RSAPublicComponents& out) {
    DerCursor c{der.data(), der.data() + der.size()};
    DerCursor spki;
    if (!c.read_sequence(spki)) return false;

    DerCursor algId;
    if (!spki.read_sequence(algId)) return false;
    std::vector<std::uint8_t> oid;
    if (!algId.read_tag(0x06, oid)) return false;
    if (algId.p < algId.end) {
        if (!algId.skip_expected(0x05)) return false;  // NULL params
    }

    std::vector<std::uint8_t> bitString;
    if (!spki.read_tag(0x03, bitString)) return false;
    if (bitString.empty() || bitString[0] != 0) return false;  // unused-bits prefix must be 0

    DerCursor rsaPub{bitString.data() + 1, bitString.data() + bitString.size()};
    DerCursor rsaPubSeq;
    if (!rsaPub.read_sequence(rsaPubSeq)) return false;
    if (!rsaPubSeq.read_integer(out.modulus_be)) return false;
    if (!rsaPubSeq.read_integer(out.exponent_be)) return false;
    return rsaPubSeq.p == rsaPubSeq.end;
}

bool parse_pkcs8_private_der(const std::vector<std::uint8_t>& der, RSAPrivateComponents& out) {
    DerCursor c{der.data(), der.data() + der.size()};
    DerCursor pki;
    if (!c.read_sequence(pki)) return false;

    std::vector<std::uint8_t> version;
    if (!pki.read_tag(0x02, version)) return false;
    DerCursor algId;
    if (!pki.read_sequence(algId)) return false;
    std::vector<std::uint8_t> oid;
    if (!algId.read_tag(0x06, oid)) return false;
    if (algId.p < algId.end) {
        if (!algId.skip_expected(0x05)) return false;
    }
    std::vector<std::uint8_t> octet;
    if (!pki.read_tag(0x04, octet)) return false;  // privateKey OCTET STRING

    DerCursor rsaPriv{octet.data(), octet.data() + octet.size()};
    DerCursor rsaPrivSeq;
    if (!rsaPriv.read_sequence(rsaPrivSeq)) return false;
    std::vector<std::uint8_t> ver;
    if (!rsaPrivSeq.read_integer(ver)) return false;
    if (!rsaPrivSeq.read_integer(out.modulus_be)) return false;
    if (!rsaPrivSeq.read_integer(out.exponent_be)) return false;
    if (!rsaPrivSeq.read_integer(out.private_exponent_be)) return false;
    if (!rsaPrivSeq.read_integer(out.prime1_be)) return false;
    if (!rsaPrivSeq.read_integer(out.prime2_be)) return false;
    if (!rsaPrivSeq.read_integer(out.exponent1_be)) return false;
    if (!rsaPrivSeq.read_integer(out.exponent2_be)) return false;
    if (!rsaPrivSeq.read_integer(out.coefficient_be)) return false;
    return rsaPrivSeq.p == rsaPrivSeq.end;
}

} // namespace emuder
