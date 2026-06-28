// emulator_der.h — tiny ASN.1 DER codec + PEM armor + Base64.
//
// This translation unit exists only to back the localhost cloud emulator that
// is compiled into steam.dll. CNG produces RSA key blobs in its own binary
// format, not DER, so a small hand-rolled codec is required to emit the exact
// wire formats the protocol speaks:
//   - RSAPublicKey (PKCS#1) DER          -> b64 + "]" public-key response, "pkcs1"
//   - SubjectPublicKeyInfo DER           -> b64 + "]" public-key response, "spki"
//   - PKCS#8 PrivateKeyInfo (PEM round trip) -> key persistence file
// Nothing else lives here; all session/network logic is in emulator_core.cpp.
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace emuder {

// ---- Base64 (strict decode, mirroring Python's base64.b64decode(validate=True)) ----
std::string base64_encode(const std::uint8_t* data, std::size_t len);
std::string base64_encode(const std::vector<std::uint8_t>& data);
// Returns false on any non-alphabet character (excluding '=' padding) or malformed length.
bool base64_decode(std::string_view text, std::vector<std::uint8_t>& out);

// ---- PEM armor / unarmor (PKCS#8 "BEGIN PRIVATE KEY" style) ----
std::string pem_armor_private_key(const std::vector<std::uint8_t>& der);
bool pem_unarmor(std::string_view pem, std::vector<std::uint8_t>& der);

// ---- RSA component structs ----
struct RSAPublicComponents {
    std::vector<std::uint8_t> modulus_be;    // n, big-endian magnitude (no DER sign byte)
    std::vector<std::uint8_t> exponent_be;   // e, big-endian magnitude
};

struct RSAPrivateComponents {
    std::vector<std::uint8_t> modulus_be;            // n
    std::vector<std::uint8_t> exponent_be;           // e
    std::vector<std::uint8_t> private_exponent_be;   // d
    std::vector<std::uint8_t> prime1_be;             // p
    std::vector<std::uint8_t> prime2_be;             // q
    std::vector<std::uint8_t> exponent1_be;          // d mod (p-1)
    std::vector<std::uint8_t> exponent2_be;          // d mod (q-1)
    std::vector<std::uint8_t> coefficient_be;        // q^-1 mod p
};

// ---- DER building ----
std::vector<std::uint8_t> build_pkcs1_public_der(const RSAPublicComponents& pub);
std::vector<std::uint8_t> build_spki_der(const RSAPublicComponents& pub);
std::vector<std::uint8_t> build_pkcs8_private_der(const RSAPrivateComponents& priv);

// ---- DER parsing (return false on any malformed input) ----
bool parse_spki_public_der(const std::vector<std::uint8_t>& der, RSAPublicComponents& out);
bool parse_pkcs8_private_der(const std::vector<std::uint8_t>& der, RSAPrivateComponents& out);

} // namespace emuder
