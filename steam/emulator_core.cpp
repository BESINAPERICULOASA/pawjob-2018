// emulator_core.cpp — see emulator_core.h.
//
// Ports tools/runtime/local_cloud_emulator.py into steam.dll. The protocol is
// reproduced byte-for-byte from the Python reference (HELLO, b64(DER)+"]"
// public key, RSA-OAEP-SHA1 session exchange, AES-CBC-PKCS7 framing with both
// the length-indicated and standalone paths). Crypto is Windows CNG only; the
// DER/PEM/Base64 wire formats come from emulator_der.*.
#include "emulator_core.h"
#include "emulator_der.h"

// winsock2 must precede windows.h to avoid pulling in the legacy winsock.h.
// NOMINMAX keeps windows.h from defining min/max macros that break std::min.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <mutex>
#include <numeric>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {

// bcrypt.h in this SDK exposes BCRYPT_PAD_OAEP (0x00000004) but predates the
// BCRYPT_OAEP_PADDING alias used by newer headers; alias it for readability.
// The RSA public-exponent property is set by the documented string name.
#ifndef BCRYPT_OAEP_PADDING
#define BCRYPT_OAEP_PADDING BCRYPT_PAD_OAEP
#endif
#ifndef BCRYPT_PUBLIC_EXPONENT
#define BCRYPT_PUBLIC_EXPONENT L"PublicExponent"
#endif

constexpr std::string_view kHello = "hello server";
constexpr std::uint8_t kDelimiter = 0x5d;  // b"]"
constexpr std::uint16_t kListenPort = 5444;
constexpr std::size_t kRecvChunk = 65535;
constexpr std::size_t kMaxPayloadCiphertext = 1024 * 1024;
constexpr std::size_t kLogPreview = 256;
constexpr std::size_t kAesBlock = 16;

constexpr const char* kDefaultLoginResponse = "ok,0123456789abcdef,ok";
constexpr const char* kDefaultRequestResponse = "ok,0123456789abcdef,ok";
constexpr const char* kConfigListPrefix = "ok,0123456789abcdef";
constexpr const char* kConfigExtension = ".acupthz";
constexpr const char* kCountResponse = "0";

// ---- timestamp / preview helpers (mirror the Python logger) ----
std::string log_timestamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    return std::format("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

std::string hex_bytes(const std::uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve(len * 3);
    for (std::size_t i = 0; i < len; ++i) {
        if (!out.empty()) out.push_back(' ');
        out.append(std::format("{:02x}", data[i]));
    }
    return out;
}
std::string hex_bytes(const std::vector<std::uint8_t>& data) {
    return hex_bytes(data.data(), data.size());
}

std::string ascii_bytes(const std::uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve(len);
    for (std::size_t i = 0; i < len; ++i) {
        const std::uint8_t b = data[i];
        out.push_back((b >= 0x20 && b <= 0x7e) ? static_cast<char>(b) : '.');
    }
    return out;
}
std::string ascii_bytes(const std::vector<std::uint8_t>& data) {
    return ascii_bytes(data.data(), data.size());
}

std::string preview_suffix(std::size_t len) {
    if (len <= kLogPreview) return "";
    return std::format(" ...(+{} bytes)", len - kLogPreview);
}
std::string preview_hex(const std::vector<std::uint8_t>& data) {
    const std::size_t take = std::min(data.size(), kLogPreview);
    return hex_bytes(data.data(), take) + preview_suffix(data.size());
}
std::string preview_ascii(const std::vector<std::uint8_t>& data) {
    const std::size_t take = std::min(data.size(), kLogPreview);
    return ascii_bytes(data.data(), take) + preview_suffix(data.size());
}

// ---- thread-safe file logger (quiet when no path) ----
class EmulatorLog {
    std::mutex mutex_;
    std::filesystem::path path_;
    bool enabled_ = false;
public:
    void open(const std::filesystem::path& p) {
        path_ = p;
        enabled_ = !p.empty();
        if (enabled_) {
            std::error_code ec;
            std::filesystem::create_directories(p.parent_path(), ec);
        }
    }
    bool enabled() const { return enabled_; }
    void write(const std::string& line) {
        if (!enabled_) return;
        const std::string payload = log_timestamp() + " " + line + "\n";
        std::lock_guard<std::mutex> lk(mutex_);
        std::ofstream out(path_, std::ios::app);
        if (out) { out << payload; out.flush(); }
    }
};

// ---- byte buffer helpers ----
using Bytes = std::vector<std::uint8_t>;

bool send_all(SOCKET s, const std::uint8_t* data, std::size_t len) {
    std::size_t sent = 0;
    while (sent < len) {
        const int n = ::send(s, reinterpret_cast<const char*>(data + sent),
                             static_cast<int>(len - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

// ---- CNG RAII ----
struct CngAlg {
    BCRYPT_ALG_HANDLE handle = nullptr;
    bool open_rsa() {
        return BCryptOpenAlgorithmProvider(&handle, BCRYPT_RSA_ALGORITHM, nullptr, 0) == 0;
    }
    bool open_aes() {
        if (BCryptOpenAlgorithmProvider(&handle, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return false;
        // Set CBC chaining mode for AES.
        return BCryptSetProperty(handle, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<LPWSTR>(BCRYPT_CHAIN_MODE_CBC)),
            sizeof(BCRYPT_CHAIN_MODE_CBC), 0) == 0;
    }
    void close() { if (handle) { BCryptCloseAlgorithmProvider(handle, 0); handle = nullptr; } }
};

struct CngKey {
    BCRYPT_KEY_HANDLE handle = nullptr;
    void destroy() { if (handle) { BCryptDestroyKey(handle); handle = nullptr; } }
};

bool rsa_generate_keypair(BCRYPT_ALG_HANDLE alg, CngKey& out, emuder::RSAPublicComponents& pub) {
    // Pin e=65537 on the algorithm provider before generation. The Microsoft
    // Primitive Provider default is already 65537, but setting it explicitly
    // guarantees the self-test exponent assertion below is meaningful.
    ULONG pubExp = 65537;
    BCryptSetProperty(alg, BCRYPT_PUBLIC_EXPONENT, reinterpret_cast<PUCHAR>(&pubExp), sizeof(pubExp), 0);
    BCRYPT_KEY_HANDLE h = nullptr;
    if (BCryptGenerateKeyPair(alg, &h, 1024, 0) != 0) return false;
    if (BCryptFinalizeKeyPair(h, 0) != 0) { BCryptDestroyKey(h); return false; }
    ULONG cbBlob = 0;
    if (BCryptExportKey(h, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &cbBlob, 0) != 0) {
        BCryptDestroyKey(h); return false;
    }
    Bytes blob(cbBlob);
    if (BCryptExportKey(h, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob.data(), cbBlob, &cbBlob, 0) != 0) {
        BCryptDestroyKey(h); return false;
    }
    const auto* hdr = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(blob.data());
    const std::uint8_t* e = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
    const std::uint8_t* n = e + hdr->cbPublicExp;
    pub.exponent_be.assign(e, e + hdr->cbPublicExp);
    pub.modulus_be.assign(n, n + hdr->cbModulus);
    out.handle = h;
    return true;
}

bool rsa_export_full_private(BCRYPT_KEY_HANDLE key, emuder::RSAPrivateComponents& priv) {
    ULONG cbBlob = 0;
    if (BCryptExportKey(key, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &cbBlob, 0) != 0)
        return false;
    Bytes blob(cbBlob);
    if (BCryptExportKey(key, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, blob.data(), cbBlob, &cbBlob, 0) != 0)
        return false;
    const auto* hdr = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(blob.data());
    const std::uint8_t* p = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
    const std::uint8_t* e = p;            p += hdr->cbPublicExp;
    const std::uint8_t* n = p;            p += hdr->cbModulus;
    const std::uint8_t* p1 = p;           p += hdr->cbPrime1;
    const std::uint8_t* p2 = p;           p += hdr->cbPrime2;
    const std::uint8_t* e1 = p;           p += hdr->cbPrime1;
    const std::uint8_t* e2 = p;           p += hdr->cbPrime2;
    const std::uint8_t* c  = p;           p += hdr->cbPrime1;
    const std::uint8_t* d  = p;           p += hdr->cbModulus;
    priv.exponent_be.assign(e, e + hdr->cbPublicExp);
    priv.modulus_be.assign(n, n + hdr->cbModulus);
    priv.prime1_be.assign(p1, p1 + hdr->cbPrime1);
    priv.prime2_be.assign(p2, p2 + hdr->cbPrime2);
    priv.exponent1_be.assign(e1, e1 + hdr->cbPrime1);
    priv.exponent2_be.assign(e2, e2 + hdr->cbPrime2);
    priv.coefficient_be.assign(c, c + hdr->cbPrime1);
    priv.private_exponent_be.assign(d, d + hdr->cbModulus);
    return true;
}

bool rsa_import_public(BCRYPT_ALG_HANDLE alg, const emuder::RSAPublicComponents& pub, CngKey& out) {
    BCRYPT_RSAKEY_BLOB hdr{};
    hdr.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    hdr.BitLength = static_cast<ULONG>(pub.modulus_be.size() * 8);
    hdr.cbPublicExp = static_cast<ULONG>(pub.exponent_be.size());
    hdr.cbModulus = static_cast<ULONG>(pub.modulus_be.size());
    hdr.cbPrime1 = 0;
    hdr.cbPrime2 = 0;
    Bytes blob;
    blob.insert(blob.end(), reinterpret_cast<std::uint8_t*>(&hdr),
                reinterpret_cast<std::uint8_t*>(&hdr) + sizeof(hdr));
    blob.insert(blob.end(), pub.exponent_be.begin(), pub.exponent_be.end());
    blob.insert(blob.end(), pub.modulus_be.begin(), pub.modulus_be.end());
    return BCryptImportKey(alg, nullptr, BCRYPT_RSAPUBLIC_BLOB, &out.handle, nullptr, 0,
        blob.data(), static_cast<ULONG>(blob.size()), 0) == 0;
}

bool rsa_import_full_private(BCRYPT_ALG_HANDLE alg, const emuder::RSAPrivateComponents& priv, CngKey& out) {
    BCRYPT_RSAKEY_BLOB hdr{};
    hdr.Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
    hdr.BitLength = static_cast<ULONG>(priv.modulus_be.size() * 8);
    hdr.cbPublicExp = static_cast<ULONG>(priv.exponent_be.size());
    hdr.cbModulus = static_cast<ULONG>(priv.modulus_be.size());
    hdr.cbPrime1 = static_cast<ULONG>(priv.prime1_be.size());
    hdr.cbPrime2 = static_cast<ULONG>(priv.prime2_be.size());
    Bytes blob;
    blob.insert(blob.end(), reinterpret_cast<std::uint8_t*>(&hdr),
                reinterpret_cast<std::uint8_t*>(&hdr) + sizeof(hdr));
    blob.insert(blob.end(), priv.exponent_be.begin(), priv.exponent_be.end());
    blob.insert(blob.end(), priv.modulus_be.begin(), priv.modulus_be.end());
    blob.insert(blob.end(), priv.prime1_be.begin(), priv.prime1_be.end());
    blob.insert(blob.end(), priv.prime2_be.begin(), priv.prime2_be.end());
    blob.insert(blob.end(), priv.exponent1_be.begin(), priv.exponent1_be.end());
    blob.insert(blob.end(), priv.exponent2_be.begin(), priv.exponent2_be.end());
    blob.insert(blob.end(), priv.coefficient_be.begin(), priv.coefficient_be.end());
    blob.insert(blob.end(), priv.private_exponent_be.begin(), priv.private_exponent_be.end());
    return BCryptImportKey(alg, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, &out.handle, nullptr, 0,
        blob.data(), static_cast<ULONG>(blob.size()), 0) == 0;
}

bool rsa_oaep_sha1_decrypt(BCRYPT_KEY_HANDLE key, const std::uint8_t* ct, std::size_t ctLen, Bytes& out) {
    BCRYPT_OAEP_PADDING_INFO pad{};
    pad.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    pad.pbLabel = nullptr;
    pad.cbLabel = 0;
    PUCHAR pCt = const_cast<PUCHAR>(ct);
    ULONG cbResult = 0;
    if (BCryptDecrypt(key, pCt, static_cast<ULONG>(ctLen), &pad, nullptr, 0, nullptr, 0, &cbResult,
        BCRYPT_OAEP_PADDING) != 0) return false;
    out.resize(cbResult);
    const NTSTATUS st = BCryptDecrypt(key, pCt, static_cast<ULONG>(ctLen), &pad, nullptr, 0,
        out.data(), cbResult, &cbResult, BCRYPT_OAEP_PADDING);
    if (st != 0) { out.clear(); return false; }
    out.resize(cbResult);
    return true;
}

bool rsa_oaep_sha1_encrypt(BCRYPT_KEY_HANDLE key, const std::uint8_t* pt, std::size_t ptLen, Bytes& out) {
    BCRYPT_OAEP_PADDING_INFO pad{};
    pad.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    pad.pbLabel = nullptr;
    pad.cbLabel = 0;
    // CNG takes PUCHAR (non-const); the input is read-only on the encrypt path.
    PUCHAR pIn = const_cast<PUCHAR>(pt);
    ULONG cbResult = 0;
    if (BCryptEncrypt(key, pIn, static_cast<ULONG>(ptLen), &pad, nullptr, 0, nullptr, 0, &cbResult,
        BCRYPT_OAEP_PADDING) != 0) return false;
    out.resize(cbResult);
    const NTSTATUS st = BCryptEncrypt(key, pIn, static_cast<ULONG>(ptLen), &pad, nullptr, 0,
        out.data(), cbResult, &cbResult, BCRYPT_OAEP_PADDING);
    if (st != 0) { out.clear(); return false; }
    out.resize(cbResult);
    return true;
}

// AES-CBC with BCRYPT_BLOCK_PADDING (PKCS7). A fresh IV copy is taken because
// CNG updates pbIV in place; the session reuses the same IV for every frame, so
// the original IV bytes must be preserved across calls.
bool aes_cbc_encrypt(BCRYPT_ALG_HANDLE alg, const std::uint8_t* key, std::size_t keyLen,
                     const std::uint8_t* iv16, const std::uint8_t* pt, std::size_t ptLen, Bytes& out) {
    CngKey hKey;
    if (BCryptGenerateSymmetricKey(alg, &hKey.handle, nullptr, 0,
        const_cast<PUCHAR>(key), static_cast<ULONG>(keyLen), 0) != 0) return false;
    std::uint8_t iv[kAesBlock];
    std::memcpy(iv, iv16, kAesBlock);
    PUCHAR pIn = const_cast<PUCHAR>(pt);
    ULONG cbResult = 0;
    if (BCryptEncrypt(hKey.handle, pIn, static_cast<ULONG>(ptLen), nullptr, iv, kAesBlock, nullptr, 0,
        &cbResult, BCRYPT_BLOCK_PADDING) != 0) { hKey.destroy(); return false; }
    out.resize(cbResult);
    std::memcpy(iv, iv16, kAesBlock);
    const NTSTATUS st = BCryptEncrypt(hKey.handle, pIn, static_cast<ULONG>(ptLen), nullptr, iv, kAesBlock,
        out.data(), cbResult, &cbResult, BCRYPT_BLOCK_PADDING);
    hKey.destroy();
    if (st != 0) { out.clear(); return false; }
    out.resize(cbResult);
    return true;
}

bool aes_cbc_decrypt(BCRYPT_ALG_HANDLE alg, const std::uint8_t* key, std::size_t keyLen,
                     const std::uint8_t* iv16, const std::uint8_t* ct, std::size_t ctLen, Bytes& out) {
    CngKey hKey;
    if (BCryptGenerateSymmetricKey(alg, &hKey.handle, nullptr, 0,
        const_cast<PUCHAR>(key), static_cast<ULONG>(keyLen), 0) != 0) return false;
    std::uint8_t iv[kAesBlock];
    std::memcpy(iv, iv16, kAesBlock);
    PUCHAR pCt = const_cast<PUCHAR>(ct);
    ULONG cbResult = 0;
    if (BCryptDecrypt(hKey.handle, pCt, static_cast<ULONG>(ctLen), nullptr, iv, kAesBlock, nullptr, 0,
        &cbResult, BCRYPT_BLOCK_PADDING) != 0) { hKey.destroy(); return false; }
    out.resize(cbResult);
    std::memcpy(iv, iv16, kAesBlock);
    const NTSTATUS st = BCryptDecrypt(hKey.handle, pCt, static_cast<ULONG>(ctLen), nullptr, iv, kAesBlock,
        out.data(), cbResult, &cbResult, BCRYPT_BLOCK_PADDING);
    hKey.destroy();
    if (st != 0) { out.clear(); return false; }
    out.resize(cbResult);
    return true;
}

// ---- string / field helpers (mirror sanitize_field, sanitize_config_name) ----
bool is_printable_keep(std::uint8_t u) {
    const bool in_printable = (u == 0x09 || u == 0x0a || u == 0x0b || u == 0x0c || u == 0x0d ||
                               (u >= 0x20 && u <= 0x7e));
    if (!in_printable) return false;
    if (u == ',' || u == '\r' || u == '\n' || u == '\t') return false;
    return true;
}

std::string sanitize_field(std::string_view value) {
    std::string out;
    for (char ch : value) if (is_printable_keep(static_cast<std::uint8_t>(ch))) out.push_back(ch);
    const auto is_ws = [](char ch) {
        const std::uint8_t u = static_cast<std::uint8_t>(ch);
        return u == 0x20 || u == 0x09 || u == 0x0a || u == 0x0d || u == 0x0b || u == 0x0c;
    };
    std::size_t a = 0, b = out.size();
    while (a < b && is_ws(out[a])) ++a;
    while (b > a && is_ws(out[b - 1])) --b;
    return out.substr(a, b - a);
}

std::string sanitize_config_name(std::string_view value) {
    std::string cleaned = sanitize_field(value);
    static const char kBad[] = "<>:\"/\\|?*";
    std::string out;
    for (char ch : cleaned) {
        if (std::strchr(kBad, ch) == nullptr) out.push_back(ch);
    }
    const auto is_strip = [](char ch) { return ch == ' ' || ch == '.'; };
    std::size_t a = 0, b = out.size();
    while (a < b && is_strip(out[a])) ++a;
    while (b > a && is_strip(out[b - 1])) --b;
    return out.substr(a, b - a);
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool ends_with_ci(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           to_lower(s).compare(s.size() - suffix.size(), suffix.size(), to_lower(suffix)) == 0;
}

std::vector<std::string> split_comma(const std::string& s) {
    std::vector<std::string> fields;
    std::string cur;
    for (char ch : s) { if (ch == ',') { fields.push_back(cur); cur.clear(); } else cur.push_back(ch); }
    fields.push_back(cur);
    return fields;
}

// decode("ascii") — strict: returns false if any byte >= 0x80.
bool ascii_split_strict(const Bytes& payload, std::vector<std::string>& fields) {
    fields.clear();
    std::string s;
    for (auto b : payload) {
        if (b >= 0x80) return false;
        s.push_back(static_cast<char>(b));
    }
    fields = split_comma(s);
    return true;
}

// decode("ascii", errors="ignore") — drop non-ASCII bytes before splitting.
std::vector<std::string> ascii_split_ignore(const Bytes& payload) {
    std::string s;
    for (auto b : payload) if (b < 0x80) s.push_back(static_cast<char>(b));
    return split_comma(s);
}

std::filesystem::path config_file_path(const std::filesystem::path& config_dir,
                                       std::string_view extension, std::string_view name) {
    std::string safe = sanitize_config_name(name);
    if (safe.empty()) throw std::runtime_error("empty config name");
    if (!extension.empty()) {
        const std::string ext(extension);
        if (!ends_with_ci(safe, ext)) safe += ext;
    }
    return config_dir / safe;
}

std::vector<std::string> read_config_names(const std::filesystem::path& config_dir, std::string_view extension) {
    std::vector<std::string> names;
    if (config_dir.empty()) return names;
    std::error_code ec;
    if (!std::filesystem::exists(config_dir, ec)) return names;
    struct Entry { std::string name_lower; std::filesystem::path path; };
    std::vector<Entry> entries;
    const std::string ext(extension);
    for (auto it = std::filesystem::directory_iterator(config_dir, ec);
         !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
        const auto& p = it->path();
        std::error_code fec;
        if (!std::filesystem::is_regular_file(p, fec)) continue;
        const std::string fname = p.filename().string();
        if (!ext.empty()) {
            if (!ends_with_ci(fname, ext)) continue;
        }
        entries.push_back({to_lower(fname), p});
    }
    std::sort(entries.begin(), entries.end(),
              [](const Entry& a, const Entry& b) { return a.name_lower < b.name_lower; });
    for (const auto& e : entries) {
        const std::string name = sanitize_field(e.path.stem().string());
        if (!name.empty()) names.push_back(name);
    }
    return names;
}

Bytes build_config_list_response(const std::filesystem::path& config_dir, std::string_view extension,
                                std::string_view prefix, bool empty, std::vector<std::string>& out_names) {
    out_names.clear();
    if (!empty) {
        out_names = read_config_names(config_dir, extension);
        if (out_names.size() > 20) out_names.resize(20);
    }
    std::vector<std::string> fields;
    for (const auto& part : split_comma(std::string(prefix))) {
        const std::string s = sanitize_field(part);
        if (!s.empty()) fields.push_back(s);
    }
    fields.push_back(std::to_string(out_names.size()));
    for (const auto& n : out_names) { fields.push_back(n); fields.push_back(n); fields.push_back(n); }
    std::string joined;
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (i) joined.push_back(',');
        joined += fields[i];
    }
    return Bytes(joined.begin(), joined.end());
}

struct SaveResult { std::filesystem::path target; std::string config_name; std::size_t blob_len; };
SaveResult save_config_blob(const std::filesystem::path& config_dir, std::string_view extension,
                           const Bytes& payload) {
    if (config_dir.empty()) throw std::runtime_error("config directory is not set");
    std::vector<std::string> fields;
    if (!ascii_split_strict(payload, fields)) throw std::runtime_error("non-ascii payload");
    if (fields.size() < 5) throw std::runtime_error("expected at least 5 fields");
    const std::string config_name = sanitize_config_name(fields[3]);
    const std::string& config_blob = fields[4];
    const std::filesystem::path target = config_file_path(config_dir, extension, config_name);
    std::error_code ec;
    std::filesystem::create_directories(target.parent_path(), ec);
    std::ofstream out(target, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot open config file");
    out.write(config_blob.data(), static_cast<std::streamsize>(config_blob.size()));
    if (!out) throw std::runtime_error("write failed");
    return { target, config_name, config_blob.size() };
}

Bytes config_mutation_response(const Bytes& payload, std::string_view config_name) {
    const std::vector<std::string> fields = ascii_split_ignore(payload);
    std::string request_token = "0123456789abcdef";
    if (fields.size() > 1) {
        const std::string t = sanitize_field(fields[1]);
        if (!t.empty()) request_token = t;
    }
    const std::string r = "ok," + request_token + "," + std::string(config_name);
    return Bytes(r.begin(), r.end());
}

struct DeleteResult {
    std::filesystem::path target;
    std::string config_name;
    bool deleted;
};
DeleteResult delete_config_file(const std::filesystem::path& config_dir, std::string_view extension,
                               const Bytes& payload) {
    if (config_dir.empty()) throw std::runtime_error("config directory is not set");
    std::vector<std::string> fields;
    if (!ascii_split_strict(payload, fields)) throw std::runtime_error("non-ascii payload");
    if (fields.size() < 4) throw std::runtime_error("expected at least 4 fields");
    const std::string config_name = sanitize_config_name(fields[3]);
    const std::filesystem::path target = config_file_path(config_dir, extension, config_name);
    DeleteResult r{ target, config_name, false };
    std::error_code ec;
    if (!std::filesystem::exists(target, ec)) return r;  // delete of missing is ok
    // The reference emulator archives deletes to .deleted\<stem>.<stamp><ext>.
    // The operator explicitly does not want a .deleted tree under
    // pawjob\configs, so configs are removed outright instead. The on-wire
    // response is unchanged (delete of missing or present is "ok").
    std::filesystem::remove(target, ec);
    if (ec) throw std::runtime_error("remove failed");
    r.deleted = true;
    return r;
}

struct LoadResult { Bytes response; std::filesystem::path target; std::string config_name; std::size_t blob_len; bool status_only; bool has_target; };
LoadResult load_config_blob(const std::filesystem::path& config_dir, std::string_view extension,
                           const Bytes& payload, const Bytes& status_response, const Bytes& default_response,
                           bool has_fallback, std::string_view fallback) {
    std::vector<std::string> fields;
    if (!ascii_split_strict(payload, fields)) throw std::runtime_error("non-ascii payload");
    if (fields.size() < 4) throw std::runtime_error("expected at least 4 fields");
    // Python: sanitize_field(fields[1]) if len(fields) > 1 else "0123456789abcdef"
    // Note: an empty sanitized token stays empty (no fallback here, unlike config_mutation_response).
    std::string request_token = "0123456789abcdef";
    if (fields.size() > 1) {
        request_token = sanitize_field(fields[1]);
    }
    std::string config_name = sanitize_config_name(fields[3]);
    if (to_lower(config_name) == "ok") {
        if (has_fallback && !fallback.empty()) {
            config_name = sanitize_config_name(fallback);
        } else {
            const Bytes& resp = !status_response.empty() ? status_response : default_response;
            return { resp, {}, config_name, 0, true, false };
        }
    }
    if (config_dir.empty()) throw std::runtime_error("config directory is not set");
    const std::filesystem::path target = config_file_path(config_dir, extension, config_name);
    std::error_code ec;
    if (!std::filesystem::exists(target, ec)) throw std::runtime_error("file not found");
    std::ifstream in(target, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open");
    const Bytes blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const std::string head = "ok," + request_token + ",2," + config_name + ",";
    Bytes response(head.begin(), head.end());
    response.insert(response.end(), blob.begin(), blob.end());
    return { response, target, config_name, blob.size(), false, true };
}

// parse_csv_command_id: returns fields[2], or false (< 3 fields / non-ASCII).
bool parse_csv_command_id(const Bytes& payload, std::string& command_id) {
    command_id.clear();
    for (auto b : payload) if (b >= 0x80) return false;
    const std::vector<std::string> fields = split_comma(std::string(payload.begin(), payload.end()));
    if (fields.size() < 3) return false;
    command_id = fields[2];
    return true;
}

// Mirror Python's int(text, 10): leading/trailing whitespace is stripped, an
// optional single sign is allowed, underscores between digits are ignored,
// and the remaining characters must be ASCII digits. A parseable value that
// overflows `long` is reported as parsed (returns true) but clamped to a
// sentinel above kMaxPayloadCiphertext so the caller's >1MiB check routes it
// to client_control_block — matching Python, where the parse succeeds and the
// subsequent range test rejects it (rather than the parse itself throwing).
bool parse_decimal(const std::string& s, long& out) {
    // Strip leading ASCII whitespace (Python str strips the same set on int()).
    std::size_t a = 0, b = s.size();
    auto is_ws = [](char ch) {
        const unsigned char u = static_cast<unsigned char>(ch);
        return u == ' ' || u == '\t' || u == '\n' || u == '\r' || u == 0x0b || u == 0x0c;
    };
    while (a < b && is_ws(s[a])) ++a;
    while (b > a && is_ws(s[b - 1])) --b;
    if (a >= b) return false;  // empty or all-whitespace -> ValueError

    bool negative = false;
    if (s[a] == '+') ++a;
    else if (s[a] == '-') { negative = true; ++a; }
    if (a >= b) return false;  // sign with no digits -> ValueError

    // Accumulate digits, skipping single underscores that sit between digits
    // (Python int() allows "1_000" but not "_1000" or "1000_").
    unsigned long long mag = 0;
    bool have_digit = false;
    bool prev_under = false;
    bool overflow = false;
    for (std::size_t i = a; i < b; ++i) {
        const char ch = s[i];
        if (ch == '_') {
            if (!have_digit || prev_under) return false;  // leading/double underscore
            prev_under = true;
            continue;
        }
        if (ch < '0' || ch > '9') return false;
        prev_under = false;
        have_digit = true;
        mag = mag * 10ull + static_cast<unsigned long long>(ch - '0');
        if (mag > 0x7fffffffffffffffull) overflow = true;
    }
    if (!have_digit || prev_under) return false;  // no digits, or a trailing underscore

    if (overflow) {
        // Parsed successfully but too large for long; clamp above 1MiB so the
        // caller's range check routes to client_control_block (Python behavior).
        out = -1;
        return true;
    }
    out = negative ? -static_cast<long>(mag) : static_cast<long>(mag);
    return true;
}

// ---- shared listener state ----
Bytes byte_range(std::string_view s) { return Bytes(s.begin(), s.end()); }

struct SharedEmulator {
    EmulatorConfig config;
    EmulatorLog log;
    CngAlg rsa_alg;
    CngAlg aes_alg;
    CngKey rsa_key;                 // shared private key; read-only across client threads
    Bytes public_response;          // b64(spki_der) + "]"  — precomputed
    int rsa_bits = 0;

    std::set<std::string> config_list_commands{"9", "19"};
    std::set<std::string> pure_config_list_commands{"19"};
    std::set<std::string> count_response_commands{"7", "17"};
    std::set<std::string> save_config_commands{"10", "13"};
    std::set<std::string> delete_config_commands{"11"};
    std::set<std::string> load_config_commands{"12"};
    std::set<std::string> echo_commands{};
    std::set<std::string> reply_commands{"14"};
    Bytes count_response{byte_range(kCountResponse)};
    Bytes login_response{byte_range(kDefaultLoginResponse)};
    Bytes request_response{byte_range(kDefaultRequestResponse)};
    Bytes default_request_response{byte_range(kDefaultRequestResponse)};  // used when request_response is "None"
    bool has_request_response = true;
    std::string config_list_prefix = kConfigListPrefix;
    std::string config_extension = kConfigExtension;

    std::atomic<bool> running{false};
    std::atomic<bool> stop_flag{false};
    std::atomic<int> next_client_id{1};
    SOCKET listener_socket = INVALID_SOCKET;
    std::mutex start_mutex;
};

SharedEmulator g_emu;

// ---- protocol primitives ----
Bytes public_key_response(const emuder::RSAPublicComponents& pub) {
    const Bytes spki = emuder::build_spki_der(pub);
    const std::string b64 = emuder::base64_encode(spki.data(), spki.size());
    Bytes out(b64.begin(), b64.end());
    out.push_back(kDelimiter);
    return out;
}

struct SessionKeys { Bytes plaintext, aes_key, aes_iv; };
bool decrypt_session_packet(BCRYPT_KEY_HANDLE rsaKey, const std::string& b64packet,
                           SessionKeys& sk, EmulatorLog& log, int client_id) {
    Bytes ciphertext;
    if (!emuder::base64_decode(b64packet, ciphertext) || ciphertext.empty()) {
        log.write(std::format("client={} event=error error=\"invalid session packet base64\"", client_id));
        return false;
    }
    Bytes plaintext;
    if (!rsa_oaep_sha1_decrypt(rsaKey, ciphertext.data(), ciphertext.size(), plaintext)) {
        log.write(std::format("client={} event=error error=\"rsa decrypt failed\"", client_id));
        return false;
    }
    // split plaintext on ','
    std::string s(plaintext.begin(), plaintext.end());
    std::vector<std::string> parts = split_comma(s);
    if (parts.size() != 2) {
        log.write(std::format("client={} event=error error=\"expected two comma-separated base64 fields, got {}\"",
            client_id, parts.size()));
        return false;
    }
    Bytes aes_key, aes_iv;
    if (!emuder::base64_decode(parts[0], aes_key)) {
        log.write(std::format("client={} event=error error=\"aes key base64 invalid\"", client_id));
        return false;
    }
    if (!emuder::base64_decode(parts[1], aes_iv)) {
        log.write(std::format("client={} event=error error=\"aes iv base64 invalid\"", client_id));
        return false;
    }
    if (aes_key.size() != 16 && aes_key.size() != 24 && aes_key.size() != 32) {
        log.write(std::format("client={} event=error error=\"expected AES key and 16-byte IV, got key={}\"",
            client_id, aes_key.size()));
        return false;
    }
    if (aes_iv.size() < 16) {
        log.write(std::format("client={} event=error error=\"expected AES key and 16-byte IV, got iv={}\"",
            client_id, aes_iv.size()));
        return false;
    }
    aes_iv.resize(16);  // truncate to first 16 bytes — intentional, preserved from Python
    sk.plaintext = plaintext;
    sk.aes_key = aes_key;
    sk.aes_iv = aes_iv;
    return true;
}

bool build_server_frames(SharedEmulator& emu, const SessionKeys& sk, const Bytes& plaintext,
                         const std::string& length_mode, Bytes& length_frame, Bytes& payload_frame,
                         std::string& length_text) {
    if (!aes_cbc_encrypt(emu.aes_alg.handle, sk.aes_key.data(), sk.aes_key.size(),
                         sk.aes_iv.data(), plaintext.data(), plaintext.size(), payload_frame))
        return false;
    std::string lt;
    if (length_mode == "bytes") lt = std::to_string(payload_frame.size());
    else if (length_mode == "blocks") lt = std::to_string(payload_frame.size() / kAesBlock);
    else return false;
    const Bytes ltbytes(lt.begin(), lt.end());
    if (!aes_cbc_encrypt(emu.aes_alg.handle, sk.aes_key.data(), sk.aes_key.size(),
                         sk.aes_iv.data(), ltbytes.data(), ltbytes.size(), length_frame))
        return false;
    length_text = lt;
    return true;
}

void send_server_frame(SOCKET sock, SharedEmulator& emu, int client_id, const SessionKeys& sk,
                       const Bytes& plaintext, const std::string& reason, const std::string& length_mode) {
    Bytes length_frame, payload_frame;
    std::string length_text;
    if (!build_server_frames(emu, sk, plaintext, length_mode, length_frame, payload_frame, length_text)) {
        emu.log.write(std::format("client={} event=send_server_frame_error reason={}", client_id, reason));
        return;
    }
    send_all(sock, length_frame.data(), length_frame.size());
    emu.log.write(std::format(
        "client={} event=send_server_length_frame reason={} length_mode={} bytes={} plaintext_ascii=\"{}\" "
        "payload_ciphertext_bytes={} hex=\"{}\"",
        client_id, reason, length_mode, length_frame.size(), length_text, payload_frame.size(),
        hex_bytes(length_frame)));
    send_all(sock, payload_frame.data(), payload_frame.size());
    emu.log.write(std::format(
        "client={} event=send_server_payload_frame reason={} bytes={} plaintext_ascii=\"{}\" hex=\"{}\"",
        client_id, reason, payload_frame.size(), preview_ascii(plaintext), preview_hex(payload_frame)));
}

void log_packet(EmulatorLog& log, int client_id, int packet_id, const Bytes& data) {
    log.write(std::format("client={} packet={} bytes={} hex=\"{}\" ascii=\"{}\"",
        client_id, packet_id, data.size(), preview_hex(data), preview_ascii(data)));
}

// recv until the delimiter; on socket close returns false (mirrors Python ConnectionError).
bool read_until_delimiter(SOCKET sock, EmulatorLog& log, int client_id, int& packet_counter,
                          const Bytes& initial, Bytes& message_out, Bytes& remainder_out) {
    Bytes buffer = initial;
    for (;;) {
        const std::size_t pos = std::find(buffer.begin(), buffer.end(), kDelimiter) - buffer.begin();
        if (pos < buffer.size()) {
            message_out.assign(buffer.begin(), buffer.begin() + pos);
            remainder_out.assign(buffer.begin() + pos + 1, buffer.end());
            return true;
        }
        Bytes chunk(kRecvChunk);
        const int n = ::recv(sock, reinterpret_cast<char*>(chunk.data()), static_cast<int>(kRecvChunk), 0);
        if (n <= 0) return false;
        chunk.resize(static_cast<std::size_t>(n));
        ++packet_counter;
        log_packet(log, client_id, packet_counter, chunk);
        buffer.insert(buffer.end(), chunk.begin(), chunk.end());
    }
}

// ---- client frame state machine (faithful port of read_client_frames) ----
void read_client_frames(SharedEmulator& emu, SOCKET sock, int client_id, int& packet_counter,
                        const SessionKeys& sk, Bytes initial) {
    Bytes buffer = std::move(initial);
    long pending_payload_length = 0;
    bool pending_set = false;
    int frame_counter = 0;
    bool expect_standalone_payload = false;
    std::string last_saved_config_name;
    bool has_last_saved = false;

    for (;;) {
        for (;;) {
            if (expect_standalone_payload && !buffer.empty()) {
                if (buffer.size() % kAesBlock != 0) break;
                ++frame_counter;
                Bytes payload_frame = buffer;
                buffer.clear();
                expect_standalone_payload = false;
                Bytes payload_plaintext;
                if (!aes_cbc_decrypt(emu.aes_alg.handle, sk.aes_key.data(), sk.aes_key.size(),
                                     sk.aes_iv.data(), payload_frame.data(), payload_frame.size(),
                                     payload_plaintext)) {
                    emu.log.write(std::format(
                        "client={} event=client_standalone_payload_error frame={} ciphertext_bytes={} "
                        "ciphertext_hex=\"{}\" error=\"aes decrypt failed\"",
                        client_id, frame_counter, payload_frame.size(), preview_hex(payload_frame)));
                    break;
                }
                std::string command_id;
                parse_csv_command_id(payload_plaintext, command_id);
                emu.log.write(std::format(
                    "client={} event=client_standalone_payload frame={} command_id=\"{}\" "
                    "ciphertext_bytes={} plaintext_bytes={} plaintext_ascii=\"{}\" plaintext_hex=\"{}\"",
                    client_id, frame_counter,
                    command_id.empty() ? std::string("<unknown>") : command_id,
                    payload_frame.size(), payload_plaintext.size(),
                    preview_ascii(payload_plaintext), preview_hex(payload_plaintext)));

                Bytes response_plaintext;
                bool has_response = false;
                std::string response_reason = "standalone_payload";

                if (emu.config_list_commands.count(command_id)) {
                    const bool use_pure = emu.pure_config_list_commands.count(command_id) != 0;
                    std::vector<std::string> names;
                    response_plaintext = build_config_list_response(
                        emu.config.config_dir, emu.config_extension,
                        use_pure ? std::string_view("") : std::string_view(emu.config_list_prefix),
                        false, names);
                    response_reason = std::format("config_list_command_{}", command_id);
                    emu.log.write(std::format(
                        "client={} event=config_list_response command_id=\"{}\" format=\"{}\" "
                        "config_dir=\"{}\" names=\"{}\" plaintext_ascii=\"{}\"",
                        client_id, command_id, use_pure ? "pure_count" : "prefixed",
                        emu.config.config_dir.string(), names.empty() ? std::string("<none>") :
                        std::accumulate(std::next(names.begin()), names.end(), names[0],
                            [](const std::string& a, const std::string& b) { return a + "," + b; }),
                        preview_ascii(response_plaintext)));
                    has_response = true;
                } else if (emu.count_response_commands.count(command_id)) {
                    response_plaintext = emu.count_response;
                    response_reason = std::format("count_response_command_{}", command_id);
                    emu.log.write(std::format(
                        "client={} event=count_response command_id=\"{}\" plaintext_ascii=\"{}\"",
                        client_id, command_id, ascii_bytes(response_plaintext)));
                    has_response = true;
                } else if (emu.save_config_commands.count(command_id)) {
                    try {
                        const SaveResult sr = save_config_blob(
                            emu.config.config_dir, emu.config_extension, payload_plaintext);
                        last_saved_config_name = sr.config_name;
                        has_last_saved = true;
                        response_plaintext = config_mutation_response(payload_plaintext, sr.config_name);
                        response_reason = std::format("save_config_command_{}", command_id);
                        emu.log.write(std::format(
                            "client={} event=save_config command_id=\"{}\" name=\"{}\" path=\"{}\" "
                            "bytes={} response_ascii=\"{}\"",
                            client_id, command_id, sr.config_name, sr.target.string(),
                            sr.blob_len, ascii_bytes(response_plaintext)));
                        has_response = true;
                    } catch (const std::exception& exc) {
                        response_plaintext = Bytes{'e', 'r', 'r', 'o', 'r'};
                        response_reason = std::format("save_config_error_command_{}", command_id);
                        emu.log.write(std::format(
                            "client={} event=save_config_error command_id=\"{}\" error=\"{}\"",
                            client_id, command_id, exc.what()));
                        has_response = true;
                    }
                } else if (emu.delete_config_commands.count(command_id)) {
                    try {
                        const DeleteResult dr = delete_config_file(
                            emu.config.config_dir, emu.config_extension, payload_plaintext);
                        // Python: request_response if request_response is not None else DEFAULT_REQUEST_RESPONSE
                        response_plaintext = emu.has_request_response ? emu.request_response : emu.default_request_response;
                        response_reason = std::format("delete_config_command_{}", command_id);
                        emu.log.write(std::format(
                            "client={} event=delete_config command_id=\"{}\" name=\"{}\" path=\"{}\" "
                            "deleted={} response_ascii=\"{}\"",
                            client_id, command_id, dr.config_name, dr.target.string(),
                            dr.deleted ? 1 : 0,
                            ascii_bytes(response_plaintext)));
                        has_response = true;
                    } catch (const std::exception& exc) {
                        response_plaintext = Bytes{'e', 'r', 'r', 'o', 'r'};
                        response_reason = std::format("delete_config_error_command_{}", command_id);
                        emu.log.write(std::format(
                            "client={} event=delete_config_error command_id=\"{}\" error=\"{}\"",
                            client_id, command_id, exc.what()));
                        has_response = true;
                    }
                } else if (emu.load_config_commands.count(command_id)) {
                    try {
                        const std::string fb = has_last_saved ? last_saved_config_name : std::string();
                        LoadResult lr = load_config_blob(
                            emu.config.config_dir, emu.config_extension, payload_plaintext,
                            emu.request_response, emu.default_request_response, has_last_saved, fb);
                        response_plaintext = lr.response;
                        response_reason = std::format("load_config_command_{}", command_id);
                        emu.log.write(std::format(
                            "client={} event=load_config command_id=\"{}\" name=\"{}\" path=\"{}\" "
                            "bytes={} response_bytes={} status_only={} response_preview=\"{}\"",
                            client_id, command_id, lr.config_name,
                            lr.has_target ? lr.target.string() : std::string("<status>"),
                            lr.blob_len, response_plaintext.size(), lr.status_only ? 1 : 0,
                            preview_ascii(response_plaintext)));
                        has_response = true;
                    } catch (const std::exception& exc) {
                        response_plaintext = Bytes{'e', 'r', 'r', 'o', 'r'};
                        response_reason = std::format("load_config_error_command_{}", command_id);
                        emu.log.write(std::format(
                            "client={} event=load_config_error command_id=\"{}\" error=\"{}\"",
                            client_id, command_id, exc.what()));
                        has_response = true;
                    }
                } else if (!emu.echo_commands.empty() && emu.echo_commands.count(command_id)) {
                    response_plaintext = payload_plaintext;
                    response_reason = std::format("standalone_payload_echo_command_{}", command_id);
                    has_response = true;
                } else if (emu.has_request_response && emu.reply_commands.count(command_id)) {
                    response_plaintext = emu.request_response;
                    has_response = true;  // response_reason stays "standalone_payload"
                }

                if (has_response) {
                    send_server_frame(sock, emu, client_id, sk, response_plaintext, response_reason, "blocks");
                } else {
                    const std::string reason = emu.has_request_response ? "command_not_enabled" : "request_response_disabled";
                    emu.log.write(std::format(
                        "client={} event=no_server_response reason={} command_id=\"{}\"",
                        client_id, reason, command_id.empty() ? std::string("<unknown>") : command_id));
                }
                continue;
            }

            if (!pending_set) {
                if (buffer.size() < kAesBlock) break;
                Bytes length_frame(buffer.begin(), buffer.begin() + kAesBlock);
                buffer.erase(buffer.begin(), buffer.begin() + kAesBlock);
                ++frame_counter;
                Bytes length_plaintext;
                if (!aes_cbc_decrypt(emu.aes_alg.handle, sk.aes_key.data(), sk.aes_key.size(),
                                     sk.aes_iv.data(), length_frame.data(), length_frame.size(),
                                     length_plaintext)) {
                    emu.log.write(std::format(
                        "client={} event=client_frame_length_error frame={} ciphertext_hex=\"{}\" "
                        "error=\"aes decrypt failed\"",
                        client_id, frame_counter, hex_bytes(length_frame)));
                    expect_standalone_payload = true;
                    continue;
                }
                // Python: length_plaintext.decode("ascii") raises on a non-ASCII
                // byte -> client_frame_length_error. Otherwise int(text, 10) parses
                // (stripping whitespace, accepting +/-/underscores); only a non-
                // parseable text raises -> client_frame_length_error. A parseable
                // but invalid value (<=0, %16!=0, >1MiB) goes to client_control_block.
                bool ascii_ok = true;
                std::string length_text;
                length_text.reserve(length_plaintext.size());
                for (auto b : length_plaintext) {
                    if (b >= 0x80) { ascii_ok = false; break; }
                    length_text.push_back(static_cast<char>(b));
                }
                long parsed = 0;
                const bool decimal_ok = ascii_ok && parse_decimal(length_text, parsed);
                if (!ascii_ok || !decimal_ok) {
                    emu.log.write(std::format(
                        "client={} event=client_frame_length_error frame={} ciphertext_hex=\"{}\" "
                        "error=\"{}\"",
                        client_id, frame_counter, hex_bytes(length_frame),
                        !ascii_ok ? "non-ascii length" : "non-decimal length"));
                    expect_standalone_payload = true;
                    continue;
                }
                // matches Python: invalid if <=0, %16!=0, or >1MiB
                if (parsed <= 0 || parsed % kAesBlock != 0 ||
                    static_cast<std::size_t>(parsed) > kMaxPayloadCiphertext) {
                    emu.log.write(std::format(
                        "client={} event=client_control_block frame={} ciphertext_hex=\"{}\" "
                        "plaintext_ascii=\"{}\" parsed_decimal={}",
                        client_id, frame_counter, hex_bytes(length_frame),
                        ascii_bytes(length_plaintext), parsed));
                    expect_standalone_payload = true;
                    continue;
                }
                pending_payload_length = parsed;
                pending_set = true;
                emu.log.write(std::format(
                    "client={} event=client_frame_length frame={} ciphertext_hex=\"{}\" "
                    "plaintext_ascii=\"{}\" payload_ciphertext_bytes={}",
                    client_id, frame_counter, hex_bytes(length_frame),
                    ascii_bytes(length_plaintext), pending_payload_length));
            }

            if (buffer.size() < static_cast<std::size_t>(pending_payload_length)) break;
            const long payload_length = pending_payload_length;
            Bytes payload_frame(buffer.begin(), buffer.begin() + payload_length);
            buffer.erase(buffer.begin(), buffer.begin() + payload_length);
            pending_set = false;
            Bytes payload_plaintext;
            if (!aes_cbc_decrypt(emu.aes_alg.handle, sk.aes_key.data(), sk.aes_key.size(),
                                 sk.aes_iv.data(), payload_frame.data(), payload_frame.size(),
                                 payload_plaintext)) {
                emu.log.write(std::format(
                    "client={} event=client_frame_payload_error frame={} ciphertext_bytes={} "
                    "ciphertext_hex=\"{}\" error=\"aes decrypt failed\"",
                    client_id, frame_counter, payload_frame.size(), preview_hex(payload_frame)));
                return;  // tear down connection — preserved from Python
            }
            emu.log.write(std::format(
                "client={} event=client_frame_payload frame={} ciphertext_bytes={} plaintext_bytes={} "
                "plaintext_ascii=\"{}\" plaintext_hex=\"{}\"",
                client_id, frame_counter, payload_frame.size(), payload_plaintext.size(),
                preview_ascii(payload_plaintext), preview_hex(payload_plaintext)));
            // The framed (length-indicated) path does NOT dispatch in the reference
            // implementation — it only logs. The inner loop restarts to parse the
            // next 16-byte block. Do not add dispatch here; the standalone path
            // above is the only dispatch site, matching local_cloud_emulator.py.
        }

        Bytes data(kRecvChunk);
        const int n = ::recv(sock, reinterpret_cast<char*>(data.data()), static_cast<int>(kRecvChunk), 0);
        if (n <= 0) {
            std::string pp = pending_set ? std::to_string(pending_payload_length) : std::string("<none>");
            emu.log.write(std::format(
                "client={} event=close packets={} pending_payload_length={} buffered_bytes={}",
                client_id, packet_counter, pp, buffer.size()));
            return;
        }
        data.resize(static_cast<std::size_t>(n));
        ++packet_counter;
        log_packet(emu.log, client_id, packet_counter, data);
        buffer.insert(buffer.end(), data.begin(), data.end());
    }
}

void handle_client(SharedEmulator& emu, SOCKET sock, int client_id, sockaddr_in peer) {
    char ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
    emu.log.write(std::format("client={} event=open peer={}:{}", client_id, ip, ntohs(peer.sin_port)));
    int packet_counter = 0;
    try {
        Bytes first(kRecvChunk);
        int n = ::recv(sock, reinterpret_cast<char*>(first.data()), static_cast<int>(kRecvChunk), 0);
        if (n <= 0) {
            emu.log.write(std::format("client={} event=close packets=0", client_id));
            return;
        }
        first.resize(static_cast<std::size_t>(n));
        ++packet_counter;
        log_packet(emu.log, client_id, packet_counter, first);

        Bytes hello(kHello.begin(), kHello.end());
        if (first != hello) {
            emu.log.write(std::format(
                "client={} event=unexpected_first_packet expected=\"hello server\"", client_id));
            return;
        }

        const std::size_t total_sent = send_all(sock, emu.public_response.data(),
                                                 emu.public_response.size())
            ? emu.public_response.size() : 0;
        emu.log.write(std::format(
            "client={} event=send_public_key bytes={} rsa_bits={} public_format=spki "
            "response_b64_len={} response_suffix=5d",
            client_id, total_sent, emu.rsa_bits, emu.public_response.size() - 1));

        Bytes session_packet, remainder;
        if (!read_until_delimiter(sock, emu.log, client_id, packet_counter, Bytes{}, session_packet, remainder)) {
            emu.log.write(std::format("client={} event=error error=\"socket closed while waiting for delimiter\" packets={}",
                client_id, packet_counter));
            return;
        }
        emu.log.write(std::format(
            "client={} event=session_packet bytes={} b64_ascii=\"{}\" remainder_bytes={}",
            client_id, session_packet.size(), preview_ascii(session_packet), remainder.size()));

        SessionKeys sk;
        if (!decrypt_session_packet(emu.rsa_key.handle,
                std::string(session_packet.begin(), session_packet.end()), sk, emu.log, client_id))
            return;
        emu.log.write(std::format(
            "client={} event=session_decrypted plaintext_ascii=\"{}\" aes_key_len={} aes_key_hex=\"{}\" "
            "aes_iv_len={} aes_iv_hex=\"{}\"",
            client_id, ascii_bytes(sk.plaintext), sk.aes_key.size(), hex_bytes(sk.aes_key),
            sk.aes_iv.size(), hex_bytes(sk.aes_iv)));

        if (!remainder.empty()) {
            emu.log.write(std::format(
                "client={} event=remainder_after_session bytes={} hex=\"{}\" ascii=\"{}\"",
                client_id, remainder.size(), preview_hex(remainder), preview_ascii(remainder)));
        }

        send_server_frame(sock, emu, client_id, sk, emu.login_response, "login", "bytes");

        read_client_frames(emu, sock, client_id, packet_counter, sk, std::move(remainder));
    } catch (const std::exception& exc) {
        emu.log.write(std::format("client={} event=error error=\"{}\" packets={}",
            client_id, exc.what(), packet_counter));
    }
}

struct ClientThreadArg {
    SharedEmulator* emu;
    SOCKET sock;
    int client_id;
    sockaddr_in peer;
};

// SEH crash-log helpers kept out of the __try/__except functions themselves so
// the thread procs hold no C++ objects requiring stack unwinding (C2712). The
// helpers own the std::string temporaries; the thread procs pass only POD.
static void log_client_thread_crash(EmulatorLog& log, int client_id, DWORD code) {
    log.write(std::format("client={} event=client_thread_seh_crash code=0x{:08x}",
        client_id, static_cast<unsigned long>(code)));
}
static void log_listener_thread_crash(EmulatorLog& log, DWORD code) {
    log.write(std::format("event=listener_thread_seh_crash code=0x{:08x}",
        static_cast<unsigned long>(code)));
}

DWORD WINAPI client_thread(LPVOID param) {
    // Crash containment: handle_client may throw C++ exceptions (caught by its
    // own try/catch) but a structured exception (access violation) under /EHsc
    // would otherwise terminate steam.exe. This thread proc holds only POD
    // locals, so SEH __try/__except is legal here and confines any emulator
    // crash to this one client connection — the carve path and the listener
    // stay up regardless.
    auto* arg = static_cast<ClientThreadArg*>(param);
    SharedEmulator* emu = arg->emu;
    const SOCKET sock = arg->sock;
    const int client_id = arg->client_id;
    const sockaddr_in peer = arg->peer;
    delete arg;
    __try {
        handle_client(*emu, sock, client_id, peer);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_client_thread_crash(emu->log, client_id, GetExceptionCode());
    }
    closesocket(sock);
    return 0;
}

// The accept loop body lives in its own function so listener_thread itself
// holds no C++ objects with destructors (C2712 forbids __try in functions that
// require unwinding). All std::string temporaries stay here.
static void listener_loop(SharedEmulator& emu) {
    for (;;) {
        if (emu.stop_flag.load(std::memory_order_acquire)) break;
        sockaddr_in peer{};
        int peerlen = sizeof(peer);
        const SOCKET client = ::accept(emu.listener_socket, reinterpret_cast<sockaddr*>(&peer), &peerlen);
        if (client == INVALID_SOCKET) {
            if (emu.stop_flag.load(std::memory_order_acquire)) break;
            // transient accept error — log and keep going
            emu.log.write(std::format("event=accept_error errno={}", WSAGetLastError()));
            continue;
        }
        const int client_id = emu.next_client_id.fetch_add(1);
        auto* arg = new ClientThreadArg{ &emu, client, client_id, peer };
        const HANDLE th = CreateThread(nullptr, 0, &client_thread, arg, 0, nullptr);
        if (th) CloseHandle(th);  // detached — dies with the process
        else { closesocket(client); delete arg; }
    }
}

DWORD WINAPI listener_thread(LPVOID param) {
    auto* emu = static_cast<SharedEmulator*>(param);
    __try {
        listener_loop(*emu);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_listener_thread_crash(emu->log, GetExceptionCode());
    }
    return 0;
}

bool load_or_generate_key(SharedEmulator& emu) {
    emuder::RSAPublicComponents pub;
    // Mirror Python load_or_generate_key: if the PEM file is present, attempt
    // to load it; a malformed/unreadable file aborts startup (Python's
    // load_pem_private_key raises and the process exits). Do NOT silently
    // regenerate over a corrupt key — that would diverge from the reference
    // and could mask a damaged state file.
    std::error_code ec;
    if (!emu.config.key_path.empty() && std::filesystem::exists(emu.config.key_path, ec)) {
        std::ifstream in(emu.config.key_path, std::ios::binary);
        if (!in) {
            emu.log.write(std::format("event=key_load_failed path=\"{}\" reason=\"open failed\"",
                emu.config.key_path.string()));
            return false;
        }
        std::string pem((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        Bytes der;
        if (!emuder::pem_unarmor(pem, der) || der.empty()) {
            emu.log.write(std::format("event=key_load_failed path=\"{}\" reason=\"pem unarmor failed\"",
                emu.config.key_path.string()));
            return false;
        }
        emuder::RSAPrivateComponents priv;
        if (!emuder::parse_pkcs8_private_der(der, priv)) {
            emu.log.write(std::format("event=key_load_failed path=\"{}\" reason=\"pkcs8 parse failed\"",
                emu.config.key_path.string()));
            return false;
        }
        if (!rsa_import_full_private(emu.rsa_alg.handle, priv, emu.rsa_key)) {
            emu.log.write(std::format("event=key_load_failed path=\"{}\" reason=\"cng import failed\"",
                emu.config.key_path.string()));
            return false;
        }
        pub.exponent_be = priv.exponent_be;
        pub.modulus_be = priv.modulus_be;
        emu.rsa_bits = static_cast<int>(pub.modulus_be.size() * 8);
        emu.public_response = public_key_response(pub);
        emu.log.write(std::format("event=key_loaded path=\"{}\" bits={}",
            emu.config.key_path.string(), emu.rsa_bits));
        return true;
    }

    // No existing key file — generate a fresh RSA-1024 key, e=65537.
    if (!rsa_generate_keypair(emu.rsa_alg.handle, emu.rsa_key, pub)) {
        emu.log.write("event=key_generate_failed");
        return false;
    }
    emu.rsa_bits = 1024;
    emu.log.write(std::format("event=key_generated bits={}", emu.rsa_bits));

    if (!emu.config.key_path.empty()) {
        std::error_code ec2;
        std::filesystem::create_directories(emu.config.key_path.parent_path(), ec2);
        emuder::RSAPrivateComponents priv;
        if (rsa_export_full_private(emu.rsa_key.handle, priv)) {
            const Bytes der = emuder::build_pkcs8_private_der(priv);
            const std::string pem = emuder::pem_armor_private_key(der);
            std::ofstream out(emu.config.key_path, std::ios::binary | std::ios::trunc);
            if (out) { out << pem; out.flush(); }
            emu.log.write(std::format("event=key_saved path=\"{}\"", emu.config.key_path.string()));
        }
    }
    emu.public_response = public_key_response(pub);
    return true;
}

} // namespace

bool emulator_start(const EmulatorConfig& cfg) {
    SharedEmulator& emu = g_emu;
    std::lock_guard<std::mutex> lk(emu.start_mutex);
    if (emu.running.load(std::memory_order_acquire)) return true;  // idempotent start-once

    emu.config = cfg;
    emu.log.open(cfg.log_path);

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        emu.log.write(std::format("event=wsastartup_failed errno={}", WSAGetLastError()));
        return false;
    }

    if (!emu.rsa_alg.open_rsa()) { emu.log.write("event=rsa_alg_open_failed"); WSACleanup(); return false; }
    if (!emu.aes_alg.open_aes()) { emu.log.write("event=aes_alg_open_failed"); emu.rsa_alg.close(); WSACleanup(); return false; }

    if (!load_or_generate_key(emu)) {
        // Equivalent to the former "skip" path: log and fall back silently.
        emu.aes_alg.close();
        emu.rsa_alg.close();
        WSACleanup();
        return false;
    }

    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        emu.log.write(std::format("event=listener_socket_failed errno={}", WSAGetLastError()));
        emu.rsa_key.destroy(); emu.aes_alg.close(); emu.rsa_alg.close(); WSACleanup();
        return false;
    }
    BOOL reuse = TRUE;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(kListenPort);
    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        emu.log.write(std::format("event=listener_bind_failed errno={} port={}", WSAGetLastError(), kListenPort));
        closesocket(listener);
        emu.rsa_key.destroy(); emu.aes_alg.close(); emu.rsa_alg.close(); WSACleanup();
        return false;  // 5444 in use — do not crash, keep carve behavior intact
    }
    if (listen(listener, SOMAXCONN) == SOCKET_ERROR) {
        emu.log.write(std::format("event=listener_listen_failed errno={}", WSAGetLastError()));
        closesocket(listener);
        emu.rsa_key.destroy(); emu.aes_alg.close(); emu.rsa_alg.close(); WSACleanup();
        return false;
    }

    emu.listener_socket = listener;
    emu.stop_flag.store(false, std::memory_order_release);
    const HANDLE th = CreateThread(nullptr, 0, &listener_thread, &emu, 0, nullptr);
    if (!th) {
        emu.log.write(std::format("event=listener_thread_failed errno={}", GetLastError()));
        closesocket(listener); emu.listener_socket = INVALID_SOCKET;
        emu.rsa_key.destroy(); emu.aes_alg.close(); emu.rsa_alg.close(); WSACleanup();
        return false;
    }
    CloseHandle(th);  // detached listener

    emu.running.store(true, std::memory_order_release);
    emu.log.write(std::format(
        "event=start listen=127.0.0.1:{} log=\"{}\" rsa_bits={} public_format=spki "
        "public_response_bytes={} login_response_ascii=\"{}\" config_dir=\"{}\" config_extension=\"{}\"",
        kListenPort, emu.config.log_path.empty() ? std::string("<disabled>") : emu.config.log_path.string(),
        emu.rsa_bits, emu.public_response.size(), ascii_bytes(emu.login_response),
        emu.config.config_dir.string(), emu.config_extension));
    return true;
}

void emulator_stop() {
    SharedEmulator& emu = g_emu;
    if (!emu.running.load(std::memory_order_acquire)) return;
    emu.stop_flag.store(true, std::memory_order_release);
    if (emu.listener_socket != INVALID_SOCKET) {
        closesocket(emu.listener_socket);  // unblocks accept(); no client-thread joins
        emu.listener_socket = INVALID_SOCKET;
    }
    emu.running.store(false, std::memory_order_release);
    // CNG handles and any in-flight client threads are reclaimed at process
    // exit — matching the old job-object lifetime without a child process.
}
