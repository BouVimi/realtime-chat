#include "utils/AuthCrypto.h"
#include <sodium.h>
#include <array>
#include <stdexcept>
namespace chat::auth {
void initializeCrypto() {
    static const int initialized = sodium_init();
    if (initialized < 0) throw std::runtime_error("Crypto initialization failed");
}
Token generateToken() {
    initializeCrypto();
    std::array<unsigned char, 32> bytes{};
    randombytes_buf(bytes.data(), bytes.size());
    std::array<char, 44> text{}; // 43 characters and NUL, URL-safe and unpadded.
    sodium_bin2base64(text.data(), text.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    Token result;
    result.encoded = text.data();
    crypto_hash_sha256(result.hash.data(), bytes.data(), bytes.size());
    sodium_memzero(bytes.data(), bytes.size());
    return result;
}
std::optional<TokenHash> hashToken(std::string_view encoded) {
    initializeCrypto();
    if (encoded.size() != 43) return std::nullopt;
    for (unsigned char c : encoded)
        if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '-' && c != '_')
            return std::nullopt;
    std::array<unsigned char, 32> bytes{};
    std::size_t length = 0;
    const char *end = nullptr;
    if (sodium_base642bin(bytes.data(), bytes.size(), encoded.data(), encoded.size(), nullptr,
                         &length, &end, sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0 ||
        length != bytes.size() || end != encoded.data() + encoded.size()) {
        sodium_memzero(bytes.data(), bytes.size());
        return std::nullopt;
    }
    std::array<char, 44> canonical{};
    sodium_bin2base64(canonical.data(), canonical.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (encoded != canonical.data()) { sodium_memzero(bytes.data(), bytes.size()); return std::nullopt; }
    TokenHash hash{};
    crypto_hash_sha256(hash.data(), bytes.data(), bytes.size());
    sodium_memzero(bytes.data(), bytes.size());
    return hash;
}
std::string hashPassword(std::string_view password) {
    initializeCrypto();
    if (password.size() > 512) throw std::runtime_error("Password input too large");
    std::array<char, crypto_pwhash_STRBYTES> output{};
    if (crypto_pwhash_str(output.data(), password.data(), password.size(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
        throw std::runtime_error("Password hashing failed");
    std::string result(output.data());
    sodium_memzero(output.data(), output.size());
    if (!result.starts_with("$argon2id$")) throw std::runtime_error("Argon2id is required");
    return result;
}
bool verifyPassword(std::string_view password, const std::string &hash) {
    initializeCrypto();
    if (password.size() > 512 || hash.size() >= crypto_pwhash_STRBYTES || hash.find('\0') != std::string::npos) return false;
    return crypto_pwhash_str_verify(hash.c_str(), password.data(), password.size()) == 0;
}
bool needsRehash(const std::string &hash) {
    initializeCrypto();
    return crypto_pwhash_str_needs_rehash(hash.c_str(), crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                        crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0;
}
}
