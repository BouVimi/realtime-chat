#include "validators/AuthValidators.h"
#include <algorithm>
#include <array>
#include <cstdint>

namespace chat::validation {
namespace {
bool letter(unsigned char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
bool digit(unsigned char c) { return c >= '0' && c <= '9'; }
bool space(unsigned char c) { return c == ' ' || (c >= '\t' && c <= '\r'); }
std::string_view trim(std::string_view s) {
    while (!s.empty() && space(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && space(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return s;
}
std::string lower(std::string_view s) {
    std::string out(s);
    for (char &c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return out;
}
void fail(ValidationResult &r, const char *field, const char *code, const char *message) {
    r.valid = false;
    r.errors.push_back({field, code, message});
}
// Strict UTF-8 decoding: rejects overlong forms, surrogates and > U+10FFFF.
std::optional<std::size_t> utf8Length(std::string_view s) {
    std::size_t count = 0;
    for (std::size_t i = 0; i < s.size(); ++count) {
        const auto first = static_cast<unsigned char>(s[i++]);
        std::uint32_t cp = first;
        unsigned rest = 0;
        std::uint32_t minimum = 0;
        if (first <= 0x7f) {}
        else if (first >= 0xc2 && first <= 0xdf) { cp = first & 0x1f; rest = 1; minimum = 0x80; }
        else if (first >= 0xe0 && first <= 0xef) { cp = first & 0x0f; rest = 2; minimum = 0x800; }
        else if (first >= 0xf0 && first <= 0xf4) { cp = first & 0x07; rest = 3; minimum = 0x10000; }
        else return std::nullopt;
        if (rest > s.size() - i) return std::nullopt;
        while (rest--) {
            auto c = static_cast<unsigned char>(s[i++]);
            if ((c & 0xc0) != 0x80) return std::nullopt;
            cp = (cp << 6) | (c & 0x3f);
        }
        if (cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return std::nullopt;
        if (cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f)) return std::nullopt;
    }
    return count;
}
bool emailShape(std::string_view s) {
    const auto at = s.find('@');
    if (at == std::string_view::npos || at == 0 || at > 64 || at + 1 >= s.size() ||
        s.find('@', at + 1) != std::string_view::npos) return false;
    const auto local = s.substr(0, at);
    if (local.front() == '.' || local.back() == '.' || local.find("..") != std::string_view::npos) return false;
    constexpr std::string_view specials = "!#$%&'*+-/=?^_`{|}~.";
    for (unsigned char c : local)
        if (!letter(c) && !digit(c) && specials.find(static_cast<char>(c)) == std::string_view::npos) return false;
    const auto domain = s.substr(at + 1);
    if (domain.find('.') == std::string_view::npos) return false;
    std::size_t start = 0;
    while (start < domain.size()) {
        auto end = domain.find('.', start);
        if (end == std::string_view::npos) end = domain.size();
        auto label = domain.substr(start, end - start);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return false;
        for (unsigned char c : label) if (!letter(c) && !digit(c) && c != '-') return false;
        if (end == domain.size()) return true;
        start = end + 1;
    }
    return false;
}
}

ValidationResult validateEmail(std::string_view input) {
    ValidationResult r;
    input = trim(input);
    if (input.empty()) fail(r, "email", "EMAIL_REQUIRED", "Email is required");
    else if (input.size() > 254) fail(r, "email", "EMAIL_TOO_LONG", "Email must be at most 254 characters");
    else if (!emailShape(input)) fail(r, "email", "EMAIL_INVALID", "Use a valid ASCII email address");
    if (r.valid) r.normalized = lower(input);
    return r;
}

ValidationResult validateUsername(std::string_view input) {
    ValidationResult r;
    if (input.size() < 3 || input.size() > 32)
        fail(r, "username", "USERNAME_LENGTH", "Username must be 3 to 32 ASCII characters");
    bool allowed = true;
    for (unsigned char c : input) if (!letter(c) && !digit(c) && c != '_' && c != '-') allowed = false;
    if (!allowed) fail(r, "username", "USERNAME_CHARACTERS", "Use ASCII letters, digits, underscore or hyphen");
    if (!input.empty() && digit(static_cast<unsigned char>(input.front())))
        fail(r, "username", "USERNAME_START", "Username must not start with a digit");
    if (r.valid) r.normalized = std::string(input);
    return r;
}

ValidationResult validatePassword(std::string_view password, std::string_view username, std::string_view email) {
    ValidationResult r;
    // At most four bytes per Unicode code point; bound all subsequent work.
    if (password.size() > 512) {
        fail(r, "password", "PASSWORD_LENGTH", "Password must be 10 to 128 Unicode characters");
        return r;
    }
    const auto count = utf8Length(password);
    if (!count) {
        fail(r, "password", "PASSWORD_ENCODING", "Use valid UTF-8 without control characters");
        return r;
    }
    if (*count < 10 || *count > 128)
        fail(r, "password", "PASSWORD_LENGTH", "Password must be 10 to 128 Unicode characters");
    bool hasLetter = false, hasDigit = false;
    for (unsigned char c : password) { hasLetter = hasLetter || letter(c); hasDigit = hasDigit || digit(c); }
    if (!hasLetter || !hasDigit)
        fail(r, "password", "PASSWORD_COMPLEXITY", "Include at least one ASCII letter and one digit");
    const auto folded = lower(password);
    constexpr std::array common = {"password1", "password12", "password123", "password1234",
        "password12345", "1234567890", "qwerty12345", "qwerty123456", "welcome123", "welcome1234",
        "letmein123", "letmein1234", "abc123456789", "iloveyou123", "admin12345"};
    if (std::find(common.begin(), common.end(), folded) != common.end())
        fail(r, "password", "PASSWORD_COMMON", "Choose a less common password");
    const auto name = lower(username);
    if (!name.empty() && folded.find(name) != std::string::npos)
        fail(r, "password", "PASSWORD_CONTAINS_USERNAME", "Password must not contain your username");
    const auto address = lower(trim(email));
    const auto at = address.find('@');
    if (at != std::string::npos && at != 0 && folded.find(address.substr(0, at)) != std::string::npos)
        fail(r, "password", "PASSWORD_CONTAINS_EMAIL", "Password must not contain your email local part");
    return r; // Never normalize or return a password.
}

dto::ValidationErrorResponse toErrorResponse(const ValidationResult &result) {
    return {{"VALIDATION_ERROR", "Invalid input", result.errors}};
}
}
