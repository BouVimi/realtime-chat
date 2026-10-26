#include "validators/AuthValidators.h"
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace chat;
using namespace chat::validation;
namespace {
void require(bool value) { if (!value) throw std::runtime_error("assertion failed"); }
bool has(const ValidationResult &r, const std::string &code) {
    for (const auto &error : r.errors) if (error.code == code) return true;
    return false;
}
std::string repeat(const std::string &s, int count) {
    std::string result;
    while (count-- > 0) result += s;
    return result;
}
ValidationResult password(const std::string &p) {
    return validatePassword(p, "mounir", "contact@example.com");
}
template<class T> concept HasPasswordHash = requires(T value) { value.passwordHash; };
template<class T> concept HasSnakePasswordHash = requires(T value) { value.password_hash; };
template<class T> concept HasTokenHash = requires(T value) { value.tokenHash; };
static_assert(!HasPasswordHash<dto::UserResponse>);
static_assert(!HasSnakePasswordHash<dto::UserResponse>);
static_assert(!HasTokenHash<dto::UserResponse>);
}
int main() {
    using Case = std::pair<std::string, std::function<void()>>;
    const std::vector<Case> cases = {
        {"email: normalize", [] {
            auto r = validateEmail(" \tAlice+Tag@EXAMPLE.COM\r\n");
            require(r.valid && r.errors.empty() && r.normalized == "alice+tag@example.com");
        }},
        {"email: apostrophe is valid data", [] { require(validateEmail("o'hara@example.com").valid); }},
        {"email: empty", [] { require(has(validateEmail(""), "EMAIL_REQUIRED")); }},
        {"email: blank", [] { require(has(validateEmail(" \t\r\n"), "EMAIL_REQUIRED")); }},
        {"email: 254 boundary", [] {
            const auto e = std::string(64, 'a') + "@" + std::string(63, 'b') + "." + std::string(63, 'c') + "." + std::string(61, 'd');
            require(e.size() == 254 && validateEmail(e).valid);
        }},
        {"email: 255 boundary", [] {
            const auto e = std::string(64, 'a') + "@" + std::string(63, 'b') + "." + std::string(63, 'c') + "." + std::string(62, 'd');
            require(has(validateEmail(e), "EMAIL_TOO_LONG"));
        }},
        {"email: malformed cases", [] {
            for (auto e : {"alice", "@example.com", "a@", "a@@example.com", "a@example", ".a@example.com",
                "a.@example.com", "a..b@example.com", "a@-example.com", "a@example-.com", "a@a..com", "a@example.com.",
                "a b@example.com", "a@exa_mple.com", "a@ex ample.com"}) require(!validateEmail(e).valid);
        }},
        {"email: local and label length", [] {
            require(!validateEmail(std::string(65, 'a') + "@example.com").valid);
            require(!validateEmail("a@" + std::string(64, 'a') + ".com").valid);
        }},
        {"email: Unicode and malformed UTF-8", [] {
            require(!validateEmail("caf\xc3\xa9@example.com").valid);
            require(!validateEmail("alice@\xe4\xbe\x8b.com").valid);
            require(!validateEmail(std::string("a\xff@example.com")).valid);
            require(validateEmail("a@xn--bcher-kva.de").valid);
        }},
        {"email: attacks", [] {
            for (auto e : {"x' OR '1'='1@example.com", "<script>@example.com", "a@example.com\r\nBcc: x@y.com", "a@example.com; DROP TABLE users;"})
                require(!validateEmail(e).valid);
            require(!validateEmail(std::string("a\0b@example.com", 15)).valid);
        }},
        {"username: valid", [] {
            for (auto n : {"abc", "Alice_1", "user-name", "_ab", "-ab"}) require(validateUsername(n).valid);
            require(validateUsername("Alice_1").normalized == "Alice_1");
        }},
        {"username: length boundaries", [] {
            require(!validateUsername("").valid);
            require(!validateUsername("ab").valid);
            require(validateUsername("abc").valid);
            require(validateUsername(std::string(32, 'a')).valid);
            require(!validateUsername(std::string(33, 'a')).valid);
        }},
        {"username: first digit", [] { require(has(validateUsername("1abc"), "USERNAME_START")); }},
        {"username: Unicode", [] {
            require(!validateUsername("caf\xc3\xa9").valid);
            require(!validateUsername("\xe4\xbe\x8b\xe4\xbe\x8b\xe4\xbe\x8b").valid);
            require(!validateUsername(std::string("ab\xff")).valid);
        }},
        {"username: attacks and whitespace", [] {
            for (auto n : {"abc ", " abc", "a b", "a\tb", "a\nb", "../admin", "a' OR 1=1--", "<script>", "a;DROP TABLE users;"})
                require(!validateUsername(n).valid);
            require(!validateUsername(std::string("ab\0c", 4)).valid);
        }},
        {"password: valid ASCII", [] {
            auto r = password("Cobalt7!Sunrise");
            require(r.valid && r.errors.empty() && r.normalized.empty());
        }},
        {"password: length boundaries", [] {
            require(!password("").valid);
            require(has(password("Abcdefg12"), "PASSWORD_LENGTH"));
            require(password("Abcdefgh12").valid);
            require(password("A1" + std::string(126, 'x')).valid);
            require(has(password("A1" + std::string(127, 'x')), "PASSWORD_LENGTH"));
            require(!password(std::string(10000, 'a')).valid);
        }},
        {"password: Unicode code point boundaries", [] {
            require(password("Abcdefg1\xc3\xa9\xc3\xa9").valid);
            require(!password("Abcdef1\xc3\xa9\xc3\xa9").valid);
            require(password("A1" + repeat("\xf0\x9f\x94\x92", 126)).valid);
            require(has(password("A1" + repeat("\xf0\x9f\x94\x92", 127)), "PASSWORD_LENGTH"));
        }},
        {"password: complexity", [] {
            require(has(password("abcdefghijk"), "PASSWORD_COMPLEXITY"));
            require(has(password("135792468013"), "PASSWORD_COMPLEXITY"));
            require(has(password(repeat("\xc3\xa9", 10) + "1"), "PASSWORD_COMPLEXITY"));
            require(!password("          ").valid);
        }},
        {"password: common denylist", [] {
            for (auto p : {"Password123", "PASSWORD1234", "qwerty12345", "Welcome123", "iloveyou123"})
                require(has(password(p), "PASSWORD_COMMON"));
        }},
        {"password: identity substrings", [] {
            require(has(validatePassword("xxMOUNIR77xx", "mounir", "contact@example.com"), "PASSWORD_CONTAINS_USERNAME"));
            require(has(validatePassword("XXCONTACT77xx", "mounir", " Contact@Example.com "), "PASSWORD_CONTAINS_EMAIL"));
            require(has(validatePassword("Long8password", "xyz", "p@example.com"), "PASSWORD_CONTAINS_EMAIL"));
        }},
        {"password: invalid UTF-8", [] {
            for (auto suffix : {std::string("\xc0\xaf"), std::string("\xed\xa0\x80"), std::string("\xf4\x90\x80\x80"),
                 std::string("\xe2\x82"), std::string("\x80"), std::string("\xff")})
                require(has(password("ValidBase123" + suffix), "PASSWORD_ENCODING"));
        }},
        {"password: NUL and controls", [] {
            require(!password(std::string("Valid\0Pass123", 13)).valid);
            require(!password("ValidPass123\n").valid);
            require(!password("ValidPass123\xc2\x85").valid);
        }},
        {"password: SQL-looking strings remain data", [] {
            require(password("abc' OR 1=1--").valid);
            require(password("<script>abc123</script>").valid);
            require(password("  Strong7 Phrase  ").valid);
        }},
        {"structured field errors", [] {
            auto result = validateUsername("1$");
            require(!result.valid && result.normalized.empty() && result.errors.size() == 3);
            for (const auto &e : result.errors) require(e.field == "username" && !e.code.empty() && !e.message.empty());
            auto response = toErrorResponse(result);
            require(response.error.code == "VALIDATION_ERROR" && response.error.fields.size() == 3);
        }},
        {"safe response projection", [] {
            User user; user.id = 7; user.username = "Alice"; user.passwordHash = "secret-hash";
            auto response = dto::toUserResponse(user);
            require(response.id == 7 && response.username == "Alice");
        }}
    };
    int failed = 0;
    for (const auto &[name, test] : cases) {
        try { test(); std::cout << "PASS " << name << '\n'; }
        catch (const std::exception &e) { ++failed; std::cerr << "FAIL " << name << ": " << e.what() << '\n'; }
    }
    std::cout << cases.size() - failed << '/' << cases.size() << " cases passed\n";
    return failed ? 1 : 0;
}
