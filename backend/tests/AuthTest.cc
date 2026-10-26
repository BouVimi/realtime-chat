#include "utils/AuthCrypto.h"
#include "services/AuthPolicy.h"
#include "config/AuthConfig.h"
#include "services/AuthService.h"
#include <trantor/net/EventLoopThread.h>
#include <future>
#include <sodium.h>
#include <cstdlib>
#include <iostream>
#include <set>
#include <stdexcept>
using namespace chat;
using namespace chat::auth;
namespace {
void check(bool condition, const char *message) { if (!condition) throw std::runtime_error(message); }
}
int main() {
    try {
        initializeCrypto();
        std::set<std::string> generated;
        for (int i = 0; i < 128; ++i) {
            auto token = generateToken();
            check(token.encoded.size() == 43, "token size");
            check(token.encoded.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == std::string::npos, "base64url alphabet");
            auto digest = hashToken(token.encoded);
            check(digest && *digest == token.hash, "token hash round trip");
            generated.insert(token.encoded);
        }
        check(generated.size() == 128, "token uniqueness sample");
        auto zero = hashToken(std::string(43, 'A'));
        unsigned char bytes[32]{};
        TokenHash known{};
        crypto_hash_sha256(known.data(), bytes, sizeof bytes);
        check(zero && *zero == known, "hash raw decoded token, including zero bytes");
        check(!hashToken("") && !hashToken(std::string(42, 'A')) && !hashToken(std::string(44, 'A')), "bad token lengths");
        check(!hashToken(std::string(42, 'A') + "=") && !hashToken(std::string(42, 'A') + "+"), "reject padding and alternate alphabet");
        check(!hashToken(std::string(42, 'A') + "B"), "reject noncanonical trailing bits");
        check(!hashToken(std::string(42, 'A') + "\n"), "reject whitespace");
        const std::string password = "Cobalt7!Sunrise";
        auto hash1 = hashPassword(password), hash2 = hashPassword(password);
        check(hash1.starts_with("$argon2id$") && hash1 != hash2, "Argon2id and random salts");
        check(verifyPassword(password, hash1) && !verifyPassword("Wrong7!Sunrise", hash1), "password verification");
        check(!needsRehash(hash1), "current hash parameters");
        char oldHash[crypto_pwhash_STRBYTES]{};
        check(crypto_pwhash_str(oldHash, password.data(), password.size(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE + 1, crypto_pwhash_MEMLIMIT_INTERACTIVE) == 0, "create old policy hash");
        check(needsRehash(oldHash) && verifyPassword(password, oldHash), "rehash detection");
        check(!verifyPassword(std::string(513, 'a'), hash1), "oversized password bound");
        auto dummy = hashPassword(generateToken().encoded);
        check(!verifyPassword(password, dummy), "dummy hash executes real password verification");

        Timestamp now{std::chrono::seconds(1000000)};
        std::optional<User> user{User{}};
        check(decideLogin(std::nullopt, false, now) == LoginDecision::Deny, "unknown user denied");
        check(decideLogin(user, false, now) == LoginDecision::RecordFailure, "wrong password records failure");
        check(decideLogin(user, true, now) == LoginDecision::Allow, "correct password allowed");
        for (int attempt = 1; attempt <= 5; ++attempt) {
            auto state = nextFailure(*user, now);
            check(state.count == attempt && state.lockedUntil.has_value() == (attempt == 5), "five attempt threshold");
            user->failedLoginCount = state.count;
            user->lockedUntil = state.lockedUntil;
        }
        check(*user->lockedUntil == now + std::chrono::minutes(15), "15 minute duration");
        check(decideLogin(user, true, now) == LoginDecision::Deny && decideLogin(user, false, now) == LoginDecision::Deny, "locked user always denied");
        const auto unlockedAt = *user->lockedUntil;
        check(decideLogin(user, true, unlockedAt) == LoginDecision::Allow, "lock boundary is inclusive expiry");
        auto restarted = nextFailure(*user, unlockedAt);
        check(restarted.count == 1 && !restarted.lockedUntil, "expired lock starts a fresh failure window");
        check(registrationErrors("ALICE@example.com", "Alice", "xxALICE123xx").size() >= 1, "registration rejects identity substring");
        check(registrationErrors("med@example.com", "Mounir", "Cobalt7!Sunrise").empty(), "registration valid");
        check(!registrationErrors("bad", "1?", "short").empty(), "registration gathers field errors");

        unsetenv("SESSION_TTL_HOURS"); unsetenv("COOKIE_SECURE"); unsetenv("ALLOWED_ORIGINS");
        auto defaults = loadAuthConfig();
        check(defaults.sessionTtlHours == 168 && defaults.cookieSecure && defaults.maxAgeSeconds() == 604800, "secure config defaults");
        setenv("SESSION_TTL_HOURS", "24", 1); setenv("COOKIE_SECURE", "false", 1);
        setenv("ALLOWED_ORIGINS", "https://chat.example,http://localhost:5173", 1);
        auto config = loadAuthConfig();
        check(config.maxAgeSeconds() == 86400 && !config.cookieSecure, "config overrides");
        check(isOriginAllowed(config, "https://chat.example") && !isOriginAllowed(config, "https://chat.example.evil"), "exact Origin matching");
        for (const char *bad : {"0", "-1", "8761", "abc", "1x", ""}) {
            setenv("SESSION_TTL_HOURS", bad, 1);
            bool rejected = false; try { loadAuthConfig(); } catch (...) { rejected = true; }
            check(rejected, "invalid TTL rejected");
        }
        setenv("SESSION_TTL_HOURS", "168", 1);
        setenv("COOKIE_SECURE", "maybe", 1);
        bool rejected = false; try { loadAuthConfig(); } catch (...) { rejected = true; }
        check(rejected, "invalid cookie flag rejected");
        setenv("COOKIE_SECURE", "true", 1);
        for (const char *bad : {"*", "null", "https://chat.example/", "https://user@chat.example", "https://chat.example,", ""}) {
            setenv("ALLOWED_ORIGINS", bad, 1);
            rejected = false; try { loadAuthConfig(); } catch (...) { rejected = true; }
            check(rejected, "unsafe allowed origin rejected");
        }
        // Exercise actual service paths that do not require a database, plus worker resumption.
        trantor::EventLoopThread thread("auth-unit-loop");
        thread.run();
        AuthService service{AuthConfig{}};
        CryptoExecutor executor;
        std::promise<void> completion;
        auto future = completion.get_future();
        thread.getLoop()->queueInLoop([&] {
            drogon::async_run([&]() -> drogon::Task<void> {
                try {
                    auto invalid = co_await service.registerUser("bad", "1?", "short");
                    check(std::holds_alternative<InvalidInput>(invalid), "typed registration validation");
                    check(!std::get<InvalidInput>(invalid).fields.empty(), "registration field errors");
                    check(!(co_await service.validateSession("malformed")), "invalid session bypasses database");
                    check(!(co_await service.logout("malformed")), "invalid logout bypasses database");
                    auto work = co_await executor.run([] { return CryptoResult{true, hashPassword("Cobalt7!Sunrise")}; });
                    check(work.verified && verifyPassword("Cobalt7!Sunrise", work.hash), "crypto worker await/resume");
                    completion.set_value();
                } catch (...) { completion.set_exception(std::current_exception()); }
                co_return;
            });
        });
        future.get();
        thread.getLoop()->quit();
        thread.wait();
        std::cout << "PASS tokens, Argon2id/rehash, auth policy/config, service validation and crypto worker\n";
        return 0;
    } catch (const std::exception &e) {
        // Assertion messages are fixed literals and contain no secrets.
        std::cerr << "FAIL " << e.what() << '\n'; return 1;
    }
}
