#include "config/Config.h"
#include "dto/AuthDto.h"
#include "repositories/UserRepository.h"
#include "repositories/SessionRepository.h"
#include <drogon/drogon.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>
#include <variant>

namespace {
using namespace chat;
void require(bool condition, const char *message) {
    if (!condition) throw std::runtime_error(message);
}
Timestamp now() {
    return std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::system_clock::now());
}
TokenHash hash(unsigned char first) {
    TokenHash value{};
    for (std::size_t i = 0; i < value.size(); ++i) value[i] = static_cast<unsigned char>(i * 7);
    value[0] = first; // Test digest bytes include zero and high-bit values.
    return value;
}
drogon::Task<void> checkRepositories(drogon::orm::DbClientPtr tx) {
    UserRepository users(tx);
    SessionRepository sessions(tx);
    auto result = co_await users.createUser("repo-test@example.invalid", "Repo_Test", "$argon2id$test-placeholder");
    require(std::holds_alternative<User>(result), "createUser");
    auto user = std::get<User>(result);
    require(user.id > 0 && user.failedLoginCount == 0 && !user.lockedUntil, "user defaults");
    require(user.passwordHash == "$argon2id$test-placeholder", "internal password hash mapping");
    require(dto::toUserResponse(user).username == "Repo_Test", "safe DTO projection");
    auto byId = co_await users.findById(user.id);
    require(byId && byId->id == user.id, "findById");
    auto byEmail = co_await users.findByEmail("REPO-TEST@EXAMPLE.INVALID");
    require(byEmail && byEmail->id == user.id, "case-insensitive email lookup");
    auto byName = co_await users.findByUsername("rEpO_tEsT");
    require(byName && byName->id == user.id, "case-insensitive username lookup");
    require(!(co_await users.findById(-1)), "missing user");
    require(!(co_await users.findByEmail("' OR 1=1--")), "email SQL injection");
    require(!(co_await users.findByUsername("' OR 1=1--")), "username SQL injection");

    auto duplicateEmail = co_await users.createUser("REPO-TEST@example.invalid", "Other_Name", "hash");
    require(std::holds_alternative<CreateUserError>(duplicateEmail) &&
        std::get<CreateUserError>(duplicateEmail) == CreateUserError::EmailTaken, "EmailTaken result");
    auto duplicateUsername = co_await users.createUser("other@example.invalid", "repo_test", "hash");
    require(std::holds_alternative<CreateUserError>(duplicateUsername) &&
        std::get<CreateUserError>(duplicateUsername) == CreateUserError::UsernameTaken, "UsernameTaken result");
    auto both = co_await users.createUser("REPO-TEST@example.invalid", "REPO_TEST", "hash");
    require(std::holds_alternative<CreateUserError>(both) &&
        std::get<CreateUserError>(both) == CreateUserError::EmailTaken, "email wins when both conflict");

    // Verify updated_at assignments even though now() is stable within this transaction.
    co_await tx->execSqlCoro("UPDATE users SET updated_at = now() - INTERVAL '1 day' WHERE id = $1", user.id);
    require((co_await users.recordFailedLogin(user.id)) == 1, "first failed attempt");
    require((co_await users.recordFailedLogin(user.id)) == 2, "second failed attempt");
    auto failed = co_await users.findById(user.id);
    require(failed && failed->updatedAt >= user.updatedAt, "counter updates updated_at");
    co_await tx->execSqlCoro("UPDATE users SET failed_login_count = 2147483647 WHERE id = $1", user.id);
    require((co_await users.recordFailedLogin(user.id)) == 2147483647, "counter saturates");
    auto until = now() + std::chrono::minutes(15);
    co_await tx->execSqlCoro("UPDATE users SET updated_at = now() - INTERVAL '1 day' WHERE id = $1", user.id);
    require(co_await users.setLockedUntil(user.id, until), "set lock");
    auto locked = co_await users.findById(user.id);
    require(locked && locked->lockedUntil && locked->updatedAt >= user.updatedAt, "lock mapping and updated_at");
    auto lockDelta = *locked->lockedUntil - until;
    require(lockDelta >= -std::chrono::microseconds(1) && lockDelta <= std::chrono::microseconds(1), "UTC lock precision");
    co_await tx->execSqlCoro("UPDATE users SET updated_at = now() - INTERVAL '1 day' WHERE id = $1", user.id);
    require(co_await users.setLockedUntil(user.id, std::nullopt), "clear lock");
    auto unlocked = co_await users.findById(user.id);
    require(unlocked && !unlocked->lockedUntil && unlocked->updatedAt >= user.updatedAt, "NULL lock and updated_at");
    require(co_await users.setLockedUntil(user.id, until), "restore lock");
    co_await tx->execSqlCoro("UPDATE users SET updated_at = now() - INTERVAL '1 day' WHERE id = $1", user.id);
    require(co_await users.resetFailedLogins(user.id), "reset failures");
    auto reset = co_await users.findById(user.id);
    require(reset && reset->failedLoginCount == 0 && !reset->lockedUntil && reset->updatedAt >= user.updatedAt, "reset state and timestamp");
    require(!(co_await users.recordFailedLogin(-1)), "counter missing user");
    require(!(co_await users.resetFailedLogins(-1)), "reset missing user");
    require(!(co_await users.setLockedUntil(-1, until)), "lock missing user");

    auto expires = now() + std::chrono::hours(24);
    auto session = co_await sessions.create(user.id, hash(0), expires);
    require(session.tokenHash == hash(0) && session.userId == user.id && !session.revokedAt, "binary digest mapping");
    auto active = co_await sessions.findActiveByTokenHash(hash(0));
    require(active && active->user.id == user.id && active->session.id == session.id, "joined active session");
    require(!(co_await sessions.findActiveByTokenHash(hash(255))), "missing digest");
    require(!(co_await sessions.revoke(session.id, -1)), "wrong owner cannot revoke");
    require((co_await sessions.findActiveByTokenHash(hash(0))).has_value(), "wrong owner leaves session active");
    require(co_await sessions.revoke(session.id, user.id), "revoke");
    require(!(co_await sessions.findActiveByTokenHash(hash(0))), "revoked session denied");
    require(!(co_await sessions.revoke(session.id, user.id)), "idempotent revoke");
    require(!(co_await sessions.revoke(-1, user.id)), "missing revoke");

    auto expired = co_await sessions.create(user.id, hash(1), expires);
    co_await tx->execSqlCoro(R"SQL(
        UPDATE sessions SET created_at = now() - INTERVAL '2 days',
            expires_at = now() - INTERVAL '1 day' WHERE id = $1
    )SQL", expired.id);
    require(!(co_await sessions.findActiveByTokenHash(hash(1))), "expired session denied");
    auto boundary = co_await sessions.create(user.id, hash(2), expires);
    co_await tx->execSqlCoro(R"SQL(
        UPDATE sessions SET created_at = now() - INTERVAL '1 day', expires_at = now() WHERE id = $1
    )SQL", boundary.id);
    require(!(co_await sessions.findActiveByTokenHash(hash(2))), "expires-at-now denied");
    require((co_await sessions.deleteExpired()) == 2, "delete expired including boundary");
    require((co_await sessions.deleteExpired()) == 0, "delete expired idempotent");
    co_await sessions.create(user.id, hash(3), expires);
    co_await sessions.create(user.id, hash(4), expires);
    auto second = co_await users.createUser("second@example.invalid", "Second_User", "hash");
    auto otherId = std::get<User>(second).id;
    co_await sessions.create(otherId, hash(5), expires);
    require((co_await sessions.revokeAllForUser(user.id)) == 2, "revoke all user sessions");
    require(!(co_await sessions.findActiveByTokenHash(hash(3))), "revoke all enforced");
    require((co_await sessions.findActiveByTokenHash(hash(5))).has_value(), "other user sessions unaffected");
    require((co_await sessions.revokeAllForUser(user.id)) == 0, "revoke all idempotent");
    co_await tx->execSqlCoro("DELETE FROM users WHERE id = $1", otherId);
    require(!(co_await sessions.findActiveByTokenHash(hash(5))), "deleted user invalidates session");
    auto count = co_await tx->execSqlCoro("SELECT count(*) AS n FROM sessions WHERE user_id = $1", otherId);
    require(count[0]["n"].as<int>() == 0, "FK cascades");
    std::cout << "PASS repository CRUD, conflicts, counters, locks, UTC and session lifecycle\n";
}
}
int main(int argc, char **argv) {
    const auto *enabled = std::getenv("CHAT_RUN_REPOSITORY_TESTS");
    if (!enabled || std::string(enabled) != "1") {
        std::cout << "SKIP: set CHAT_RUN_REPOSITORY_TESTS=1 on a migrated, empty test database\n";
        return 77;
    }
    if (argc != 2) return 1;
    std::atomic<int> exitCode{1};
    try {
        auto config = chat::loadConfig(argv[1]);
        config["listeners"] = Json::Value(Json::arrayValue);
        config["db_clients"][0]["number_of_connections"] = 1;
        config["db_clients"][0]["timeout"] = 5.0;
        drogon::app().loadConfigJson(config);
        drogon::app().registerBeginningAdvice([&exitCode] {
            drogon::async_run([&exitCode]() -> drogon::Task<void> {
                try {
                    auto db = drogon::app().getDbClient("default");
                    std::exception_ptr failure;
                    {
                        auto tx = co_await db->newTransactionCoro();
                        try {
                            auto counts = co_await tx->execSqlCoro(R"SQL(
                                SELECT (SELECT count(*) FROM users) AS users_count,
                                       (SELECT count(*) FROM sessions) AS sessions_count
                            )SQL");
                            if (counts[0]["users_count"].as<std::int64_t>() != 0 ||
                                counts[0]["sessions_count"].as<std::int64_t>() != 0)
                                throw std::runtime_error("Use an empty dedicated test database");
                            co_await checkRepositories(tx);
                        } catch (...) { failure = std::current_exception(); }
                        tx->rollback();
                    }
                    // Pool size 1: this cannot execute until rollback releases the connection.
                    auto remaining = co_await db->execSqlCoro(R"SQL(
                        SELECT (SELECT count(*) FROM users) AS users_count,
                               (SELECT count(*) FROM sessions) AS sessions_count
                    )SQL");
                    if (failure) std::rethrow_exception(failure);
                    require(remaining[0]["users_count"].as<std::int64_t>() == 0 &&
                            remaining[0]["sessions_count"].as<std::int64_t>() == 0,
                            "fixture rollback left data behind");
                    exitCode = 0;
                } catch (const drogon::orm::DrogonDbException &) {
                    std::cerr << "Repository test DB setup failed; no DB details logged\n";
                } catch (const std::exception &e) {
                    std::cerr << "Repository assertion failed: " << e.what() << '\n';
                }
                drogon::app().quit();
                co_return;
            });
        });
        drogon::app().run();
    } catch (...) { std::cerr << "Repository test setup failed\n"; }
    return exitCode.load();
}
