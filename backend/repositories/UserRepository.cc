#include "repositories/UserRepository.h"
#include "repositories/RowMapping.h"
#include <drogon/drogon.h>
#include <drogon/orm/Exception.h>

namespace chat {
using repository_detail::userFromRow;
drogon::orm::DbClientPtr UserRepository::client() const {
    auto db = db_ ? db_ : drogon::app().getDbClient("default");
    if (!db) throw RepositoryError{};
    return db;
}

drogon::Task<CreateUserResult> UserRepository::createUser(
    std::string email, std::string username, std::string passwordHash) {
    try {
        auto db = client();
        // ON CONFLICT handles unique violations without aborting an injected transaction.
        // A second statement gets a fresh READ COMMITTED snapshot after a racing insert.
        for (int attempt = 0; attempt < 3; ++attempt) {
            auto rows = co_await db->execSqlCoro(R"SQL(
                INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3)
                ON CONFLICT DO NOTHING
                RETURNING id, email, username, password_hash,
                (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us,
                (extract(epoch FROM updated_at) * 1000000)::bigint AS updated_at_us,
                failed_login_count,
                (extract(epoch FROM locked_until) * 1000000)::bigint AS locked_until_us
            )SQL", email, username, passwordHash);
            if (!rows.empty()) co_return userFromRow(rows[0]);
            auto conflicts = co_await db->execSqlCoro(R"SQL(
                SELECT EXISTS(SELECT 1 FROM users WHERE lower(email) = lower($1)) AS email_taken,
                       EXISTS(SELECT 1 FROM users WHERE lower(username) = lower($2)) AS username_taken
            )SQL", email, username);
            if (conflicts[0]["email_taken"].as<bool>()) co_return CreateUserError::EmailTaken;
            if (conflicts[0]["username_taken"].as<bool>()) co_return CreateUserError::UsernameTaken;
            // A concurrent delete removed the conflict: retry the insert, not a pre-check.
        }
        throw RepositoryError{};
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}

drogon::Task<std::optional<User>> UserRepository::findById(UserId id) {
    try {
        auto rows = co_await client()->execSqlCoro(R"SQL(
            SELECT id, email, username, password_hash,
                (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us,
                (extract(epoch FROM updated_at) * 1000000)::bigint AS updated_at_us,
                failed_login_count,
                (extract(epoch FROM locked_until) * 1000000)::bigint AS locked_until_us FROM users WHERE id = $1
        )SQL", id);
        if (rows.empty()) co_return std::nullopt;
        co_return userFromRow(rows[0]);
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}

drogon::Task<std::optional<User>> UserRepository::findByEmail(std::string email) {
    try {
        auto rows = co_await client()->execSqlCoro(R"SQL(
            SELECT id, email, username, password_hash,
                (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us,
                (extract(epoch FROM updated_at) * 1000000)::bigint AS updated_at_us,
                failed_login_count,
                (extract(epoch FROM locked_until) * 1000000)::bigint AS locked_until_us FROM users WHERE lower(email) = lower($1)
        )SQL", email);
        if (rows.empty()) co_return std::nullopt;
        co_return userFromRow(rows[0]);
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}

drogon::Task<std::optional<User>> UserRepository::findByUsername(std::string username) {
    try {
        auto rows = co_await client()->execSqlCoro(R"SQL(
            SELECT id, email, username, password_hash,
                (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us,
                (extract(epoch FROM updated_at) * 1000000)::bigint AS updated_at_us,
                failed_login_count,
                (extract(epoch FROM locked_until) * 1000000)::bigint AS locked_until_us FROM users WHERE lower(username) = lower($1)
        )SQL", username);
        if (rows.empty()) co_return std::nullopt;
        co_return userFromRow(rows[0]);
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}

drogon::Task<std::optional<int>> UserRepository::recordFailedLogin(UserId id) {
    try {
        auto rows = co_await client()->execSqlCoro(R"SQL(
            UPDATE users
            SET failed_login_count = LEAST(failed_login_count::bigint + 1, 2147483647)::integer,
                updated_at = now()
            WHERE id = $1 RETURNING failed_login_count
        )SQL", id);
        if (rows.empty()) co_return std::nullopt;
        co_return rows[0]["failed_login_count"].as<int>();
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}

drogon::Task<bool> UserRepository::resetFailedLogins(UserId id) {
    try {
        auto rows = co_await client()->execSqlCoro(R"SQL(
            UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = now()
            WHERE id = $1
        )SQL", id);
        co_return rows.affectedRows() == 1;
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}

drogon::Task<bool> UserRepository::setLockedUntil(UserId id, std::optional<Timestamp> until) {
    try {
        auto db = client();
        if (until) {
            auto rows = co_await db->execSqlCoro(R"SQL(
                UPDATE users
                SET locked_until = TIMESTAMPTZ 'epoch' + $2::bigint * INTERVAL '1 microsecond',
                    updated_at = now()
                WHERE id = $1
            )SQL", id, until->time_since_epoch().count());
            co_return rows.affectedRows() == 1;
        }
        auto rows = co_await db->execSqlCoro(R"SQL(
            UPDATE users SET locked_until = NULL, updated_at = now() WHERE id = $1
        )SQL", id);
        co_return rows.affectedRows() == 1;
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}
}
