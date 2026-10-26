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

drogon::Task<std::optional<User>> UserRepository::findByIdentifierForUpdate(std::string identifier, bool isEmail) {
    try {
        if (!std::dynamic_pointer_cast<drogon::orm::Transaction>(db_)) throw RepositoryError{};
        auto db = client();
        if (isEmail) {
            auto rows = co_await db->execSqlCoro(R"SQL(
                SELECT id, email, username, password_hash,
                (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us,
                (extract(epoch FROM updated_at) * 1000000)::bigint AS updated_at_us,
                failed_login_count,
                (extract(epoch FROM locked_until) * 1000000)::bigint AS locked_until_us FROM users WHERE lower(email) = lower($1) FOR UPDATE
            )SQL", identifier);
            if (rows.empty()) co_return std::nullopt;
            co_return userFromRow(rows[0]);
        }
        auto rows = co_await db->execSqlCoro(R"SQL(
            SELECT id, email, username, password_hash,
                (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us,
                (extract(epoch FROM updated_at) * 1000000)::bigint AS updated_at_us,
                failed_login_count,
                (extract(epoch FROM locked_until) * 1000000)::bigint AS locked_until_us FROM users WHERE lower(username) = lower($1) FOR UPDATE
        )SQL", identifier);
        if (rows.empty()) co_return std::nullopt;
        co_return userFromRow(rows[0]);
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}

drogon::Task<Timestamp> UserRepository::databaseNow() {
    try {
        auto rows = co_await client()->execSqlCoro(
            "SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint AS now_us");
        co_return repository_detail::timestamp(rows[0]["now_us"]);
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}

drogon::Task<bool> UserRepository::updatePasswordHash(UserId id, std::string passwordHash) {
    try {
        auto rows = co_await client()->execSqlCoro(
            "UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1", id, passwordHash);
        co_return rows.affectedRows() == 1;
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}


drogon::Task<UpdateUserResult> UserRepository::updateProfile(
    UserId id, std::optional<std::string> email, std::optional<std::string> username) {
    // A failed UPDATE must roll back independently, so conflict diagnosis uses a fresh snapshot.
    // Drogon transactions auto-rollback on errors; never diagnose via an aborted transaction.
    if (std::dynamic_pointer_cast<drogon::orm::Transaction>(db_) || (!email && !username))
        throw RepositoryError{};
    auto db = client();
    const std::int32_t hasEmail = email.has_value() ? 1 : 0;
    const std::int32_t hasUsername = username.has_value() ? 1 : 0;
    const std::string emailValue = email.value_or("");
    const std::string usernameValue = username.value_or("");
    for (int attempt = 0; attempt < 3; ++attempt) {
        bool failed = false;
        try {
            auto rows = co_await db->execSqlCoro(R"SQL(
                UPDATE users AS u
                SET email = CASE WHEN $2::integer = 1 THEN $3::text ELSE u.email END,
                    username = CASE WHEN $4::integer = 1 THEN $5::text ELSE u.username END,
                    updated_at = now()
                WHERE u.id = $1
                  AND ($2::integer = 0 OR NOT EXISTS (
                    SELECT 1 FROM users other
                    WHERE lower(other.email) = lower($3::text) AND other.id <> $1))
                  AND ($4::integer = 0 OR NOT EXISTS (
                    SELECT 1 FROM users other
                    WHERE lower(other.username) = lower($5::text) AND other.id <> $1))
                RETURNING id, email, username, password_hash,
                    (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us,
                    (extract(epoch FROM updated_at) * 1000000)::bigint AS updated_at_us,
                    failed_login_count,
                    (extract(epoch FROM locked_until) * 1000000)::bigint AS locked_until_us
            )SQL", id, hasEmail, emailValue, hasUsername, usernameValue);
            if (!rows.empty()) co_return userFromRow(rows[0]);
        } catch (const drogon::orm::DrogonDbException &) {
            // A concurrent writer can still hit the unique index after the prechecks.
            // The autocommit UPDATE is atomic: neither field was partially committed.
            failed = true;
        }
        try {
            auto conflicts = co_await db->execSqlCoro(R"SQL(
                SELECT EXISTS(SELECT 1 FROM users WHERE id = $1) AS user_exists,
                    EXISTS(SELECT 1 FROM users WHERE $2::integer = 1
                        AND lower(email) = lower($3::text) AND id <> $1) AS email_taken,
                    EXISTS(SELECT 1 FROM users WHERE $4::integer = 1
                        AND lower(username) = lower($5::text) AND id <> $1) AS username_taken
            )SQL", id, hasEmail, emailValue, hasUsername, usernameValue);
            if (!conflicts[0]["user_exists"].as<bool>()) co_return UserNotFound{};
            if (conflicts[0]["email_taken"].as<bool>()) co_return CreateUserError::EmailTaken;
            if (conflicts[0]["username_taken"].as<bool>()) co_return CreateUserError::UsernameTaken;
        } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
        if (failed) throw RepositoryError{}; // Unexpected infrastructure failure, not invalid input.
        // A conflicting row may have been deleted between statements; retry a bounded number of times.
    }
    throw RepositoryError{};
}
}
