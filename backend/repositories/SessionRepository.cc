#include "repositories/SessionRepository.h"
#include "repositories/RowMapping.h"
#include <drogon/drogon.h>
#include <drogon/orm/Exception.h>

namespace chat {
using namespace repository_detail;
drogon::orm::DbClientPtr SessionRepository::client() const {
    auto db = db_ ? db_ : drogon::app().getDbClient("default");
    if (!db) throw RepositoryError{};
    return db;
}

drogon::Task<Session> SessionRepository::create(UserId userId, TokenHash tokenHash, Timestamp expiresAt) {
    try {
        auto rows = co_await client()->execSqlCoro(R"SQL(
            INSERT INTO sessions (user_id, token_hash, expires_at)
            VALUES ($1, $2, TIMESTAMPTZ 'epoch' + $3::bigint * INTERVAL '1 microsecond')
            RETURNING id AS session_id, user_id, token_hash,
                (extract(epoch FROM created_at) * 1000000)::bigint AS session_created_at_us,
                (extract(epoch FROM expires_at) * 1000000)::bigint AS expires_at_us,
                (extract(epoch FROM revoked_at) * 1000000)::bigint AS revoked_at_us
        )SQL", userId, binaryHash(tokenHash), expiresAt.time_since_epoch().count());
        co_return sessionFromRow(rows[0]);
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}

drogon::Task<std::optional<ActiveSession>> SessionRepository::findActiveByTokenHash(TokenHash tokenHash) {
    try {
        auto rows = co_await client()->execSqlCoro(R"SQL(
            SELECT s.id AS session_id, s.user_id, s.token_hash,
                (extract(epoch FROM s.created_at) * 1000000)::bigint AS session_created_at_us,
                (extract(epoch FROM s.expires_at) * 1000000)::bigint AS expires_at_us,
                (extract(epoch FROM s.revoked_at) * 1000000)::bigint AS revoked_at_us,
                u.id, u.email, u.username, u.password_hash,
                (extract(epoch FROM u.created_at) * 1000000)::bigint AS created_at_us,
                (extract(epoch FROM u.updated_at) * 1000000)::bigint AS updated_at_us,
                u.failed_login_count,
                (extract(epoch FROM u.locked_until) * 1000000)::bigint AS locked_until_us
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
        )SQL", binaryHash(tokenHash));
        if (rows.empty()) co_return std::nullopt;
        co_return ActiveSession{sessionFromRow(rows[0]), userFromRow(rows[0])};
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}

drogon::Task<bool> SessionRepository::revoke(SessionId id, UserId userId) {
    try {
        auto rows = co_await client()->execSqlCoro(R"SQL(
            UPDATE sessions SET revoked_at = now()
            WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
        )SQL", id, userId);
        co_return rows.affectedRows() == 1;
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}

drogon::Task<std::size_t> SessionRepository::revokeAllForUser(UserId userId) {
    try {
        auto rows = co_await client()->execSqlCoro(R"SQL(
            UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL
        )SQL", userId);
        co_return rows.affectedRows();
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}

drogon::Task<std::size_t> SessionRepository::deleteExpired() {
    try {
        auto rows = co_await client()->execSqlCoro("DELETE FROM sessions WHERE expires_at <= now()");
        co_return rows.affectedRows();
    } catch (const drogon::orm::DrogonDbException &) { throw RepositoryError{}; }
}
}
