#pragma once
#include "models/Session.h"
#include <drogon/orm/DbClient.h>
#include <drogon/utils/coroutine.h>
#include <optional>
#include <utility>

namespace chat {
class SessionRepository {
public:
    explicit SessionRepository(drogon::orm::DbClientPtr db = {}) : db_(std::move(db)) {}
    drogon::Task<Session> create(UserId userId, TokenHash tokenHash, Timestamp expiresAt);
    drogon::Task<std::optional<ActiveSession>> findActiveByTokenHash(TokenHash tokenHash);
    // Require the authenticated owner. false = wrong owner, missing or already revoked.
    drogon::Task<bool> revoke(SessionId id, UserId userId);
    drogon::Task<std::size_t> revokeAllForUser(UserId userId);
    drogon::Task<std::size_t> deleteExpired();
private:
    drogon::orm::DbClientPtr db_;
    drogon::orm::DbClientPtr client() const;
};
}
