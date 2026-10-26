#pragma once
#include "models/User.h"
#include <array>
#include <cstdint>
#include <optional>

namespace chat {
using SessionId = std::int64_t;
using TokenHash = std::array<unsigned char, 32>;

// SHA-256 digest bytes, not the raw bearer token.
struct Session {
    SessionId id{};
    UserId userId{};
    TokenHash tokenHash{};
    Timestamp createdAt{};
    Timestamp expiresAt{};
    std::optional<Timestamp> revokedAt;
};

struct ActiveSession {
    Session session;
    User user;
};
}
