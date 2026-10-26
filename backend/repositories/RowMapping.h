#pragma once
#include "models/Session.h"
#include "repositories/RepositoryError.h"
#include <drogon/orm/Row.h>
#include <algorithm>
#include <vector>

namespace chat::repository_detail {
inline Timestamp timestamp(const drogon::orm::Field &field) {
    return Timestamp{std::chrono::microseconds{field.as<std::int64_t>()}};
}
inline std::optional<Timestamp> nullableTimestamp(const drogon::orm::Field &field) {
    if (field.isNull()) return std::nullopt;
    return timestamp(field);
}
// All queries provide the same explicit aliases; no timezone-dependent parsing.
inline User userFromRow(const drogon::orm::Row &row) {
    return {row["id"].as<UserId>(), row["email"].as<std::string>(),
        row["username"].as<std::string>(), row["password_hash"].as<std::string>(),
        timestamp(row["created_at_us"]), timestamp(row["updated_at_us"]),
        row["failed_login_count"].as<int>(), nullableTimestamp(row["locked_until_us"])};
}
inline Session sessionFromRow(const drogon::orm::Row &row) {
    const auto bytes = row["token_hash"].as<std::vector<char>>();
    if (bytes.size() != 32) throw RepositoryError{};
    TokenHash hash{};
    std::transform(bytes.begin(), bytes.end(), hash.begin(), [](char c) { return static_cast<unsigned char>(c); });
    return {row["session_id"].as<SessionId>(), row["user_id"].as<UserId>(), hash,
        timestamp(row["session_created_at_us"]), timestamp(row["expires_at_us"]),
        nullableTimestamp(row["revoked_at_us"])};
}
inline std::vector<char> binaryHash(const TokenHash &hash) {
    // Preserve all byte values, including zero bytes.
    const auto *begin = reinterpret_cast<const char *>(hash.data());
    return {begin, begin + hash.size()};
}
}
