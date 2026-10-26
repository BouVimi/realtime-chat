#pragma once
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace chat {
using UserId = std::int64_t;
using Timestamp = std::chrono::sys_time<std::chrono::microseconds>;

// Internal persistence model. Never serialize this type to the client.
struct User {
  UserId id{};
  std::string email;
  std::string username;
  std::string passwordHash;
  Timestamp createdAt{};
  Timestamp updatedAt{};
  int failedLoginCount{};
  std::optional<Timestamp> lockedUntil;
};
} // namespace chat
