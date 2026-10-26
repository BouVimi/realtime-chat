#pragma once
#include "models/User.h"
#include <drogon/orm/DbClient.h>
#include <drogon/utils/coroutine.h>
#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace chat {
enum class CreateUserError { EmailTaken, UsernameTaken };
using CreateUserResult = std::variant<User, CreateUserError>;
struct UserNotFound {};
using UpdateUserResult = std::variant<User, CreateUserError, UserNotFound>;

class UserRepository {
public:
    // Inject a normal client or transaction in tests. Otherwise resolve it lazily.
    explicit UserRepository(drogon::orm::DbClientPtr db = {}) : db_(std::move(db)) {}
    drogon::Task<CreateUserResult> createUser(std::string email, std::string username, std::string passwordHash);
    // Regular client only: each update is one atomic autocommit statement.
    drogon::Task<UpdateUserResult> updateProfile(UserId id, std::optional<std::string> email,
                                                std::optional<std::string> username);
    drogon::Task<std::optional<User>> findById(UserId id);
    drogon::Task<std::optional<User>> findByEmail(std::string email);
    drogon::Task<std::optional<User>> findByUsername(std::string username);
    // AuthService injects a transaction before calling this row-locking lookup.
    drogon::Task<std::optional<User>> findByIdentifierForUpdate(std::string identifier, bool isEmail);
    drogon::Task<Timestamp> databaseNow();
    drogon::Task<bool> updatePasswordHash(UserId id, std::string passwordHash);
    drogon::Task<std::optional<int>> recordFailedLogin(UserId id);
    // Successful login clears both the counter and lockout.
    drogon::Task<bool> resetFailedLogins(UserId id);
    drogon::Task<bool> setLockedUntil(UserId id, std::optional<Timestamp> until);
private:
    drogon::orm::DbClientPtr db_;
    drogon::orm::DbClientPtr client() const;
};
}
