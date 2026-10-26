#pragma once
#include "config/AuthConfig.h"
#include "dto/AuthDto.h"
#include "repositories/UserRepository.h"
#include "repositories/SessionRepository.h"
#include "utils/CryptoExecutor.h"
#include <variant>
namespace chat::auth {
struct Registered { dto::UserResponse user; };
struct InvalidInput { std::vector<dto::FieldError> fields; };
struct EmailTaken {};
struct UsernameTaken {};
using RegisterResult = std::variant<Registered, InvalidInput, EmailTaken, UsernameTaken>;
struct InvalidCredentials {}; // Includes unknown users and locked accounts.
struct LoggedIn { dto::UserResponse user; std::string token; Timestamp expiresAt; int maxAge{}; };
using LoginResult = std::variant<LoggedIn, InvalidCredentials>;
struct ProfileUpdated { dto::UserResponse user; };
struct NoAuthenticatedUser {};
using UpdateMeResult = std::variant<ProfileUpdated, InvalidInput, EmailTaken, UsernameTaken, NoAuthenticatedUser>;

class AuthService {
public:
    explicit AuthService(AuthConfig config, drogon::orm::DbClientPtr db = {});
    drogon::Task<RegisterResult> registerUser(std::string email, std::string username, std::string password);
    drogon::Task<LoginResult> login(std::string identifier, std::string password);
    drogon::Task<UpdateMeResult> updateMe(UserId authenticatedId, dto::UpdateMeRequest input);
    drogon::Task<std::size_t> deleteExpiredSessions();
    drogon::Task<bool> logout(std::string token);
    drogon::Task<std::optional<User>> validateSession(std::string token);
    const AuthConfig &config() const { return config_; }
private:
    AuthConfig config_;
    drogon::orm::DbClientPtr db_;
    CryptoExecutor crypto_;
    std::string dummyHash_;
    drogon::orm::DbClientPtr client() const;
    drogon::Task<LoginResult> loginInTransaction(drogon::orm::DbClientPtr tx, std::string identifier, std::string password);
};
// Initialize before app.run(); default controllers/filters share this instance.
AuthService &authService();
}
