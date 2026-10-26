#pragma once
#include "models/User.h"
#include <optional>
#include <string>
#include <vector>

namespace chat::dto {
// Input only: do not log request bodies or passwords.
struct RegisterRequest { std::string email; std::string username; std::string password; };
struct LoginRequest { std::string email; std::string password; };
struct UpdateMeRequest { std::optional<std::string> email; std::optional<std::string> username; };

// Safe output allowlist. Models and request DTOs are not response DTOs.
struct UserResponse {
    UserId id{};
    std::string email;
    std::string username;
    Timestamp createdAt{};
    Timestamp updatedAt{};
};
inline UserResponse toUserResponse(const User &user) {
    return {user.id, user.email, user.username, user.createdAt, user.updatedAt};
}

struct FieldError { std::string field; std::string code; std::string message; };
// Serialize as {"error":{"code":...,"message":...,"fields":[...]}}.
struct ValidationError {
    std::string code{"VALIDATION_ERROR"};
    std::string message{"Invalid input"};
    std::vector<FieldError> fields;
};
struct ValidationErrorResponse { ValidationError error; };
}
