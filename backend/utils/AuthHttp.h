#pragma once
#include "config/AuthConfig.h"
#include "dto/AuthDto.h"
#include <drogon/drogon.h>
namespace chat::auth {
inline constexpr char JsonBodyAttribute[] = "chat.auth.json";
inline constexpr char UserAttribute[] = "chat.auth.user";
using AuthenticatedUser = std::shared_ptr<const dto::UserResponse>;
// Global pre-routing guard: JSON/size/Origin checks run before AuthFilter.
drogon::HttpResponsePtr guardRequest(const drogon::HttpRequestPtr &request, const AuthConfig &config);
std::shared_ptr<const Json::Value> jsonBody(const drogon::HttpRequestPtr &request);
drogon::HttpResponsePtr fieldErrorResponse(const std::vector<dto::FieldError> &errors);
Json::Value serializeUser(const dto::UserResponse &user);
drogon::Cookie sessionCookie(const std::string &token, int maxAge, const AuthConfig &config);
}
