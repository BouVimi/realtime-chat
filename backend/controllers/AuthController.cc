#include "controllers/AuthController.h"
#include "services/AuthService.h"
#include "utils/AuthHttp.h"
#include "utils/HttpError.h"
#include <initializer_list>
namespace chat {
namespace {
std::vector<dto::FieldError> schemaErrors(const Json::Value &body, std::initializer_list<const char *> required) {
    std::vector<dto::FieldError> errors;
    for (const auto *key : required)
        if (!body.isMember(key) || !body[key].isString())
            errors.push_back({key, "STRING_REQUIRED", "Field must be a string"});
    for (const auto &key : body.getMemberNames()) {
        bool known = false;
        for (const auto *allowed : required) if (key == allowed) known = true;
        if (!known) errors.push_back({"body", "UNKNOWN_FIELD", "Body contains an unsupported field"});
    }
    return errors;
}
drogon::HttpResponsePtr userResponse(const dto::UserResponse &user, drogon::HttpStatusCode status) {
    Json::Value body;
    body["user"] = auth::serializeUser(user);
    auto response = drogon::HttpResponse::newHttpJsonResponse(body);
    response->setStatusCode(status);
    response->addHeader("Cache-Control", "no-store");
    return response;
}
}
drogon::Task<drogon::HttpResponsePtr> AuthController::registerUser(drogon::HttpRequestPtr request) {
    auto body = auth::jsonBody(request);
    if (!body) co_return chat::error(drogon::k400BadRequest, "INVALID_JSON", "Body must be a valid JSON object");
    auto fields = schemaErrors(*body, {"email", "username", "password"});
    if (!fields.empty()) co_return auth::fieldErrorResponse(fields);
    dto::RegisterRequest input{(*body)["email"].asString(), (*body)["username"].asString(), (*body)["password"].asString()};
    auto result = co_await auth::authService().registerUser(std::move(input.email), std::move(input.username), std::move(input.password));
    if (auto *registered = std::get_if<auth::Registered>(&result)) co_return userResponse(registered->user, drogon::k201Created);
    if (auto *invalid = std::get_if<auth::InvalidInput>(&result)) co_return auth::fieldErrorResponse(invalid->fields);
    if (std::holds_alternative<auth::EmailTaken>(result))
        co_return chat::error(drogon::k409Conflict, "EMAIL_TAKEN", "Email is already registered");
    co_return chat::error(drogon::k409Conflict, "USERNAME_TAKEN", "Username is already registered");
}
drogon::Task<drogon::HttpResponsePtr> AuthController::login(drogon::HttpRequestPtr request) {
    auto body = auth::jsonBody(request);
    if (!body) co_return chat::error(drogon::k400BadRequest, "INVALID_JSON", "Body must be a valid JSON object");
    auto fields = schemaErrors(*body, {"identifier", "password"});
    if (!fields.empty()) co_return auth::fieldErrorResponse(fields);
    dto::LoginRequest input{(*body)["identifier"].asString(), (*body)["password"].asString()};
    auto result = co_await auth::authService().login(std::move(input.identifier), std::move(input.password));
    if (auto *success = std::get_if<auth::LoggedIn>(&result)) {
        auto response = userResponse(success->user, drogon::k200OK);
        response->addCookie(auth::sessionCookie(success->token, success->maxAge, auth::authService().config()));
        co_return response;
    }
    // The same status, code and message for wrong user, password or lockout.
    co_return chat::error(drogon::k401Unauthorized, "INVALID_CREDENTIALS", "Invalid credentials");
}
drogon::Task<drogon::HttpResponsePtr> AuthController::logout(drogon::HttpRequestPtr request) {
    auto user = request->attributes()->get<auth::AuthenticatedUser>(auth::UserAttribute);
    if (!user) co_return chat::error(drogon::k401Unauthorized, "UNAUTHORIZED", "Authentication required");
    // A body is optional for logout. If supplied, retain the JSON-object contract.
    if (!request->body().empty()) {
        auto body = auth::jsonBody(request);
        if (!body) co_return chat::error(drogon::k400BadRequest, "INVALID_JSON", "Body must be a valid JSON object");
        if (!body->empty()) co_return auth::fieldErrorResponse({{"body", "EMPTY_OBJECT_REQUIRED", "Logout body must be an empty object"}});
    }
    co_await auth::authService().logout(request->getCookie("session"));
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(drogon::k204NoContent);
    response->addHeader("Cache-Control", "no-store");
    response->addCookie(auth::sessionCookie("", 0, auth::authService().config()));
    co_return response;
}
drogon::Task<drogon::HttpResponsePtr> AuthController::me(drogon::HttpRequestPtr request) {
    auto user = request->attributes()->get<auth::AuthenticatedUser>(auth::UserAttribute);
    if (!user) co_return chat::error(drogon::k401Unauthorized, "UNAUTHORIZED", "Authentication required");
    co_return userResponse(*user, drogon::k200OK);
}
}
