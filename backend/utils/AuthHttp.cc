#include "utils/AuthHttp.h"
#include "utils/HttpError.h"
#include <algorithm>
#include <cctype>
#include <memory>
#include <trantor/utils/Date.h>
namespace chat::auth {
namespace {
// JsonCpp 1.9.5 can accept comments inside empty objects despite allowComments=false.
// A slash outside a quoted JSON string cannot be valid JSON.
bool hasBareSlash(std::string_view text) {
    bool quoted = false, escaped = false;
    for (char c : text) {
        if (quoted) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
        } else if (c == '"') quoted = true;
        else if (c == '/') return true;
    }
    return false;
}
bool stateChanging(drogon::HttpMethod method) {
    return method == drogon::Post || method == drogon::Put || method == drogon::Patch || method == drogon::Delete;
}
std::string mediaType(std::string value) {
    value.resize(value.find(';') == std::string::npos ? value.size() : value.find(';'));
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.pop_back();
    for (char &c : value) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return value;
}
}
drogon::HttpResponsePtr guardRequest(const drogon::HttpRequestPtr &request, const AuthConfig &config) {
    if (!stateChanging(request->method())) return nullptr;
    const auto &headers = request->headers();
    const auto origin = headers.find("origin");
    if ((origin != headers.end() && !isOriginAllowed(config, origin->second)) ||
        (origin == headers.end() && request->getHeader("sec-fetch-site") == "cross-site"))
        return chat::error(drogon::k403Forbidden, "ORIGIN_FORBIDDEN", "Origin is not allowed");
    if (request->body().size() > 4096)
        return chat::error(drogon::k413RequestEntityTooLarge, "BODY_TOO_LARGE", "Request body exceeds 4 KB");
    // Empty requests have no representation to validate; controllers decide if a body is required.
    if (request->body().empty()) return nullptr;
    const auto encoding = request->getHeader("content-encoding");
    if ((!encoding.empty() && encoding != "identity") || mediaType(request->getHeader("content-type")) != "application/json")
        return chat::error(drogon::k415UnsupportedMediaType, "JSON_REQUIRED", "Content-Type must be application/json");
    Json::CharReaderBuilder builder;
    builder["allowComments"] = false;
    builder["collectComments"] = false;
    builder["allowTrailingCommas"] = false;
    builder["rejectDupKeys"] = true;
    builder["failIfExtra"] = true;
    builder["stackLimit"] = 32;
    auto reader = std::unique_ptr<Json::CharReader>(builder.newCharReader());
    auto body = std::make_shared<Json::Value>();
    std::string parseErrors; // Never log parser errors: they may include request input.
    const auto data = request->body();
    bool parsed = false;
    try {
        parsed = !hasBareSlash(data) && reader->parse(data.data(), data.data() + data.size(), body.get(), &parseErrors);
    } catch (const Json::Exception &) {
        // Depth-limit/parser exceptions must also become a sanitized 400.
    }
    if (!parsed || !body->isObject())
        return chat::error(drogon::k400BadRequest, "INVALID_JSON", "Body must be a valid JSON object");
    request->attributes()->insert(JsonBodyAttribute, std::shared_ptr<const Json::Value>(body));
    return nullptr;
}
std::shared_ptr<const Json::Value> jsonBody(const drogon::HttpRequestPtr &request) {
    return request->attributes()->get<std::shared_ptr<const Json::Value>>(JsonBodyAttribute);
}
drogon::HttpResponsePtr fieldErrorResponse(const std::vector<dto::FieldError> &errors) {
    // Reuse the shared error factory and extend its standard envelope with fields.
    auto response = chat::error(drogon::k400BadRequest, "INVALID_INPUT", "Invalid input");
    auto body = *response->getJsonObject();
    body["error"]["fields"] = Json::Value(Json::arrayValue);
    for (const auto &error : errors) {
        Json::Value field;
        field["field"] = error.field;
        field["code"] = error.code;
        field["message"] = error.message;
        body["error"]["fields"].append(std::move(field));
    }
    response = drogon::HttpResponse::newHttpJsonResponse(body);
    response->setStatusCode(drogon::k400BadRequest);
    response->addHeader("Cache-Control", "no-store");
    return response;
}
Json::Value serializeUser(const dto::UserResponse &user) {
    Json::Value body;
    body["id"] = std::to_string(user.id);
    body["email"] = user.email;
    body["username"] = user.username;
    body["created_at"] = trantor::Date(user.createdAt.time_since_epoch().count()).toCustomFormattedString("%Y-%m-%dT%H:%M:%SZ");
    body["updated_at"] = trantor::Date(user.updatedAt.time_since_epoch().count()).toCustomFormattedString("%Y-%m-%dT%H:%M:%SZ");
    return body;
}
drogon::Cookie sessionCookie(const std::string &token, int maxAge, const AuthConfig &config) {
    drogon::Cookie cookie("session", token);
    cookie.setHttpOnly(true);
    cookie.setSecure(config.cookieSecure);
    cookie.setSameSite(drogon::Cookie::SameSite::kLax);
    cookie.setPath("/");
    cookie.setMaxAge(maxAge);
    if (maxAge == 0) cookie.setExpiresDate(trantor::Date(1));
    return cookie;
}
}
