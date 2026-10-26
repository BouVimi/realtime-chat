#include "utils/AuthHttp.h"
#include <iostream>
#include <stdexcept>
using namespace chat;
using namespace chat::auth;
namespace {
void check(bool condition, const char *message) { if (!condition) throw std::runtime_error(message); }
drogon::HttpRequestPtr request(std::string body = "{}", std::string contentType = "application/json") {
    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post); req->setPath("/api/v1/auth/login");
    req->addHeader("content-type", contentType); req->setBody(std::move(body));
    return req;
}
void status(const drogon::HttpResponsePtr &response, int expected) {
    static int call = 0;
    ++call;
    if (!response || static_cast<int>(response->statusCode()) != expected)
        throw std::runtime_error("HTTP check " + std::to_string(call) + ": expected " + std::to_string(expected) +
                                 ", got " + std::to_string(response ? static_cast<int>(response->statusCode()) : 0));
    auto body = response->getJsonObject();
    check(body && (*body)["error"]["code"].isString() && (*body)["error"]["message"].isString(), "standard error envelope");
}
}
int main() {
    try {
        AuthConfig config;
        auto valid = request("{\"identifier\":\"alice\",\"password\":\"example\"}");
        check(!guardRequest(valid, config) && jsonBody(valid), "valid JSON");
        check(!guardRequest(request("{}", "application/json; charset=utf-8"), config), "JSON charset");
        check(!guardRequest(request(R"({"password":"a/b\\/c"})"), config), "slashes inside strings remain data");
        for (auto body : {"{", "null", "[]", "{} {}", "{\"x\":1,\"x\":2}", "{/*comment*/}", "{\"x\":1,}"})
            status(guardRequest(request(body), config), 400);
        auto emptyLogout = drogon::HttpRequest::newHttpRequest();
        emptyLogout->setMethod(drogon::Post);
        emptyLogout->setPath("/api/v1/auth/logout");
        check(!guardRequest(emptyLogout, config) && !jsonBody(emptyLogout), "bodyless logout needs no Content-Type");
        check(!guardRequest(request("", "text/plain"), config), "empty body does not require JSON Content-Type");
        emptyLogout->addHeader("origin", "https://evil.example");
        status(guardRequest(emptyLogout, config), 403);
        const auto deep = std::string("{\"x\":") + std::string(100, '[') + "0" + std::string(100, ']') + "}";
        status(guardRequest(request(deep), config), 400);
        status(guardRequest(request("{}", "text/plain"), config), 415);
        status(guardRequest(request("{}", "application/x-www-form-urlencoded"), config), 415);
        status(guardRequest(request(std::string(4097, 'x')), config), 413);
        auto allowed = request(); allowed->addHeader("origin", "http://localhost:5173");
        check(!guardRequest(allowed, config), "allowed Origin");
        for (auto origin : {"https://evil.example", "null", "http://localhost:5173.evil", "http://localhost:5173/", ""}) {
            auto denied = request(); denied->addHeader("origin", origin);
            status(guardRequest(denied, config), 403);
        }
        auto cross = request(); cross->addHeader("sec-fetch-site", "cross-site");
        status(guardRequest(cross, config), 403);
        auto compressed = request(); compressed->addHeader("content-encoding", "gzip");
        status(guardRequest(compressed, config), 415);
        auto get = request(); get->setMethod(drogon::Get); get->setPath("/api/v1/health");
        check(!guardRequest(get, config), "health is unaffected");
        auto cookie = sessionCookie("test", 604800, config).cookieString();
        check(cookie.find("HttpOnly") != std::string::npos && cookie.find("Secure") != std::string::npos &&
              cookie.find("SameSite=Lax") != std::string::npos && cookie.find("Path=/") != std::string::npos &&
              cookie.find("Max-Age=604800") != std::string::npos, "secure cookie flags");
        check(sessionCookie("", 0, config).cookieString().find("Max-Age=0") != std::string::npos, "clear cookie");
        dto::UserResponse user; user.id = 9007199254740993LL; user.email = "a@example.com"; user.username = "Alice";
        auto json = serializeUser(user);
        check(json["id"].asString() == "9007199254740993" && json.size() == 5 && !json.isMember("password_hash"), "safe user DTO and bigint string");
        check(json["created_at"].asString() == "1970-01-01T00:00:00Z", "UTC serialization");
        status(fieldErrorResponse({{"email", "EMAIL_INVALID", "Invalid email"}}), 400);
        std::cout << "PASS JSON, size, Origin, cookies and safe DTO serialization\n";
        return 0;
    } catch (const std::exception &e) { std::cerr << "FAIL " << e.what() << '\n'; return 1; }
}
