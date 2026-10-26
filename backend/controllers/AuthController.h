#pragma once
#include <drogon/HttpController.h>
#include <drogon/utils/coroutine.h>
namespace chat {
class AuthController : public drogon::HttpController<AuthController> {
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(AuthController::registerUser, "/api/v1/auth/register", drogon::Post);
    ADD_METHOD_TO(AuthController::login, "/api/v1/auth/login", drogon::Post);
    ADD_METHOD_TO(AuthController::logout, "/api/v1/auth/logout", drogon::Post, "chat::AuthFilter");
    ADD_METHOD_TO(AuthController::me, "/api/v1/users/me", drogon::Get, "chat::AuthFilter");
    ADD_METHOD_TO(AuthController::patchMe, "/api/v1/users/me", drogon::Patch, "chat::AuthFilter");
    METHOD_LIST_END
    drogon::Task<drogon::HttpResponsePtr> registerUser(drogon::HttpRequestPtr request);
    drogon::Task<drogon::HttpResponsePtr> login(drogon::HttpRequestPtr request);
    drogon::Task<drogon::HttpResponsePtr> logout(drogon::HttpRequestPtr request);
    drogon::Task<drogon::HttpResponsePtr> patchMe(drogon::HttpRequestPtr request);
    drogon::Task<drogon::HttpResponsePtr> me(drogon::HttpRequestPtr request);
};
}
