#include "controllers/AuthController.h"
#include "services/AuthService.h"
#include "utils/AuthHttp.h"
#include <trantor/net/EventLoopThread.h>
#include <future>
#include <iostream>
#include <stdexcept>

namespace {
void check(bool value, const char *message) {
    if (!value) throw std::runtime_error(message);
}
drogon::HttpRequestPtr request(const std::string &path, drogon::HttpMethod method) {
    auto req = drogon::HttpRequest::newHttpRequest();
    req->setPath(path); req->setMethod(method);
    return req; // Deliberately no body and no Content-Type.
}
void authenticatedContext(const drogon::HttpRequestPtr &req) {
    // Unit fixture for the controller's trusted AuthFilter contract, not a real login.
    auto user = std::make_shared<chat::dto::UserResponse>();
    user->id = 1; user->username = "Unit_User"; user->email = "unit@example.invalid";
    req->attributes()->insert(chat::auth::UserAttribute, chat::auth::AuthenticatedUser(user));
}
void status(const drogon::HttpResponsePtr &response, int expected) {
    check(static_cast<int>(response->statusCode()) == expected, "controller status mismatch");
    if (expected >= 400) {
        auto json = response->getJsonObject();
        check(json && (*json)["error"]["code"].isString() && (*json)["error"]["message"].isString(),
              "standard error envelope required");
    }
}
}
int main() {
    try {
        auto &service = chat::auth::authService(); // Startup setup before the test event loop.
        chat::AuthController controller;
        trantor::EventLoopThread thread("controller-unit-loop");
        thread.run();
        std::promise<void> completion;
        auto future = completion.get_future();
        thread.getLoop()->queueInLoop([&] {
            drogon::async_run([&]() -> drogon::Task<void> {
                try {
                    auto login = request("/api/v1/auth/login", drogon::Post);
                    check(!chat::auth::guardRequest(login, service.config()), "empty login is not a MIME error");
                    status(co_await controller.login(login), 400);
                    auto registration = request("/api/v1/auth/register", drogon::Post);
                    check(!chat::auth::guardRequest(registration, service.config()), "empty register is not a MIME error");
                    status(co_await controller.registerUser(registration), 400);
                    auto logout = request("/api/v1/auth/logout", drogon::Post);
                    check(!chat::auth::guardRequest(logout, service.config()), "empty logout needs no Content-Type");
                    status(co_await controller.logout(logout), 401); // No authentication bypass.
                    authenticatedContext(logout);
                    // Empty/malformed tokens return before DB access. This tests body handling,
                    // not successful database authentication or persisted session revocation.
                    auto loggedOut = co_await controller.logout(logout);
                    status(loggedOut, 204);
                    check(loggedOut->getCookie("session").maxAge() == 0, "logout must clear cookie");
                    auto patch = request("/api/v1/users/me", drogon::Patch);
                    check(!chat::auth::guardRequest(patch, service.config()), "empty PATCH reaches controller");
                    status(co_await controller.patchMe(patch), 401);
                    authenticatedContext(patch);
                    status(co_await controller.patchMe(patch), 400);
                    for (const char *body : {"{}", "{\"username\":\"1bad!\"}",
                         "{\"email\":\"different@example.invalid\",\"id\":2}",
                         "{\"password_hash\":\"not-a-real-hash\"}"}) {
                        auto update = request("/api/v1/users/me", drogon::Patch);
                        authenticatedContext(update);
                        update->addHeader("Content-Type", "application/json"); update->setBody(body);
                        check(!chat::auth::guardRequest(update, service.config()), "PATCH body parsed");
                        status(co_await controller.patchMe(update), 400);
                    }
                    completion.set_value();
                } catch (...) { completion.set_exception(std::current_exception()); }
                co_return;
            });
        });
        future.get();
        thread.getLoop()->quit(); thread.wait();
        std::cout << "PASS bodyless register/login/logout and protected PATCH controller validation\n";
        return 0;
    } catch (const std::exception &) {
        std::cerr << "Controller regression failed\n";
        return 1;
    }
}
