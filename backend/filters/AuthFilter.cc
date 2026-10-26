#include "filters/AuthFilter.h"
#include "services/AuthService.h"
#include "utils/AuthHttp.h"
#include "utils/HttpError.h"
namespace chat {
drogon::Task<drogon::HttpResponsePtr> AuthFilter::doFilter(const drogon::HttpRequestPtr &request) {
    // Own the request across suspension, even though Drogon's virtual API takes a reference.
    auto owned = request;
    const auto token = owned->getCookie("session");
    if (token.empty()) co_return chat::error(drogon::k401Unauthorized, "UNAUTHORIZED", "Authentication required");
    auto user = co_await auth::authService().validateSession(token);
    if (!user) {
        auto response = chat::error(drogon::k401Unauthorized, "UNAUTHORIZED", "Authentication required");
        response->addCookie(auth::sessionCookie("", 0, auth::authService().config()));
        co_return response;
    }
    owned->attributes()->insert(auth::UserAttribute,
        auth::AuthenticatedUser(std::make_shared<const dto::UserResponse>(dto::toUserResponse(*user))));
    co_return nullptr;
}
}
