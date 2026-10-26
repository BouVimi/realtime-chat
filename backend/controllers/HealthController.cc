#include "controllers/HealthController.h"
#include "utils/HttpError.h"
drogon::Task<drogon::HttpResponsePtr> chat::HealthController::health(drogon::HttpRequestPtr) {
    bool ready = false;
    try { ready = co_await service_.ready(); }
    catch (const std::exception &) {
        // Do not log DB exceptions: they may contain credentials or SQL details.
        LOG_WARN << "Health database probe failed";
    }
    if (!ready)
        co_return chat::error(drogon::k503ServiceUnavailable,
                             "DATABASE_UNAVAILABLE", "Service temporarily unavailable");
    Json::Value body;
    body["status"] = "ok";
    body["database"] = "ok";
    auto response = drogon::HttpResponse::newHttpJsonResponse(body);
    response->addHeader("Cache-Control", "no-store");
    co_return response;
}
