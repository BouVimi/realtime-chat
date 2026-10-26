#pragma once
#include <drogon/HttpController.h>
#include <drogon/utils/coroutine.h>
#include "services/HealthService.h"
namespace chat {
class HealthController : public drogon::HttpController<HealthController> {
 public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(HealthController::health, "/api/v1/health", drogon::Get);
    METHOD_LIST_END
    drogon::Task<drogon::HttpResponsePtr> health(drogon::HttpRequestPtr request);
 private:
    HealthService service_;
};
}
