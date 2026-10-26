#include "services/HealthService.h"
drogon::Task<bool> chat::HealthService::ready() {
    co_return co_await repository_.ping();
}
