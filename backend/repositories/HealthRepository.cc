#include "repositories/HealthRepository.h"
#include <drogon/orm/DbClient.h>
drogon::Task<bool> chat::HealthRepository::ping() {
    auto db = drogon::app().getDbClient("default");
    const auto rows = co_await db->execSqlCoro("SELECT 1 AS ok");
    co_return rows.size() == 1 && rows[0]["ok"].as<int>() == 1;
}
