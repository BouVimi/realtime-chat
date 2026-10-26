#pragma once
#include <drogon/drogon.h>
namespace chat {
class HealthRepository {
 public:
    drogon::Task<bool> ping();
};
}
