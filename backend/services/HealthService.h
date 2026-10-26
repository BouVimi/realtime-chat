#pragma once
#include "repositories/HealthRepository.h"
namespace chat {
class HealthService {
 public:
    drogon::Task<bool> ready();
 private:
    HealthRepository repository_;
};
}
