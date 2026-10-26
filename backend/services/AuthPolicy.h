#pragma once
#include "dto/AuthDto.h"
#include "validators/AuthValidators.h"
#include <optional>
namespace chat::auth {
enum class LoginDecision { Deny, RecordFailure, Allow };
struct FailureState { int count{}; std::optional<Timestamp> lockedUntil; };
LoginDecision decideLogin(const std::optional<User> &user, bool passwordVerified, Timestamp now);
FailureState nextFailure(const User &user, Timestamp now);
std::vector<dto::FieldError> registrationErrors(std::string_view email, std::string_view username, std::string_view password);
}
