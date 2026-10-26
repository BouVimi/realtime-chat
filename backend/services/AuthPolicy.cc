#include "services/AuthPolicy.h"
#include <limits>
namespace chat::auth {
LoginDecision decideLogin(const std::optional<User> &user, bool passwordVerified, Timestamp now) {
    if (!user || (user->lockedUntil && *user->lockedUntil > now)) return LoginDecision::Deny;
    return passwordVerified ? LoginDecision::Allow : LoginDecision::RecordFailure;
}
FailureState nextFailure(const User &user, Timestamp now) {
    const int old = user.lockedUntil && *user.lockedUntil <= now ? 0 : user.failedLoginCount;
    const int count = old == std::numeric_limits<int>::max() ? old : old + 1;
    return {count, count >= 5 ? std::optional<Timestamp>{now + std::chrono::minutes(15)} : std::nullopt};
}
std::vector<dto::FieldError> registrationErrors(std::string_view email, std::string_view username, std::string_view password) {
    auto e = validation::validateEmail(email);
    auto u = validation::validateUsername(username);
    auto p = validation::validatePassword(password, username, e.valid ? e.normalized : email);
    auto errors = std::move(e.errors);
    errors.insert(errors.end(), u.errors.begin(), u.errors.end());
    errors.insert(errors.end(), p.errors.begin(), p.errors.end());
    return errors;
}
}
