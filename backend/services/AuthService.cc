#include "services/AuthService.h"
#include "services/AuthPolicy.h"
#include "repositories/RepositoryError.h"
#include "utils/AuthCrypto.h"
#include <drogon/drogon.h>
#include <trantor/net/EventLoop.h>

namespace chat::auth {
namespace {
struct CommitAwaiter : drogon::CallbackAwaiter<bool> {
    explicit CommitAwaiter(std::shared_ptr<drogon::orm::Transaction> tx) : tx_(std::move(tx)) {}
    void await_suspend(std::coroutine_handle<> handle) {
        auto *loop = trantor::EventLoop::getEventLoopOfCurrentThread();
        tx_->setCommitCallback([this, handle, loop](bool ok) {
            this->setValue(ok);
            loop->queueInLoop([handle] { handle.resume(); });
        });
        tx_.reset(); // Drogon commits when the final transaction owner releases it.
    }
private:
    std::shared_ptr<drogon::orm::Transaction> tx_;
};
std::string trimIdentifier(std::string value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}
}
AuthService::AuthService(AuthConfig config, drogon::orm::DbClientPtr db)
    : config_(std::move(config)), db_(std::move(db)) {
    initializeCrypto();
    // Per-process dummy with the same Argon2id parameters; never exposed or logged.
    dummyHash_ = hashPassword(generateToken().encoded);
}
drogon::orm::DbClientPtr AuthService::client() const {
    auto db = db_ ? db_ : drogon::app().getDbClient("default");
    if (!db) throw RepositoryError{};
    return db;
}
drogon::Task<RegisterResult> AuthService::registerUser(std::string email, std::string username, std::string password) {
    auto errors = registrationErrors(email, username, password);
    if (!errors.empty()) co_return InvalidInput{std::move(errors)};
    auto normalized = validation::validateEmail(email).normalized;
    auto work = co_await crypto_.run([password] { return CryptoResult{false, hashPassword(password)}; });
    UserRepository users(client());
    auto created = co_await users.createUser(std::move(normalized), std::move(username), std::move(work.hash));
    if (auto *user = std::get_if<User>(&created)) co_return Registered{dto::toUserResponse(*user)};
    if (std::get<CreateUserError>(created) == CreateUserError::EmailTaken) co_return EmailTaken{};
    co_return UsernameTaken{};
}
drogon::Task<LoginResult> AuthService::loginInTransaction(
    drogon::orm::DbClientPtr tx, std::string identifier, std::string password) {
    UserRepository users(tx);
    SessionRepository sessions(tx);
    identifier = trimIdentifier(std::move(identifier));
    const bool email = identifier.find('@') != std::string::npos;
    auto validationResult = email ? validation::validateEmail(identifier) : validation::validateUsername(identifier);
    std::optional<User> user;
    if (validationResult.valid)
        user = co_await users.findByIdentifierForUpdate(validationResult.normalized, email);
    const auto hash = user ? user->passwordHash : dummyHash_;
    // Even unknown, locked and oversized-password attempts perform one Argon2 verification.
    const bool bounded = password.size() <= 512;
    auto check = co_await crypto_.run([password, hash, bounded] {
        const std::string_view candidate = bounded ? std::string_view(password) : std::string_view("invalid-overlong-input");
        return CryptoResult{verifyPassword(candidate, hash) && bounded, {}};
    });
    const auto now = co_await users.databaseNow();
    const auto decision = decideLogin(user, check.verified, now);
    if (decision == LoginDecision::Deny) co_return InvalidCredentials{};
    if (decision == LoginDecision::RecordFailure) {
        const auto state = nextFailure(*user, now);
        if (user->lockedUntil && *user->lockedUntil <= now && !(co_await users.resetFailedLogins(user->id)))
            throw RepositoryError{};
        const auto count = co_await users.recordFailedLogin(user->id);
        if (!count || *count != state.count) throw RepositoryError{};
        if (state.lockedUntil && !(co_await users.setLockedUntil(user->id, state.lockedUntil)))
            throw RepositoryError{};
        co_return InvalidCredentials{};
    }
    if (needsRehash(user->passwordHash)) {
        auto work = co_await crypto_.run([password] { return CryptoResult{false, hashPassword(password)}; });
        if (!(co_await users.updatePasswordHash(user->id, std::move(work.hash)))) throw RepositoryError{};
    }
    if (!(co_await users.resetFailedLogins(user->id))) throw RepositoryError{};
    auto token = generateToken();
    const auto expiresAt = (co_await users.databaseNow()) + std::chrono::hours(config_.sessionTtlHours);
    co_await sessions.create(user->id, token.hash, expiresAt);
    // Re-read so response timestamps reflect reset/rehash updates.
    auto current = co_await users.findById(user->id);
    if (!current) throw RepositoryError{};
    co_return LoggedIn{dto::toUserResponse(*current), std::move(token.encoded), expiresAt, config_.maxAgeSeconds()};
}
drogon::Task<LoginResult> AuthService::login(std::string identifier, std::string password) {
    auto tx = co_await client()->newTransactionCoro();
    try {
        auto result = co_await loginInTransaction(tx, std::move(identifier), std::move(password));
        // No repository or nested coroutine retains tx at this point.
        if (!(co_await CommitAwaiter{std::move(tx)})) throw RepositoryError{};
        co_return result;
    } catch (...) {
        if (tx) tx->rollback();
        throw;
    }
}
drogon::Task<bool> AuthService::logout(std::string token) {
    const auto hash = hashToken(token);
    if (!hash) co_return false;
    auto tx = co_await client()->newTransactionCoro();
    try {
        bool revoked = false;
        {
            SessionRepository sessions(tx);
            auto active = co_await sessions.findActiveByTokenHash(*hash);
            if (active) revoked = co_await sessions.revoke(active->session.id, active->user.id);
        }
        if (!(co_await CommitAwaiter{std::move(tx)})) throw RepositoryError{};
        co_return revoked;
    } catch (...) {
        if (tx) tx->rollback();
        throw;
    }
}
drogon::Task<std::optional<User>> AuthService::validateSession(std::string token) {
    const auto hash = hashToken(token);
    if (!hash) co_return std::nullopt;
    SessionRepository sessions(client());
    auto active = co_await sessions.findActiveByTokenHash(*hash);
    if (!active) co_return std::nullopt;
    co_return active->user;
}

drogon::Task<UpdateMeResult> AuthService::updateMe(UserId authenticatedId, dto::UpdateMeRequest input) {
    if (authenticatedId <= 0) co_return NoAuthenticatedUser{};
    std::vector<dto::FieldError> errors;
    if (!input.email && !input.username)
        errors.push_back({"body", "EMPTY_PATCH", "Provide email or username"});
    if (input.email) {
        auto result = validation::validateEmail(*input.email);
        errors.insert(errors.end(), result.errors.begin(), result.errors.end());
        if (result.valid) input.email = std::move(result.normalized);
    }
    if (input.username) {
        auto result = validation::validateUsername(*input.username);
        errors.insert(errors.end(), result.errors.begin(), result.errors.end());
        if (result.valid) input.username = std::move(result.normalized);
    }
    if (!errors.empty()) co_return InvalidInput{std::move(errors)};
    UserRepository users(client());
    auto result = co_await users.updateProfile(authenticatedId, std::move(input.email), std::move(input.username));
    if (const auto *user = std::get_if<User>(&result)) co_return ProfileUpdated{dto::toUserResponse(*user)};
    if (std::holds_alternative<UserNotFound>(result)) co_return NoAuthenticatedUser{};
    if (std::get<CreateUserError>(result) == CreateUserError::EmailTaken) co_return EmailTaken{};
    co_return UsernameTaken{};
}

drogon::Task<std::size_t> AuthService::deleteExpiredSessions() {
    SessionRepository sessions(client());
    co_return co_await sessions.deleteExpired();
}

AuthService &authService() {
    static AuthService service(loadAuthConfig());
    return service;
}
}
