#include "config/AuthConfig.h"
#include <charconv>
#include <cstdlib>
#include <stdexcept>
#include <string_view>
namespace chat::auth {
namespace {
std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}
bool originShape(std::string_view value) {
    const auto prefix = value.starts_with("https://") ? 8u : value.starts_with("http://") ? 7u : 0u;
    if (!prefix || value.size() <= prefix || value == "null") return false;
    const auto authority = value.substr(prefix);
    // Exact origins only: no wildcard, userinfo, path, query, fragment or whitespace.
    for (unsigned char c : authority)
        if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') &&
            c != '.' && c != '-' && c != ':' && c != '[' && c != ']') return false;
    return true;
}
}
AuthConfig loadAuthConfig() {
    AuthConfig config;
    if (const char *v = std::getenv("SESSION_TTL_HOURS")) {
        const std::string_view input(v);
        auto [end, ec] = std::from_chars(input.data(), input.data() + input.size(), config.sessionTtlHours);
        if (ec != std::errc{} || end != input.data() + input.size() || config.sessionTtlHours < 1 || config.sessionTtlHours > 8760)
            throw std::runtime_error("Invalid SESSION_TTL_HOURS");
    }
    if (const char *v = std::getenv("COOKIE_SECURE")) {
        const std::string_view input(v);
        if (input == "true") config.cookieSecure = true;
        else if (input == "false") config.cookieSecure = false;
        else throw std::runtime_error("COOKIE_SECURE must be true or false");
    }
    if (const char *v = std::getenv("ALLOWED_ORIGINS")) {
        config.allowedOrigins.clear();
        std::string_view origins(v);
        while (!origins.empty()) {
            auto comma = origins.find(',');
            auto item = trim(origins.substr(0, comma));
            if (!originShape(item)) throw std::runtime_error("Invalid ALLOWED_ORIGINS");
            config.allowedOrigins.emplace_back(item);
            if (comma == std::string_view::npos) break;
            origins.remove_prefix(comma + 1);
            if (origins.empty()) throw std::runtime_error("Invalid ALLOWED_ORIGINS");
        }
        if (config.allowedOrigins.empty()) throw std::runtime_error("ALLOWED_ORIGINS must not be empty");
    }
    return config;
}
bool isOriginAllowed(const AuthConfig &config, const std::string &origin) {
    for (const auto &allowed : config.allowedOrigins) if (origin == allowed) return true;
    return false;
}
}
