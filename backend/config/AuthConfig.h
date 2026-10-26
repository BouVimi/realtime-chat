#pragma once
#include <string>
#include <vector>
namespace chat::auth {
struct AuthConfig {
    int sessionTtlHours{168};
    bool cookieSecure{true};
    std::vector<std::string> allowedOrigins{"http://localhost:5173", "http://127.0.0.1:5173"};
    int maxAgeSeconds() const { return sessionTtlHours * 3600; }
};
AuthConfig loadAuthConfig();
bool isOriginAllowed(const AuthConfig &config, const std::string &origin);
}
