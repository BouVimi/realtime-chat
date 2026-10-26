#pragma once
#include "models/Session.h"
#include <optional>
#include <string>
#include <string_view>
namespace chat::auth {
struct Token { std::string encoded; TokenHash hash{}; };
void initializeCrypto();
Token generateToken();
std::optional<TokenHash> hashToken(std::string_view encoded);
std::string hashPassword(std::string_view password);
bool verifyPassword(std::string_view password, const std::string &hash);
bool needsRehash(const std::string &hash);
}
