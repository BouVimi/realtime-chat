#include "config/Config.h"
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <string_view>
namespace {
std::string env(const char *key, const char *fallback = nullptr) {
    const char *v = std::getenv(key);
    if (v && *v) return v;
    if (fallback) return fallback;
    throw std::runtime_error(std::string("Missing environment variable: ") + key);
}
int number(const char *key, const char *fallback, int max) {
    const auto value = env(key, fallback);
    int result = 0;
    auto [end, ec] = std::from_chars(value.data(), value.data()+value.size(), result);
    if (ec != std::errc{} || end != value.data()+value.size() || result < 1 || result > max)
        throw std::runtime_error(std::string("Invalid environment variable: ") + key);
    return result;
}
}
Json::Value chat::loadConfig(const std::string &path) {
    std::ifstream file(path);
    Json::Value config;
    Json::CharReaderBuilder reader;
    std::string errors;
    if (!file || !Json::parseFromStream(reader, file, &config, &errors))
        throw std::runtime_error("Cannot read JSON configuration");
    if (!config["listeners"].isArray() || config["listeners"].size() != 1 ||
        !config["db_clients"].isArray() || config["db_clients"].size() != 1)
        throw std::runtime_error("Invalid configuration structure");
    auto &listener = config["listeners"][0];
    listener["address"] = env("APP_HOST", "127.0.0.1");
    listener["port"] = number("APP_PORT", "8080", 65535);
    auto &db = config["db_clients"][0];
    db["host"] = env("DB_HOST", "127.0.0.1");
    db["port"] = number("DB_PORT", "5432", 65535);
    db["dbname"] = env("POSTGRES_DB");
    db["user"] = env("POSTGRES_USER");
    db["passwd"] = env("POSTGRES_PASSWORD");
    db["number_of_connections"] = number("DB_POOL_SIZE", "4", 64);
    config["app"]["number_of_threads"] = number("APP_THREADS", "2", 64);
    config["app"]["enable_session"] = false;
    return config;
}
