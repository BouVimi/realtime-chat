#include "config/Config.h"
#include <cstdlib>
#include <iostream>
#include <stdexcept>
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    setenv("POSTGRES_DB", "test", 1);
    setenv("POSTGRES_USER", "test", 1);
    setenv("POSTGRES_PASSWORD", "quote' slash\\ newline\n", 1);
    setenv("APP_PORT", "9001", 1);
    auto config = chat::loadConfig(argv[1]);
    if (config["listeners"][0]["port"].asInt() != 9001 ||
        config["db_clients"][0]["passwd"].asString() != std::getenv("POSTGRES_PASSWORD") ||
        config["app"]["enable_session"].asBool()) return 1;
    for (const char *bad : {"0", "-1", "65536", "abc", "8080x"}) {
        setenv("APP_PORT", bad, 1);
        bool rejected = false;
        try { chat::loadConfig(argv[1]); } catch (const std::runtime_error &) { rejected = true; }
        if (!rejected) return 1;
    }
    setenv("APP_PORT", "8080", 1);
    unsetenv("POSTGRES_PASSWORD");
    try { chat::loadConfig(argv[1]); } catch (const std::runtime_error &) { return 0; }
    std::cerr << "Missing password was accepted\n";
    return 1;
}
