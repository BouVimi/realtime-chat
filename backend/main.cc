#include <drogon/drogon.h>
#include "config/Config.h"
#include "utils/HttpError.h"
#include <iostream>
#include <cstdio>
#include <atomic>
#include <memory>
#include "services/AuthService.h"
#include "utils/AuthHttp.h"
int main(int argc, char **argv) {
    try {
        // Drogon's DB diagnostics can contain row details. Emit fixed events only.
        trantor::Logger::setOutputFunction([](const char *, const uint64_t) {
            constexpr char event[] = "{\"event\":\"backend_diagnostic\"}\n";
            std::fwrite(event, 1, sizeof(event) - 1, stderr);
        }, [] { std::fflush(stderr); });
        auto config = chat::loadConfig(argc > 1 ? argv[1] : "backend/config/config.json");
        config["app"]["log"]["log_path"] = "";
        config["app"]["log"]["use_spdlog"] = false;
        config["app"]["log"]["log_level"] = "WARN";
        config["app"]["client_max_body_size"] = "4K";
        config["app"]["client_max_memory_body_size"] = "4K";
        drogon::app().loadConfigJson(config);
        // Validate auth env and generate the dummy hash before serving requests.
        auto &auth = chat::auth::authService();
        drogon::app().registerSyncAdvice([&auth](const drogon::HttpRequestPtr &request) {
            return chat::auth::guardRequest(request, auth.config());
        });
        drogon::app().setFileTypes({});
        drogon::app().setImplicitPageEnable(false);
        drogon::app().setCustomErrorHandler([](drogon::HttpStatusCode status,
                                               const drogon::HttpRequestPtr &) {
            return chat::error(status, "HTTP_" + std::to_string(static_cast<int>(status)),
                               "Request could not be processed");
        });
        drogon::app().setExceptionHandler([](const std::exception &exception,
            const drogon::HttpRequestPtr &,
            std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            if (dynamic_cast<const chat::auth::ServiceBusy *>(&exception)) {
                callback(chat::error(drogon::k503ServiceUnavailable, "AUTH_BUSY", "Service temporarily unavailable"));
                return;
            }
            LOG_ERROR << "Unhandled request exception";
            callback(chat::error(drogon::k500InternalServerError,
                                 "INTERNAL_ERROR", "Internal server error"));
        });
        drogon::app().registerBeginningAdvice([&auth] {
            auto running = std::make_shared<std::atomic_bool>(false);
            auto cleanup = [&auth, running] {
                if (running->exchange(true)) return; // Do not overlap slow cleanup runs.
                drogon::async_run([&auth, running]() -> drogon::Task<void> {
                    try { co_await auth.deleteExpiredSessions(); }
                    catch (...) { LOG_WARN << "Expired session cleanup failed"; }
                    running->store(false);
                    co_return;
                });
            };
            cleanup();
            drogon::app().getLoop()->runEvery(3600.0, cleanup);
        });
        drogon::app().run();
    } catch (const std::exception &) {
        std::cerr << "Startup failed: check configuration and dependencies\n";
        return 1;
    }
}
