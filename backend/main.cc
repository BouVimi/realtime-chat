#include <drogon/drogon.h>
#include "config/Config.h"
#include "utils/HttpError.h"
#include <iostream>
int main(int argc, char **argv) {
    try {
        drogon::app().loadConfigJson(chat::loadConfig(argc > 1 ? argv[1] : "backend/config/config.json"));
        drogon::app().setFileTypes({});
        drogon::app().setImplicitPageEnable(false);
        drogon::app().setCustomErrorHandler([](drogon::HttpStatusCode status,
                                               const drogon::HttpRequestPtr &) {
            return chat::error(status, "HTTP_" + std::to_string(static_cast<int>(status)),
                               "Request could not be processed");
        });
        drogon::app().setExceptionHandler([](const std::exception &,
            const drogon::HttpRequestPtr &,
            std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            LOG_ERROR << "Unhandled request exception";
            callback(chat::error(drogon::k500InternalServerError,
                                 "INTERNAL_ERROR", "Internal server error"));
        });
        drogon::app().run();
    } catch (const std::exception &) {
        std::cerr << "Startup failed: check configuration and dependencies\n";
        return 1;
    }
}
