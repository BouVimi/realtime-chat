#pragma once
#include <drogon/drogon.h>
#include <string>
namespace chat {
inline drogon::HttpResponsePtr error(drogon::HttpStatusCode status,
                                    const std::string &code, const std::string &message) {
    Json::Value body;
    body["error"]["code"] = code;
    body["error"]["message"] = message;
    auto response = drogon::HttpResponse::newHttpJsonResponse(body);
    response->setStatusCode(status);
    response->addHeader("Cache-Control", "no-store");
    return response;
}
}
