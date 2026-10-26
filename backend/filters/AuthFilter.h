#pragma once
#include <drogon/HttpFilter.h>
namespace chat {
class AuthFilter : public drogon::HttpCoroFilter<AuthFilter> {
public:
    drogon::Task<drogon::HttpResponsePtr> doFilter(const drogon::HttpRequestPtr &request) override;
};
}
