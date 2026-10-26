#pragma once
#include <drogon/utils/coroutine.h>
#include <trantor/net/EventLoop.h>
#include <trantor/utils/ConcurrentTaskQueue.h>
#include <atomic>
#include <functional>
#include <stdexcept>
#include <string>

namespace chat::auth {
struct ServiceBusy : std::runtime_error { ServiceBusy() : std::runtime_error("Authentication temporarily busy") {} };
struct CryptoResult { bool verified{}; std::string hash; };
class CryptoExecutor {
public:
    CryptoExecutor() : queue_(2, "password-workers") {}
    struct Awaiter : drogon::CallbackAwaiter<CryptoResult> {
        Awaiter(CryptoExecutor &pool, std::function<CryptoResult()> job)
            : pool_(pool), job_(std::move(job)) {}
        bool await_suspend(std::coroutine_handle<> handle) {
            auto *loop = trantor::EventLoop::getEventLoopOfCurrentThread();
            if (!loop) { this->setException(std::make_exception_ptr(std::runtime_error("Missing event loop"))); return false; }
            if (pool_.pending_.fetch_add(1) >= 32) {
                --pool_.pending_;
                this->setException(std::make_exception_ptr(ServiceBusy{}));
                return false;
            }
            try {
                pool_.queue_.runTaskInQueue([this, handle, loop] {
                    try { this->setValue(job_()); }
                    catch (...) { this->setException(std::current_exception()); }
                    job_ = {}; // Release password copies before resuming the request.
                    --pool_.pending_;
                    loop->queueInLoop([handle] { handle.resume(); });
                });
            } catch (...) {
                --pool_.pending_;
                this->setException(std::current_exception());
                return false;
            }
            return true;
        }
    private:
        CryptoExecutor &pool_;
        std::function<CryptoResult()> job_;
    };
    Awaiter run(std::function<CryptoResult()> job) { return {*this, std::move(job)}; }
private:
    std::atomic<unsigned> pending_{0};
    trantor::ConcurrentTaskQueue queue_;
};
}
