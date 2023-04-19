#include "signal_util.h"
#include <cstdint>
#include <unordered_map>

namespace
{
    std::unordered_map<int, std::vector<std::function<void(int)>>> handlers;

    void handle_signal(int sig)
    {
        for (const auto& handler : handlers[sig])
        {
            handler(sig);
        }
    }
} // namespace

void add_cpp_signal_handler(int sig, std::function<void(int)> handler)
{
    auto old = signal(sig, handle_signal);
    if (old != handle_signal && old != nullptr)
    {
        handlers[sig].emplace_back(old);
    }

    handlers[sig].emplace_back(std::move(handler));
}

