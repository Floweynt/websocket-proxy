#pragma once

#include <csignal>
#include <functional>

void add_cpp_signal_handler(int sig,  std::function<void(int)> handler);
