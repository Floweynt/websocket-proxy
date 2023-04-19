#include "logging.h"
#include <fmt/core.h>
#include <iostream>

namespace
{
    int verbosity = 0;

    void log_impl(int level, const char* type, const std::string& name, const std::string& msg)
    {
        if (verbosity < level)
        {
            return;
        }

        std::cerr << fmt::format("[{}] {}: {}\n", type, name, msg);
    }
} // namespace

void fatal(const std::string& name, const std::string& msg)
{
    log_impl(-3, "fatal", name, msg);
    exit(-1);
}

void error(const std::string& name, const std::string& msg) { log_impl(-2, "error", name, msg); }
void warn(const std::string& name, const std::string& msg) { log_impl(-1, "warn", name, msg); }
void log(const std::string& name, const std::string& msg) { log_impl(-0, "log", name, msg); }
void debug0(const std::string& name, const std::string& msg) { log_impl(1, "debug0", name, msg); }
void debug1(const std::string& name, const std::string& msg) { log_impl(2, "debug1", name, msg); }
void debug2(const std::string& name, const std::string& msg) { log_impl(3, "debug2", name, msg); }
void debug3(const std::string& name, const std::string& msg) { log_impl(4, "debug3", name, msg); }

void set_verbosity(int value) { verbosity = value; }
