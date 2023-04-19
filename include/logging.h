#pragma once

#include <string>
#include <websocketpp/logger/basic.hpp>

void fatal(const std::string& name, const std::string& msg);
void error(const std::string& name, const std::string& msg);
void warn(const std::string& name, const std::string& msg);
void log(const std::string& name, const std::string& msg);
void debug0(const std::string& name, const std::string& msg);
void debug1(const std::string& name, const std::string& msg);
void debug2(const std::string& name, const std::string& msg);
void debug3(const std::string& name, const std::string& msg);
void set_verbosity(int value);

namespace websocketpp::log
{
    template <typename Concurrency, typename Names>
    class my_logger : public basic<Concurrency, Names>
    {
    public:
        using base = basic<Concurrency, Names>;

        my_logger(channel_type_hint::value hint = channel_type_hint::access) : basic<Concurrency, Names>(hint), m_channel_type_hint(hint) {}
        my_logger(level channels, channel_type_hint::value hint = channel_type_hint::access)
            : basic<Concurrency, Names>(channels, hint), m_channel_type_hint(hint)
        {
        }

        void write(level channel, const std::string& msg) { write(channel, msg.c_str()); }

        void write(level channel, char const* msg)
        {
            scoped_lock_type lock(base::m_lock);
            if (!this->dynamic_test(channel))
            {
                return;
            }

            if (m_channel_type_hint == channel_type_hint::access)
            {
                ::log("websocketpp", msg);
            }
            else
            {
                if (channel == elevel::devel)
                {
                    ::debug0("websocketpp", msg);
                }
                else if (channel == elevel::library)
                {
                    ::debug1("websocketpp", msg);
                }
                else if (channel == elevel::info)
                {
                    ::log("websocketpp", msg);
                }
                else if (channel == elevel::warn)
                {
                    ::warn("websocketpp", msg);
                }
                else if (channel == elevel::rerror)
                {
                    ::error("websocketpp", msg);
                }
                else if (channel == elevel::fatal)
                {

                    ::fatal("websocketpp", msg);
                }
            }
        }

    private:
        using scoped_lock_type = typename base::scoped_lock_type;
        channel_type_hint::value m_channel_type_hint;
    };

} // namespace websocketpp::log
