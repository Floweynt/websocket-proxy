#pragma once

#include "logging.h"
#include <boost/asio/error.hpp>
#include <boost/asio/socket_base.hpp>
#include <cstdint>
#include <fmt/core.h>
#include <memory>
#include <span>
#include <utility>
#include <websocketpp/close.hpp>
#include <websocketpp/common/connection_hdl.hpp>
#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/roles/client_endpoint.hpp>
#include <websocketpp/server.hpp>

class packet_reader
{
    std::span<const uint8_t> data;
    size_t index;

    void read_bytes(std::size_t bytes, uint8_t* ptr);

    template <typename T>
    auto read_ty()
    {
        T val;
        read_bytes(sizeof(T), (uint8_t*)&val);
        return val;
    }

public:
    constexpr packet_reader(std::span<uint8_t> data) : data(data), index(0) {}

    inline auto read_u8() -> uint8_t { return read_ty<uint8_t>(); }
    inline auto read_u16() -> uint16_t { return read_ty<uint16_t>(); }
    inline auto read_u32() -> uint32_t { return read_ty<uint32_t>(); }
    inline auto read_u64() -> uint64_t { return read_ty<uint64_t>(); }
    inline auto read_i8() -> int8_t { return read_ty<int8_t>(); }
    inline auto read_i16() -> int16_t { return read_ty<int16_t>(); }
    inline auto read_i32() -> int32_t { return read_ty<int32_t>(); }
    inline auto read_i64() -> int64_t { return read_ty<int64_t>(); }
    inline auto read_bytes(uint64_t size) -> std::vector<uint8_t>
    {
        std::vector<uint8_t> buf(size);
        read_bytes(size, buf.data());
        return buf;
    }

    inline auto read_string()
    {
        size_t size = read_u64();
        std::string buf(size, '\0');
        read_bytes(size, (uint8_t*)buf.data());
        return buf;
    }
};

class packet_writer
{
    std::vector<uint8_t>& data;

    inline void write_bytes(std::size_t bytes, const uint8_t* ptr) { data.insert(data.end(), ptr, ptr + bytes); }

    template <typename T>
    auto write_ty(T val)
    {
        write_bytes(sizeof(T), (uint8_t*)&val);
    }

public:
    constexpr packet_writer(std::vector<uint8_t>& data) : data(data) {}

    inline void write_u8(uint8_t val) { write_ty(val); }
    inline void write_u16(uint16_t val) { write_ty(val); }
    inline void write_u32(uint32_t val) { write_ty(val); }
    inline void write_u64(uint64_t val) { write_ty(val); }
    inline void write_i8(int8_t val) { write_ty(val); }
    inline void write_i16(int16_t val) { write_ty(val); }
    inline void write_i32(int32_t val) { write_ty(val); }
    inline void write_i64(int64_t val) { write_ty(val); }
    inline void write_bytes(const std::span<const uint8_t>& data) { write_bytes(data.size(), data.data()); }
    inline void write_string(const std::string& str)
    {
        write_u64(str.size());
        write_bytes(str.size(), (const uint8_t*)str.data());
    }
};

// Byte       1
// Bit 0 1 2 3 4 5 6 7
//     T T S C X X X X
// T T = type
//     - 0 0 -> normal
//     - 0 1 -> handshake
//     - 1 0 -> error
//     - 1 1 -> special_ctrl
// S = is_server_to_client
// C = is_client_to_server
// X = unique id
enum class packet_type : uint8_t
{
    // handeshake
    HANDSHAKE_C2S_HELLO_PACKET = 0b0101'0000,
    HANDSHAKE_S2C_HI_PACKET = 0b0110'0000,
    HANDSHAKE_C2S_CREDENTIALS_PACKET = 0b0101'0001,
    HANDSHAKE_S2C_AUTHENTICATED_PACKET = 0b0110'0001,

    // actual protocol
    C2S_NEW_TCP_CONNECTION_PACKET = 0b0001'0000,
    S2C_NEW_TCP_CONNECTION_ACK_PACKET = 0b0010'0000,
    DUPLEX_TCP_SEND_DATA_PACKET = 0b0011'0000,
    DUPLEX_CLOSE_CONNECTION = 0b0011'0001,

    // errors
    ERR_S2C_AUTHENTICATION_PACKET = 0b1010'0000,
    ERR_S2C_API_VERSION_PACKET = 0b1001'0000,
    ERR_DUPLEX_GENERIC_PACKET = 0b1011'0000,
    ERR_DUPLEX_BAD_PACKET_PACKET = 0b1011'1111,
};

template <typename T, packet_type K>
struct trivial_packet
{
    inline static auto read(packet_reader& /*reader*/) -> T { return {}; }
    inline void write(packet_writer& writer) const {}
    inline static constexpr packet_type TYPE = K;
};

// handshake packets
struct handshake_c2s_hello_packet
{
    std::string client;
    std::string api_version;

    inline static auto read(packet_reader& reader) -> handshake_c2s_hello_packet { return {reader.read_string(), reader.read_string()}; }
    inline void write(packet_writer& writer) const
    {
        writer.write_string(client);
        writer.write_string(api_version);
    }

    inline static constexpr packet_type TYPE = packet_type::HANDSHAKE_C2S_HELLO_PACKET;
};

struct handshake_s2c_hi_packet
{
    std::string server;

    inline static auto read(packet_reader& reader) -> handshake_s2c_hi_packet { return {reader.read_string()}; }
    inline void write(packet_writer& writer) const { writer.write_string(server); }
    inline static constexpr packet_type TYPE = packet_type::HANDSHAKE_S2C_HI_PACKET;
};

struct handshake_c2s_credentials_packet
{
    std::string user;
    uint64_t auth_value;

    inline static auto read(packet_reader& reader) -> handshake_c2s_credentials_packet { return {reader.read_string(), reader.read_u64()}; }
    inline void write(packet_writer& writer) const
    {
        writer.write_string(user);
        writer.write_u64(auth_value);
    }

    inline static constexpr packet_type TYPE = packet_type::HANDSHAKE_C2S_CREDENTIALS_PACKET;
};

struct handshake_s2c_authenticated_packet : trivial_packet<handshake_s2c_authenticated_packet, packet_type::HANDSHAKE_S2C_AUTHENTICATED_PACKET>
{
};

// protocol packets
struct c2s_con_tcp_ipv4_packet
{
    uint64_t id;
    uint32_t ip;
    uint16_t port;

    inline static auto read(packet_reader& reader) -> c2s_con_tcp_ipv4_packet { return {reader.read_u64(), reader.read_u32(), reader.read_u16()}; }

    inline void write(packet_writer& writer) const
    {
        writer.write_u64(id);
        writer.write_u32(ip);
        writer.write_u16(port);
    }

    inline static constexpr packet_type TYPE = packet_type::C2S_NEW_TCP_CONNECTION_PACKET;
};

struct s2c_con_tcp_ipv4_ack_packet
{
    uint64_t id;
    bool success;

    inline static auto read(packet_reader& reader) -> s2c_con_tcp_ipv4_ack_packet { return {reader.read_u64(), static_cast<bool>(reader.read_u8())}; }
    inline void write(packet_writer& writer) const
    {
        writer.write_u64(id);
        writer.write_u8(static_cast<uint8_t>(success));
    }
    inline static constexpr packet_type TYPE = packet_type::S2C_NEW_TCP_CONNECTION_ACK_PACKET;
};

struct duplex_tcp_send_data_packet
{
    uint64_t id;
    std::vector<uint8_t> data;

    inline static auto read(packet_reader& reader) -> duplex_tcp_send_data_packet
    {
        return {reader.read_u64(), reader.read_bytes(reader.read_u64())};
    }

    inline void write(packet_writer& writer) const
    {
        writer.write_u64(id);
        writer.write_u64(data.size());
        writer.write_bytes(data);
    }

    inline static constexpr packet_type TYPE = packet_type::DUPLEX_TCP_SEND_DATA_PACKET;
};

struct duplex_close_connection_packet
{
    uint64_t id;

    inline static auto read(packet_reader& reader) -> duplex_close_connection_packet { return {reader.read_u64()}; }
    inline void write(packet_writer& writer) const { writer.write_u64(id); }
    inline static constexpr packet_type TYPE = packet_type::DUPLEX_CLOSE_CONNECTION;
};

// error packets
struct err_s2c_authentication_packet : trivial_packet<err_s2c_authentication_packet, packet_type::HANDSHAKE_S2C_AUTHENTICATED_PACKET>
{
};

struct err_s2c_api_version_packet : trivial_packet<err_s2c_api_version_packet, packet_type::ERR_S2C_API_VERSION_PACKET>
{
};

struct err_duplex_generic_packet
{
    enum error_kind : uint8_t
    {
        ERR_CUSTOM = 0xff
    } error;

    std::string message;

    inline static auto read(packet_reader& reader) -> err_duplex_generic_packet { return {(error_kind)reader.read_u8(), reader.read_string()}; }
    inline void write(packet_writer& writer) const
    {
        writer.write_u8(error);
        writer.write_string(message);
    }
    inline static constexpr packet_type TYPE = packet_type::ERR_DUPLEX_GENERIC_PACKET;
};

struct err_duplex_bad_packet_packet
{
    enum error_kind : uint8_t
    {
        ERR_BAD_DIRECTION,
        ERR_BAD_PACKET_ID,
        ERR_BAD_PACKET_DATA,
    } error;

    uint8_t offending_id;

    inline static auto read(packet_reader& reader) -> err_duplex_bad_packet_packet { return {(error_kind)reader.read_u8(), reader.read_u8()}; }
    inline void write(packet_writer& writer) const
    {
        writer.write_u8(error);
        writer.write_u8(offending_id);
    }
    inline static constexpr packet_type TYPE = packet_type::ERR_DUPLEX_BAD_PACKET_PACKET;
};

#define implements_concept(type, concept) static_assert(concept<type>, "type '" #type "' does not implement concept '" #concept "'")

template <typename T>
concept protocol_packet = requires(const T& packet_ty, packet_reader& reader, packet_writer& writer) {
    {
        T::read(reader)
    } -> std::convertible_to<T>;
    {
        packet_ty.write(writer)
    } -> std::same_as<void>;
    {
        T::TYPE
    } -> std::convertible_to<packet_type>;
};

implements_concept(handshake_c2s_hello_packet, protocol_packet);
implements_concept(handshake_s2c_hi_packet, protocol_packet);
implements_concept(handshake_c2s_credentials_packet, protocol_packet);
implements_concept(handshake_s2c_authenticated_packet, protocol_packet);

implements_concept(c2s_con_tcp_ipv4_packet, protocol_packet);
implements_concept(s2c_con_tcp_ipv4_ack_packet, protocol_packet);
implements_concept(duplex_tcp_send_data_packet, protocol_packet);
implements_concept(duplex_close_connection_packet, protocol_packet);

implements_concept(err_s2c_authentication_packet, protocol_packet);
implements_concept(err_s2c_api_version_packet, protocol_packet);
implements_concept(err_duplex_generic_packet, protocol_packet);
implements_concept(err_duplex_bad_packet_packet, protocol_packet);

struct custom_logging_asio_config : public websocketpp::config::asio_client
{
    using elog_type = websocketpp::log::my_logger<concurrency_type, websocketpp::log::elevel>;
    using alog_type = websocketpp::log::my_logger<concurrency_type, websocketpp::log::alevel>;
};

struct custom_server_config : public custom_logging_asio_config
{
    using connection_base = struct
    {
        uint64_t id;
    };
};

namespace asio = websocketpp::lib::asio;
namespace ip = asio::ip;
using tcp = ip::tcp;
using websocket_client = websocketpp::client<custom_logging_asio_config>;
using websocket_server = websocketpp::server<custom_server_config>;

template <class T, class U>
auto weak_pointer_cast(std::weak_ptr<U> const& r) -> std::weak_ptr<T>
{
    return std::static_pointer_cast<T>(std::shared_ptr<U>(r));
}

template <typename T, typename Impl>
class base_channel
{
    inline static constexpr auto FRAME_SIZE = 65536;

protected:
    uint64_t id;
    T& ws_io;
    tcp::socket socket;
    std::vector<uint8_t> buffer;
    bool is_closed;

    void on_tcp_socket_data()
    {
        debug0("tcp_socket_data", fmt::format("(chan={}) read {} bytes", id, buffer.size()));
        duplex_tcp_send_data_packet packet{.id = id, .data = std::move(buffer)};
        ws_io.write_packet(packet);
        buffer = std::move(packet.data);
    }

    void start_read()
    {
        buffer.resize(FRAME_SIZE);
        std::weak_ptr<base_channel> weak_this = weak_pointer_cast<base_channel>(static_cast<Impl*>(this)->weak_from_this());
        socket.async_read_some(asio::buffer(buffer), [=](asio::error_code errc, std::size_t bytes_transferred) {
            if (weak_this.use_count() == 0 || !weak_this.lock()->socket.is_open())
            {
                return;
            }

            if (errc.failed())
            {
                if (errc == boost::asio::error::eof)
                {
                    weak_this.lock()->close_channel();
                    return;
                }

                warn("start_read", fmt::format("(chan={}) read failed: {}", weak_this.lock()->id, errc.message()));
                weak_this.lock()->close_channel();
                return;
            }

            weak_this.lock()->buffer.resize(bytes_transferred);
            weak_this.lock()->on_tcp_socket_data();
            weak_this.lock()->start_read();
        });
    }

public:
    base_channel(uint64_t id, tcp::socket socket, T& ws_io) : id(id), ws_io(ws_io), socket(std::move(socket)), is_closed(false){};

    constexpr auto get_socket() -> auto& { return socket; }
    [[nodiscard]] constexpr auto get_socket() const -> const auto& { return socket; }

    void on_duplex_tcp_send_data(const duplex_tcp_send_data_packet& packet)
    {
        debug0("tcp_send_data", fmt::format("(chan={}) recv data (size={}) fwd socket -> websocket", id, packet.data.size()));

        auto weak_this = weak_pointer_cast<base_channel>(static_cast<Impl*>(this)->weak_from_this());
        asio::async_write(socket, asio::buffer(buffer), [=](asio::error_code errc, std::size_t /*bytes_transferred*/) {
            if (weak_this.use_count() == 0)
            {
                return;
            }
            if (errc.failed())
            {
                warn("tcp_send_data", fmt::format("(chan={}) fwd socket -> websocket failed: {}", weak_this.lock()->id, errc.message()));
                weak_this.lock()->close_channel();
            }
        });
    }

    void on_duplex_close_connection(const duplex_close_connection_packet& /*packet*/)
    {
        debug0("close_connection", fmt::format("(chan={}) recv close request; closing channel", id));
        is_closed = true;

        asio::error_code errc;

        socket.shutdown(boost::asio::socket_base::shutdown_both, errc);
        if (errc.failed())
        {
            warn("close_connection", fmt::format("(chan={}) shutdown socketfailed: {}", id, errc.message()));
        }

        socket.close(errc);
        if (errc.failed())
        {
            warn("close_connection", fmt::format("(chan={}) closing socket failed: {}", id, errc.message()));
        }
    }

    void close_channel()
    {
        if (is_closed)
        {
            warn("close_channel", fmt::format("(chan={}) channel is already closed", id));
            return;
        }

        is_closed = true;
        debug0("close_channel", fmt::format("(chan={}) closing channel", id));
        static_cast<Impl*>(this)->hook_channel_close();
        force_close();
        ws_io.write_packet(duplex_close_connection_packet{.id = id});
    }

    void force_close()
    {
        if (socket.is_open())
        {
            asio::error_code errc;
            socket.close(errc);

            if (errc.failed())
            {
                warn("close_channel", fmt::format("(chan={}) failed to close channel {}", id, errc.message()));
            }
        }
    }
};

class protocol_client
{
    websocket_client ws_socket;
    websocketpp::connection_hdl connection;
    std::vector<uint8_t> write_buffer;

public:
    protocol_client() = default;

    void start(const std::string& uri);
    void write_packet(const protocol_packet auto& packet)
    {
        write_buffer.clear();
        packet_writer writer(write_buffer);

        writer.write_u8((uint8_t)std::decay_t<decltype(packet)>::TYPE);
        packet.write(writer);

        ws_socket.send(connection, write_buffer.data(), write_buffer.size(), websocketpp::frame::opcode::binary);
    }

    void close();
    void register_handlers(std::function<void(s2c_con_tcp_ipv4_ack_packet)> handle_s2c_con_tcp_ipv4_ack,
                           std::function<void(duplex_close_connection_packet)> handle_duplex_close_connection,
                           std::function<void(duplex_tcp_send_data_packet)> handle_duplex_tcp_send_data);
    constexpr auto get_ws_socket() -> auto& { return ws_socket; }
    constexpr auto get_ws_socket() const -> const auto& { return ws_socket; }
};

class proxy_client;
class client_channel : public base_channel<protocol_client, client_channel>, public std::enable_shared_from_this<client_channel>
{
    proxy_client& proxy_client;

    inline client_channel(class proxy_client& proxy_client, uint64_t id, tcp::socket socket, protocol_client& ws_client)
        : base_channel(id, std::move(socket), ws_client), proxy_client(proxy_client)
    {
    }

public:
    [[nodiscard]] static inline auto create(class proxy_client& proxy_client, uint64_t id, tcp::socket socket, protocol_client& ws_client)
        -> std::shared_ptr<client_channel>
    {
        return std::shared_ptr<client_channel>(new client_channel(proxy_client, id, std::move(socket), ws_client));
    }

    void setup();
    void on_s2c_con_tcp_ipv4_ack(const s2c_con_tcp_ipv4_ack_packet& /*packet*/);
    void close();
    void hook_channel_close();
};

class proxy_client
{
    friend class client_channel;

    protocol_client client;
    std::unordered_map<uint64_t, std::shared_ptr<client_channel>> id_to_channel;
    uint64_t curr_channel_id{};

    boost::asio::io_context* context{};
    std::unique_ptr<tcp::acceptor> acceptor;

    void on_s2c_con_tcp_ipv4_ack(const s2c_con_tcp_ipv4_ack_packet& packet);
    void on_duplex_tcp_send_data(const duplex_tcp_send_data_packet& packet);
    void on_duplex_close_connection(const duplex_close_connection_packet& packet);
    void init_channel(tcp::socket peer);
    void start_accepting();

public:
    proxy_client() = default;

    void start(const std::string& uri);
    void stop_everything_and_clean_up();
    void stop();

    constexpr auto get_client() -> auto& { return client; }
    constexpr auto get_client() const -> const auto& { return client; }
};

class protocol_server
{
    websocket_server& ws_socket;
    websocketpp::connection_hdl connection;
    std::vector<uint8_t> write_buffer;

    std::function<void(const websocketpp::config::asio_client::message_type::ptr&)> handler;

public:
    protocol_server(websocket_server& ws_socket, websocketpp::connection_hdl hdl) : ws_socket(ws_socket), connection(std::move(hdl)) {}

    void write_packet(const protocol_packet auto& packet)
    {
        write_buffer.clear();
        packet_writer writer(write_buffer);

        writer.write_u8((uint8_t)std::decay_t<decltype(packet)>::TYPE);
        packet.write(writer);

        ws_socket.send(connection, write_buffer.data(), write_buffer.size(), websocketpp::frame::opcode::binary);
    }

    void register_handlers(std::function<void(c2s_con_tcp_ipv4_packet)> handle_c2s_con_tcp_ipv4,
                           std::function<void(duplex_close_connection_packet)> handle_duplex_close_connection,
                           std::function<void(duplex_tcp_send_data_packet)> handle_duplex_tcp_send_data);

    inline void on_message(const websocketpp::config::asio_client::message_type::ptr& msg) { handler(msg); }

    constexpr auto get_ws_socket() -> auto& { return ws_socket; }
    [[nodiscard]] constexpr auto get_ws_socket() const -> const auto& { return ws_socket; }
};

class server_channel : public base_channel<protocol_server, server_channel>, public std::enable_shared_from_this<server_channel>
{
    inline server_channel(uint64_t id, tcp::socket socket, protocol_server& ws_server) : base_channel(id, std::move(socket), ws_server) {}

public:
    [[nodiscard]] static inline auto create(uint64_t id, tcp::socket socket, protocol_server& ws_server) -> std::shared_ptr<server_channel>
    {
        return std::shared_ptr<server_channel>(new server_channel(id, std::move(socket), ws_server));
    }

    void setup();
    void hook_channel_close();
};

class proxy_server_instance : public std::enable_shared_from_this<proxy_server_instance>
{
    protocol_server server;
    std::unordered_map<uint64_t, std::shared_ptr<server_channel>> id_to_channel;

    boost::asio::io_context* context;

    void on_c2s_con_tcp_ipv4(const c2s_con_tcp_ipv4_packet& packet);
    void on_duplex_tcp_send_data(const duplex_tcp_send_data_packet& packet);
    void on_duplex_close_connection(const duplex_close_connection_packet& packet);

    proxy_server_instance(websocket_server& ws_socket, websocketpp::connection_hdl hdl)
        : server(ws_socket, std::move(hdl)), context(&ws_socket.get_io_service())
    {
    }

public:
    [[nodiscard]] static inline auto create(websocket_server& ws_socket, websocketpp::connection_hdl hdl) -> std::shared_ptr<proxy_server_instance>
    {
        return std::shared_ptr<proxy_server_instance>(new proxy_server_instance(ws_socket, hdl));
    }

    void start();

    constexpr auto get_server() -> auto& { return server; }
    [[nodiscard]] constexpr auto get_server() const -> const auto& { return server; }
};

class proxy_server
{
    websocket_server server;
    std::unordered_map<uint64_t, std::shared_ptr<proxy_server_instance>> connection_to_server;
    uint64_t curr_id;

public:
    proxy_server() = default;
    void start(uint16_t port);
    void stop_everything_and_clean_up();
    void stop();
};
