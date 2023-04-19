#include "protocol.h"
#include "build_config.h"
#include "logging.h"
#include "magic_enum.hpp"
#include <boost/asio/ip/address_v4.hpp>
#include <fmt/core.h>
#include <linux/netfilter_ipv4.h>
#include <stdexcept>

class packet_reader_exception : public std::runtime_error
{
public:
    packet_reader_exception() : std::runtime_error("packet buffer exhausted"){};
};

void packet_reader::read_bytes(std::size_t bytes, uint8_t* ptr)
{
    if (index + bytes > data.size())
    {
        throw packet_reader_exception();
    }

    memcpy(ptr, data.data() + index, bytes);
    index += bytes;
}

static auto get_original_address(int sock_fd) -> std::pair<uint32_t, uint16_t>
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    socklen_t addr_sz = sizeof(addr);
    getsockopt(sock_fd, SOL_IP, SO_ORIGINAL_DST, &addr, &addr_sz);
    return {ntohl(addr.sin_addr.s_addr), ntohs(addr.sin_port)};
}

void protocol_client::register_handlers(std::function<void(s2c_con_tcp_ipv4_ack_packet)> handle_s2c_con_tcp_ipv4_ack,
                                        std::function<void(duplex_close_connection_packet)> handle_duplex_close_connection,
                                        std::function<void(duplex_tcp_send_data_packet)> handle_duplex_tcp_send_data)
{
    ws_socket.set_message_handler([handle_s2c_con_tcp_ipv4_ack = std::move(handle_s2c_con_tcp_ipv4_ack),
                                   handle_duplex_close_connection = std::move(handle_duplex_close_connection),
                                   handle_duplex_tcp_send_data = std::move(handle_duplex_tcp_send_data),
                                   this](const websocketpp::connection_hdl& /*hdl*/, const websocketpp::config::asio_client::message_type::ptr& msg) {
        packet_reader reader(std::span<uint8_t>((uint8_t*)msg->get_raw_payload().data(), msg->get_raw_payload().size()));

        try
        {
            auto packet_kind = reader.read_u8();
            switch ((packet_type)packet_kind)
            {
            case packet_type::S2C_NEW_TCP_CONNECTION_ACK_PACKET:
                handle_s2c_con_tcp_ipv4_ack(s2c_con_tcp_ipv4_ack_packet::read(reader));
                break;
            case packet_type::DUPLEX_CLOSE_CONNECTION:
                handle_duplex_close_connection(duplex_close_connection_packet::read(reader));
                break;
            case packet_type::DUPLEX_TCP_SEND_DATA_PACKET:
                handle_duplex_tcp_send_data(duplex_tcp_send_data_packet::read(reader));
                break;
            case packet_type::ERR_DUPLEX_BAD_PACKET_PACKET: {
                auto [kind, offending_id] = err_duplex_bad_packet_packet::read(reader);
                warn("protocol_client::on_message", fmt::format("received bad packet error: {} (id={})", magic_enum::enum_name(kind), offending_id));
            }
            case packet_type::ERR_DUPLEX_GENERIC_PACKET: {
                auto [kind, msg] = err_duplex_generic_packet::read(reader);
                warn("protocol_client::on_message", fmt::format("received error ({}): {}", magic_enum::enum_name(kind), msg));
            }
            default: {
                warn("protocol_client::on_message",
                     fmt::format("received bad packet (id={}, type={})", packet_kind, magic_enum::enum_name((packet_type)packet_kind)));
                err_duplex_bad_packet_packet::error_kind kind;

                if (!(packet_kind & 0b0010'0000)) // the server is not allowed to send type of packets
                {
                    kind = err_duplex_bad_packet_packet::ERR_BAD_DIRECTION;
                }
                else
                {
                    kind = err_duplex_bad_packet_packet::ERR_BAD_PACKET_ID;
                }

                write_packet(err_duplex_bad_packet_packet{kind, packet_kind});
            }
            }
        }
        catch (packet_reader_exception&)
        {
            warn("protocol_client::on_message", fmt::format("failed to parse packet: packet buffer exhausted"));
            write_packet(err_duplex_bad_packet_packet{err_duplex_bad_packet_packet::ERR_BAD_PACKET_DATA, 0});
        }
    });
}

void protocol_client::start(const std::string& uri)
{
    ws_socket.init_asio();
    ws_socket.clear_access_channels(websocketpp::log::alevel::frame_header);
    ws_socket.clear_access_channels(websocketpp::log::alevel::frame_payload);

    asio::error_code errc;
    auto con = ws_socket.get_connection(uri, errc);

    if (errc.failed())
    {
        fatal("client", fmt::format("failed to open websocket to host '{}': {}'", uri, errc.message()));
    }

    connection = con->get_handle();
    ws_socket.connect(con);
}

void protocol_client::close()
{
    asio::error_code errc;
    ws_socket.close(connection, websocketpp::close::status::normal, "channel closed do to client stopping", errc);
    if (errc.failed())
    {
        error("proxy_client", fmt::format("failed to close client: {}", errc.message()));
    }
}

void client_channel::setup()
{
    auto [ip, port] = get_original_address(socket.native_handle());
    debug0("client_channel::setup", fmt::format("(chan={}) forwarding {}:{} -> websocket", id, boost::asio::ip::address_v4(ip).to_string(), port));
    ws_io.write_packet(c2s_con_tcp_ipv4_packet{id, ip, port});
}

void client_channel::on_s2c_con_tcp_ipv4_ack(const s2c_con_tcp_ipv4_ack_packet& packet)
{
    if (!packet.success)
    {
        debug0("client_channel::s2c_con_tcp_ipv4_ack", fmt::format("(chan={}) server has failed to established connection", id));
        hook_channel_close();
        force_close();
        return;
    }

    debug0("client_channel::s2c_con_tcp_ipv4_ack", fmt::format("(chan={}) server has established connection", id));
    start_read();
}

void client_channel::hook_channel_close()
{
    proxy_client.context->post([&proxy_client = proxy_client, id = id]() { proxy_client.id_to_channel.erase(id); });
}

void proxy_client::on_s2c_con_tcp_ipv4_ack(const s2c_con_tcp_ipv4_ack_packet& packet)
{
    if (!id_to_channel.contains(packet.id))
    {
        warn("proxy_client::s2c_con_tcp_ipv4_ack", fmt::format("invalid channel {}", packet.id));
        return;
    }

    id_to_channel[packet.id]->on_s2c_con_tcp_ipv4_ack(packet);
}

void proxy_client::on_duplex_tcp_send_data(const duplex_tcp_send_data_packet& packet)
{
    if (!id_to_channel.contains(packet.id))
    {
        warn("proxy_client::duplex_tcp_send_data", fmt::format("invalid channel {}", packet.id));
        return;
    }

    id_to_channel[packet.id]->on_duplex_tcp_send_data(packet);
}

void proxy_client::on_duplex_close_connection(const duplex_close_connection_packet& packet)
{
    if (!id_to_channel.contains(packet.id))
    {
        warn("proxy_client::duplex_close_connection", fmt::format("invalid channel {}", packet.id));
        return;
    }

    id_to_channel[packet.id]->on_duplex_close_connection(packet);
    id_to_channel.erase(packet.id);
}

void proxy_client::init_channel(tcp::socket peer)
{
    debug0("proxy_client::init_channel", fmt::format("creating channel {}", curr_channel_id));
    auto& channel = (id_to_channel[curr_channel_id] = client_channel::create(*this, curr_channel_id, std::move(peer), client));
    channel->setup();
    curr_channel_id++;
}

void proxy_client::start_accepting()
{
    acceptor->async_accept(*context, [this](const asio::error_code& errc, tcp::socket peer) {
        debug0("proxy_client::start_accepting", "accepting new socket");
        if (errc.failed())
        {
            if (!acceptor->is_open())
            {
                return;
            }

            error("accept", fmt::format("failed to accept: {}", errc.message()));
        }

        init_channel(std::move(peer));
        start_accepting();
    });
}

void proxy_client::start(const std::string& uri)
{
    client.register_handlers([this](const s2c_con_tcp_ipv4_ack_packet& packet) { on_s2c_con_tcp_ipv4_ack(packet); },
                             [this](const duplex_close_connection_packet& packet) { on_duplex_close_connection(packet); },
                             [this](const duplex_tcp_send_data_packet& packet) { on_duplex_tcp_send_data(packet); });

    client.get_ws_socket().set_fail_handler([this](const websocketpp::connection_hdl& /*connection*/) { stop_everything_and_clean_up(); });
    client.get_ws_socket().set_close_handler([this](const websocketpp::connection_hdl& /*connection*/) { stop_everything_and_clean_up(); });

    client.start(uri);
    context = &client.get_ws_socket().get_io_service();
    acceptor = std::make_unique<tcp::acceptor>(*context);
    acceptor->open(asio::ip::tcp::v4());
    acceptor->bind(tcp::endpoint(ip::address_v4::from_string("127.0.0.1"), PORT));
    acceptor->listen();
    start_accepting();

    client.get_ws_socket().run();
}

void proxy_client::stop_everything_and_clean_up()
{
    log("proxy_client", "stopping forcibly");
    for (const auto& sock : id_to_channel)
    {
        sock.second->get_socket().close();
    }

    client.get_ws_socket().get_io_service().stop();
}

void proxy_client::stop()
{
    log("proxy_client", "stopping");
    for (const auto& sock : id_to_channel)
    {
        sock.second->close_channel();
    }

    client.close();
    acceptor->close();
}

void protocol_server::register_handlers(std::function<void(c2s_con_tcp_ipv4_packet)> handle_c2s_con_tcp_ipv4,
                                        std::function<void(duplex_close_connection_packet)> handle_duplex_close_connection,
                                        std::function<void(duplex_tcp_send_data_packet)> handle_duplex_tcp_send_data)
{
    handler = [handle_c2s_con_tcp_ipv4 = std::move(handle_c2s_con_tcp_ipv4), handle_duplex_tcp_send_data = std::move(handle_duplex_tcp_send_data),
               handle_duplex_close_connection = std::move(handle_duplex_close_connection),
               this](const websocketpp::config::asio_client::message_type::ptr& msg) {
        packet_reader reader(std::span<uint8_t>((uint8_t*)msg->get_raw_payload().data(), msg->get_raw_payload().size()));

        try
        {
            auto packet_kind = reader.read_u8();
            switch ((packet_type)packet_kind)
            {
            case packet_type::C2S_NEW_TCP_CONNECTION_PACKET:
                handle_c2s_con_tcp_ipv4(c2s_con_tcp_ipv4_packet::read(reader));
                break;
            case packet_type::DUPLEX_CLOSE_CONNECTION:
                handle_duplex_close_connection(duplex_close_connection_packet::read(reader));
                break;
            case packet_type::DUPLEX_TCP_SEND_DATA_PACKET:
                handle_duplex_tcp_send_data(duplex_tcp_send_data_packet::read(reader));
                break;
            case packet_type::ERR_DUPLEX_BAD_PACKET_PACKET: {
                auto [kind, offending_id] = err_duplex_bad_packet_packet::read(reader);
                warn("protocol_server::on_message", fmt::format("received bad packet error: {} (id={})", magic_enum::enum_name(kind), offending_id));
            }
            case packet_type::ERR_DUPLEX_GENERIC_PACKET: {
                auto [kind, msg] = err_duplex_generic_packet::read(reader);
                warn("protocol_server::on_message", fmt::format("received error ({}): {}", magic_enum::enum_name(kind), msg));
            }
            default: {
                warn("protocol_server::on_message",
                     fmt::format("received bad packet (id={}, type={})", packet_kind, magic_enum::enum_name((packet_type)packet_kind)));
                err_duplex_bad_packet_packet::error_kind kind;

                if (!(packet_kind & 0b0001'0000)) // the server is not allowed to send type of packets
                {
                    kind = err_duplex_bad_packet_packet::ERR_BAD_DIRECTION;
                }
                else
                {
                    kind = err_duplex_bad_packet_packet::ERR_BAD_PACKET_ID;
                }

                write_packet(err_duplex_bad_packet_packet{kind, packet_kind});
            }
            }
        }
        catch (packet_reader_exception&)
        {
            warn("protocol_server::on_message", fmt::format("failed to parse packet: packet buffer exhausted"));
            write_packet(err_duplex_bad_packet_packet{err_duplex_bad_packet_packet::ERR_BAD_PACKET_DATA, 0});
        }
    };
}

void server_channel::setup() { start_read(); }

void server_channel::hook_channel_close() {}

void proxy_server_instance::on_c2s_con_tcp_ipv4(const c2s_con_tcp_ipv4_packet& packet)
{
    auto socket = std::make_shared<tcp::socket>(*context);

    debug0("c2s_con_tcp_ipv4", fmt::format("(chan={}) connecting to {}:{}", packet.id, ip::address_v4(packet.id).to_string(), packet.port));

    socket->async_connect(tcp::endpoint(ip::address_v4(packet.id), packet.port), [this, packet, socket](const asio::error_code& errc) {
        if (errc.failed())
        {
            debug0("c2s_con_tcp_ipv4", fmt::format("(chan={}) failed to create channel: {}", packet.id, errc.message()));
            server.write_packet(s2c_con_tcp_ipv4_ack_packet{packet.id, false});
            return;
        }

        auto& channel = (id_to_channel[packet.id] = server_channel::create(packet.id, std::move(*socket), server));
        channel->setup();
        server.write_packet(s2c_con_tcp_ipv4_ack_packet{packet.id, true});
    });
}

void proxy_server_instance::start()
{
    server.register_handlers([this](const c2s_con_tcp_ipv4_packet& packet) { on_c2s_con_tcp_ipv4(packet); },
                             [this](const duplex_close_connection_packet& packet) { on_duplex_close_connection(packet); },
                             [this](const duplex_tcp_send_data_packet& packet) { on_duplex_tcp_send_data(packet); });
}

void proxy_server_instance::on_duplex_tcp_send_data(const duplex_tcp_send_data_packet& packet)
{
    if (!id_to_channel.contains(packet.id))
    {
        warn("proxy_server::duplex_tcp_send_data", fmt::format("invalid channel {}", packet.id));
        return;
    }

    id_to_channel[packet.id]->on_duplex_tcp_send_data(packet);
}

void proxy_server_instance::on_duplex_close_connection(const duplex_close_connection_packet& packet)
{
    if (!id_to_channel.contains(packet.id))
    {
        warn("proxy_server::duplex_close_connection", fmt::format("invalid channel {}", packet.id));
        return;
    }

    id_to_channel[packet.id]->on_duplex_close_connection(packet);
}

void proxy_server::start(uint16_t port)
{
    server.init_asio();
    server.clear_access_channels(websocketpp::log::alevel::frame_header);
    server.clear_access_channels(websocketpp::log::alevel::frame_payload);

    // Register a connection handler
    server.set_open_handler([this](const websocketpp::connection_hdl& hdl) {
        auto server_inst = proxy_server_instance::create(server, hdl);
        server_inst->start();
        auto con = server.get_con_from_hdl(hdl);
        con->id = curr_id++;
        con->set_message_handler(
            [weak_ref = server_inst->weak_from_this()](const websocketpp::connection_hdl& hdl, const websocket_server::message_ptr& msg) {
                if (weak_ref.use_count() == 0)
                {
                    return;
                }

                weak_ref.lock()->get_server().on_message(msg);
            });

        connection_to_server[con->id] = std::move(server_inst);
    });

    server.set_close_handler([this](const websocketpp::connection_hdl& hdl) { connection_to_server.erase(server.get_con_from_hdl(hdl)->id); });

    server.listen(port);
    server.start_accept();
    server.run();
}

void proxy_server::stop_everything_and_clean_up()
{
    log("proxy_server", "stopping forcibly");
    server.get_io_service().stop();
}

void proxy_server::stop()
{
    log("proxy_server", "stopping");
    server.stop();
}

