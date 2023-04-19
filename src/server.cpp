#include "argparse/argparse.hpp"
#include "build_config.h"
#include "logging.h"
#include "protocol.h"
#include "signal_util.h"
#include <iostream>

void prog_main(int port)
{
    proxy_server server;
    log("main", "note: use ^C/ctrl-c to exit");
    add_cpp_signal_handler(SIGINT, [&server](int) {
        server.stop();
        exit(0);
    });

    add_cpp_signal_handler(SIGSEGV, [&](int) { server.stop_everything_and_clean_up(); });

    server.start(port);
}

auto main(int argc, char** argv) -> int
{
    argparse::ArgumentParser program(argv[0], VERSION);
    int verbosity = 0;

    program.add_argument("-V", "--verbose")
        .action([&](const auto&) { verbosity++; })
        .append()
        .help("increase output verbosity")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-p", "--port")
        .help("specifies the port to bind to");

    try
    {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    if (program["--help"] == true)
    {
        std::cout << program.help().str();
        std::exit(0);
    }

    if (program["--version"] == true)
    {
        std::cout << "websocket-proxy-server " VERSION;
        std::exit(0);
    }

    set_verbosity(verbosity);

    try
    {
        prog_main(std::stoi(program.present("-p") ? program.get<std::string>("-p") : "80"));
    }
    catch (std::exception& e)
    {
        fatal("core", fmt::format("server received unhandled exception: {}", e.what()));
    }
}

