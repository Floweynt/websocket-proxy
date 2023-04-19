#include "argparse/argparse.hpp"
#include "build_config.h"
#include "logging.h"
#include "protocol.h"
#include "signal_util.h"
#include <iostream>

void prog_main(const std::string& uri)
{
    proxy_client client;
    log("main", "note: use ^C/ctrl-c to exit");
    add_cpp_signal_handler(SIGINT, [&client](int) {
        client.stop();
        exit(0);
    });

    add_cpp_signal_handler(SIGSEGV, [&client](int) { client.stop_everything_and_clean_up(); });

    client.start(uri);
}

auto main(int argc, char** argv) -> int
{
    argparse::ArgumentParser program(argv[0], VERSION);
    int verbosity = 0;

    program.add_argument("uri").help("proxy uri").required();

    program.add_argument("-V", "--verbose")
        .action([&](const auto&) { verbosity++; })
        .append()
        .help("increase output verbosity")
        .default_value(false)
        .implicit_value(true);

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
        std::cout << "websocket-proxy-client " VERSION;
        std::exit(0);
    }

    set_verbosity(verbosity);

    try
    {
        prog_main(program.get<std::string>("uri"));
    }
    catch (std::exception& e)
    {
        fatal("core", fmt::format("client received unhandled exception: {}", e.what()));
    }
}
