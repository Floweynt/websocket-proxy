project('websockproxy', 'cpp', default_options: ['cpp_std=c++20'], version: '0.0.1')

websocketpp_dep = dependency('websocketpp')
fmt_dep = dependency('fmt')

sources = [
   'src/logging.cpp',
   'src/protocol.cpp',
   'src/signal_init.cpp'
]

inc_dirs = [
  'include/',
  'deps/argparse/include/',
  'deps/magic_enum/include/'
]

conf_data = configuration_data()
conf_data.set('VERSION', '0.0.1')
conf_data.set('API_VERSION', '1.0.0')
conf_data.set('MESON_CXX_COMPILER', meson.get_compiler('cpp').get_id())
conf_data.set('CLIENT_PORT', '19293')

configure_file(input: 'build_config.h.in', output: 'build_config.h', configuration : conf_data)

executable('proxy-client', [sources, 'src/client.cpp'], include_directories: include_directories(inc_dirs), dependencies: [websocketpp_dep, fmt_dep])
executable('proxy-server', [sources, 'src/server.cpp'], include_directories: include_directories(inc_dirs), dependencies: [websocketpp_dep, fmt_dep])
