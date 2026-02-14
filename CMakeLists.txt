cmake_minimum_required(VERSION 3.10)
project(SentinelNet)

set(CMAKE_CXX_STANDARD 17)

set(NPCAP_SDK "C:/npcap-sdk")
include_directories(${NPCAP_SDK}/Include)
link_directories(${NPCAP_SDK}/Lib/x64)

include_directories(include)

add_executable(SentinelNet
    src/scanner.cpp
    src/detection.cpp
    src/server.cpp
    src/logger.cpp
    src/cli.cpp
    src/network_utils.cpp
    src/main.cpp
    src/packet_monitor.cpp
)

target_link_libraries(SentinelNet ws2_32 iphlpapi wpcap Packet)

if(MINGW)
    target_link_options(SentinelNet PRIVATE "-static-libgcc" "-static-libstdc++" "-static")
endif()