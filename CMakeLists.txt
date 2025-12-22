cmake_minimum_required(VERSION 3.10)
project(SentinelNet)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

add_executable(SentinelNet
    src/scanner.cpp
    src/detection.cpp
    src/simulation.cpp
    src/server.cpp
    src/logger.cpp
    src/cli.cpp
    src/main.cpp
)

if(WIN32)
    target_link_libraries(SentinelNet 
        ws2_32
        iphlpapi
    )

endif()