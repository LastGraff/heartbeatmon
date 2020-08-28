cmake_minimum_required(VERSION 3.0)

project(heartbeat)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lzmq -pthread -lcrypto -lssl")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(PkgConfig)
pkg_check_modules(PC_ZeroMQ QUIET zmq)
find_path(ZeroMQ_INCLUDE_DIR
        NAMES zmq.hpp
        PATHS ${PC_ZeroMQ_INCLUDE_DIRS}
        )
find_library(ZeroMQ_LIBRARY
        NAMES libzmq.a
        PATHS ${PC_ZeroMQ_LIBRARY_DIRS}
        )

find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIR})

add_executable(heartbeat_server server.cpp
                                ecdsa.cpp)
add_executable(heartbeat_client client.cpp
                                ecdsa.cpp)

