cmake_minimum_required(VERSION 3.0)
project(srp VERSION 0.0.1)

find_package(Lua REQUIRED)
find_package(OpenSSL REQUIRED)

include(GNUInstallDirs)

include_directories(${LUA_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} src/include)

string(REGEX MATCH "[0-9]+" SOVERSION ${CMAKE_PROJECT_VERSION})

add_subdirectory(src)
