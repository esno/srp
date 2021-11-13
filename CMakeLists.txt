cmake_minimum_required(VERSION 3.0)
project(srp VERSION 0.0.1)

if (LUA54)
  find_package(Lua 5.4 EXACT REQUIRED)
elseif (LUA53)
  find_package(Lua 5.3 EXACT REQUIRED)
elseif (LUA52)
  find_package(Lua 5.2 EXACT REQUIRED)
elseif (LUA51)
  find_package(Lua 5.1 EXACT REQUIRED)
else ()
  find_package(Lua REQUIRED)
endif ()

find_package(OpenSSL REQUIRED)

include(GNUInstallDirs)

include_directories(${LUA_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} src/include)

string(REGEX MATCH "[0-9]+" SOVERSION ${CMAKE_PROJECT_VERSION})

add_subdirectory(src)
