cmake_minimum_required(VERSION 3.0)
project(srp VERSION 0.0.1)

if (LUA54)
  find_package(Lua 5.4 EXACT REQUIRED)
elseif (LUA53)
  find_package(Lua 5.3 EXACT REQUIRED)
else ()
  find_package(Lua REQUIRED)

  if (${LUA_VERSION_MAJOR} EQUAL 5 AND ${LUA_VERSION_MINOR} LESS 3)
    message(FATAL_ERROR "Lua supports required bitwise operations starting with lua 5.3")
  endif ()
endif ()

find_package(OpenSSL REQUIRED)

include(GNUInstallDirs)

include_directories(${LUA_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} src/include)

string(REGEX MATCH "[0-9]+" SOVERSION ${CMAKE_PROJECT_VERSION})

add_subdirectory(src)
