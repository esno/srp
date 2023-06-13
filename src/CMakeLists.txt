add_library(bignum MODULE bignum.c compat.c)

set_target_properties(bignum PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(bignum PROPERTIES SOVERSION ${SOVERSION})
set_target_properties(bignum PROPERTIES PREFIX "")

target_link_libraries(bignum ${OPENSSL_LIBRARIES})

add_library(hash MODULE hash.c compat.c)

set_target_properties(hash PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(hash PROPERTIES SOVERSION ${SOVERSION})
set_target_properties(hash PROPERTIES PREFIX "")

target_link_libraries(hash ${OPENSSL_LIBRARIES})

set(LUA_INSTALL_DATAROOTDIR ${CMAKE_INSTALL_DATAROOTDIR}/lua/${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}/wow CACHE STRING "lua module install path")
set(LUA_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR}/lua/${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR} CACHE STRING "lua c-module install path")

install(TARGETS bignum DESTINATION ${LUA_INSTALL_LIBDIR})
install(TARGETS hash DESTINATION ${LUA_INSTALL_LIBDIR})
install(DIRECTORY authcodes DESTINATION ${LUA_INSTALL_DATAROOTDIR})
install(DIRECTORY srp DESTINATION ${LUA_INSTALL_DATAROOTDIR})

install(FILES wowpasswd.lua
  PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE
  DESTINATION ${CMAKE_INSTALL_BINDIR}
  RENAME wowpasswd)
