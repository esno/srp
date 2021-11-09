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

set(LUA_INSTALL_DATADIR ${CMAKE_INSTALL_DATADIR}/lua/${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR})
set(LUA_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR}/lua/${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR})

install(TARGETS bignum DESTINATION ${LUA_INSTALL_LIBDIR})
install(TARGETS hash DESTINATION ${LUA_INSTALL_LIBDIR})
install(FILES srp.lua DESTINATION ${LUA_INSTALL_DATADIR})

install(FILES wowpasswd.lua
  PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE
  DESTINATION ${CMAKE_INSTALL_BINDIR}
  RENAME wowpasswd)