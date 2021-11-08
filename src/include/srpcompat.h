#ifndef _srp_compat_h
#define _srp_compat_h 1

#if LUA_VERSION_NUM < 502
  #define luaL_newlib(L, m) \
    (lua_newtable(L), luaL_register(L, NULL, m))
#endif

#if !defined LUA_VERSION_NUM || LUA_VERSION_NUM==501
void luaL_setfuncs (lua_State *L, const luaL_Reg *l, int nup);
#endif

#endif
