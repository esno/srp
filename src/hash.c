#include <string.h>

#include <lua.h>
#include <lauxlib.h>

#include <openssl/sha.h>
#include <openssl/crypto.h>

#define SRP_SHA1_MTABLE "sha1_mtable"

#include <srpcompat.h>

typedef struct {
  SHA_CTX shactx;
  unsigned char digest[SHA_DIGEST_LENGTH];
  int _init;
  int _final;
} hash_udata_t;

static int hash_sha1_final(lua_State *L) {
  hash_udata_t *udata = luaL_checkudata(L, 1, SRP_SHA1_MTABLE);

  if (udata->_init != 1) {
    lua_pushnil(L);
    return 1;
  }

  udata->_final = SHA1_Final(udata->digest, &udata->shactx);
  lua_pushboolean(L, 1);
  return 1;
}

static int hash_sha1_get_digest(lua_State *L) {
  hash_udata_t *udata = luaL_checkudata(L, 1, SRP_SHA1_MTABLE);

  if (udata->_final != 1) {
    lua_pushnil(L);
    return 1;
  }

  lua_pushlstring(L, udata->digest, SHA_DIGEST_LENGTH);
  lua_pushnumber(L, SHA_DIGEST_LENGTH);

  return 2;
}

static int hash_sha1_init(lua_State *L) {
  hash_udata_t *udata = lua_newuserdata(L, sizeof(hash_udata_t));

  memset(udata, 0, sizeof(hash_udata_t));
  udata->_init = SHA1_Init(&udata->shactx);

  luaL_getmetatable(L, SRP_SHA1_MTABLE);
  lua_setmetatable(L, -2);

  return 1;
}

static int hash_sha1_tostring(lua_State *L) {
  hash_udata_t *udata = luaL_checkudata(L, 1, SRP_SHA1_MTABLE);
  unsigned char digest[41];
  int i = 0;

  if (udata->_final != 1) {
    lua_pushnil(L);
    return 1;
  }

  memset(digest, 0, sizeof(unsigned char) * 41);
  for (i = 0; i < SHA_DIGEST_LENGTH; ++i)
    sprintf(&digest[i * 2], "%02x", udata->digest[i]);

  digest[40] = '\0';
  lua_pushstring(L, digest);

  return 1;
}

static int hash_sha1_update(lua_State *L) {
  int argc = lua_gettop(L);
  size_t n = 0;
  hash_udata_t *udata = luaL_checkudata(L, 1, SRP_SHA1_MTABLE);
  const char *input = NULL;

  if (argc == 2) {
    input = luaL_checkstring(L, 2);
    n = strlen(input);
  }

  if (argc == 3) {
    n = luaL_checknumber(L, 3);
    input = luaL_checklstring(L, 2, &n);
  }

  if (udata->_init != 1) {
    lua_pushnil(L);
    return 1;
  }

  SHA1_Update(&udata->shactx, input, n);
  lua_pushboolean(L, 1);

  return 1;
}

static const struct luaL_Reg hash[] = {
  { "sha1_init", hash_sha1_init },
  { NULL, NULL }
};

static const struct luaL_Reg sha1_mtable[] = {
  { "__tostring", hash_sha1_tostring },
  { "final", hash_sha1_final },
  { "get_digest", hash_sha1_get_digest },
  { "update", hash_sha1_update },
  { NULL, NULL }
};

int luaopen_hash(lua_State *L) {
  luaL_newmetatable(L, SRP_SHA1_MTABLE); {
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, sha1_mtable, 0);
  }

  luaL_newlib(L, hash);
  return 1;
}
