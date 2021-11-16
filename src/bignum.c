#include <string.h>

#include <lua.h>
#include <lauxlib.h>

#include <openssl/bn.h>

#include <srpcompat.h>

#define SRP_BIGNUM_MTABLE "bignum_meta"

typedef struct {
  BIGNUM *bn;
} bignum_udata_t;

static int bignum_add(lua_State *L) {
  bignum_udata_t *a = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);
  bignum_udata_t *b = luaL_checkudata(L, 2, SRP_BIGNUM_MTABLE);
  bignum_udata_t *x = lua_newuserdata(L, sizeof(bignum_udata_t));

  memset(x, 0, sizeof(bignum_udata_t));
  x->bn = BN_new();
  BN_add(x->bn, a->bn, b->bn);

  luaL_getmetatable(L, SRP_BIGNUM_MTABLE);
  lua_setmetatable(L, -2);

  return 1;
}

static int bignum_gc(lua_State *L) {
  bignum_udata_t *udata = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);
  BN_free(udata->bn);

  return 0;
}

static int bignum_bin2bn(lua_State *L) {
  bignum_udata_t *udata = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);
  size_t n = luaL_checknumber(L, 3);
  const char *bin = luaL_checklstring(L, 2, &n);

  if (BN_bin2bn(bin, n, udata->bn) == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "cannot convert binary to bignum");
    return 2;
  }

  lua_pushboolean(L, 1);
  return 1;
}

static int bignum_bn2bin(lua_State *L) {
  bignum_udata_t *udata = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);
  size_t n = BN_num_bytes(udata->bn);
  unsigned char bin[n];

  if (BN_bn2bin(udata->bn, bin) == 0) {
    lua_pushnil(L);
    lua_pushstring(L, "cannot convert bignum to binary");
    return 2;
  }

  lua_pushlstring(L, bin, n);
  return 1;
}

static int bignum_hex2bn(lua_State *L) {
  bignum_udata_t *udata = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);
  const char *str = luaL_checkstring(L, 2);

  if (BN_hex2bn(&udata->bn, str) == 0) {
    lua_pushnil(L);
    lua_pushstring(L, "cannot convert string to bignum");
    return 2;
  }

  lua_pushboolean(L, 1);
  return 1;
}

static int bignum_is_zero(lua_State *L) {
  bignum_udata_t *udata = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);

  if (BN_is_zero(udata->bn) == 0)
    lua_pushnil(L);
  else
    lua_pushboolean(L, 1);

  return 1;
}

static int bignum_mod_exp(lua_State *L) {
  bignum_udata_t *r = NULL;
  bignum_udata_t *a = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);
  bignum_udata_t *p = luaL_checkudata(L, 2, SRP_BIGNUM_MTABLE);
  bignum_udata_t *m = luaL_checkudata(L, 3, SRP_BIGNUM_MTABLE);
  BN_CTX *ctx = BN_CTX_new();

  r = lua_newuserdata(L, sizeof(bignum_udata_t));
  memset(r, 0, sizeof(bignum_udata_t));
  r->bn = BN_new();

  BN_mod_exp(r->bn, a->bn, p->bn, m->bn, ctx);
  BN_CTX_free(ctx);

  luaL_getmetatable(L, SRP_BIGNUM_MTABLE);
  lua_setmetatable(L, -2);

  return 1;
}

static int bignum_mod(lua_State *L) {
  bignum_udata_t *a = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);
  bignum_udata_t *b = luaL_checkudata(L, 2, SRP_BIGNUM_MTABLE);
  bignum_udata_t *x = lua_newuserdata(L, sizeof(bignum_udata_t));
  BN_CTX *ctx = BN_CTX_new();

  memset(x, 0, sizeof(bignum_udata_t));
  x->bn = BN_new();
  BN_mod(x->bn, a->bn, b->bn, ctx);
  BN_CTX_free(ctx);

  luaL_getmetatable(L, SRP_BIGNUM_MTABLE);
  lua_setmetatable(L, -2);

  return 1;
}

static int bignum_mul(lua_State *L) {
  bignum_udata_t *a = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);
  bignum_udata_t *b = luaL_checkudata(L, 2, SRP_BIGNUM_MTABLE);
  bignum_udata_t *x = lua_newuserdata(L, sizeof(bignum_udata_t));
  BN_CTX *ctx = BN_CTX_new();

  memset(x, 0, sizeof(bignum_udata_t));
  x->bn = BN_new();
  BN_mul(x->bn, a->bn, b->bn, ctx);
  BN_CTX_free(ctx);

  luaL_getmetatable(L, SRP_BIGNUM_MTABLE);
  lua_setmetatable(L, -2);

  return 1;
}

static int bignum_new(lua_State *L) {
  bignum_udata_t *udata = lua_newuserdata(L, sizeof(bignum_udata_t));

  memset(udata, 0, sizeof(bignum_udata_t));
  udata->bn = BN_new();

  luaL_getmetatable(L, SRP_BIGNUM_MTABLE);
  lua_setmetatable(L, -2);

  return 1;
}

static int bignum_num_bytes(lua_State *L) {
  bignum_udata_t *udata = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);
  size_t n = BN_num_bytes(udata->bn);

  lua_pushnumber(L, n);

  return 1;
}

static int bignum_rand(lua_State *L) {
  bignum_udata_t *udata = lua_newuserdata(L, sizeof(bignum_udata_t));
  long numbits = luaL_checkinteger(L, 1);

  memset(udata, 0, sizeof(bignum_udata_t));
  udata->bn = BN_new();

  if (BN_rand(udata->bn, numbits, 0, 1) == 0) {
    lua_pushnil(L);
    lua_pushstring(L, "cannot generate random number");
    return 2;
  }

  luaL_getmetatable(L, SRP_BIGNUM_MTABLE);
  lua_setmetatable(L, -2);

  return 1;
}

static int bignum_set_word(lua_State *L) {
  bignum_udata_t *udata = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);
  long word = luaL_checknumber(L, 2);

  BN_set_word(udata->bn, word);
  return 0;
}

static int bignum_sub(lua_State *L) {
  bignum_udata_t *a = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);
  bignum_udata_t *b = luaL_checkudata(L, 2, SRP_BIGNUM_MTABLE);
  bignum_udata_t *x = lua_newuserdata(L, sizeof(bignum_udata_t));

  memset(x, 0, sizeof(bignum_udata_t));
  x->bn = BN_new();
  BN_sub(x->bn, a->bn, b->bn);

  luaL_getmetatable(L, SRP_BIGNUM_MTABLE);
  lua_setmetatable(L, -2);

  return 1;
}

static int bignum_tostring(lua_State *L) {
  bignum_udata_t *udata = luaL_checkudata(L, 1, SRP_BIGNUM_MTABLE);
  unsigned char *number = BN_bn2hex(udata->bn);

  if (number == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "cannot convert bignum to hex");
    return 2;
  }

  lua_pushstring(L, number);
  OPENSSL_free((void *) number);
  return 1;
}

static const struct luaL_Reg bignum[] = {
  { "new", bignum_new },
  { "rand", bignum_rand },
  { NULL, NULL }
};

static const struct luaL_Reg bignum_mtable[] = {
  { "__add", bignum_add },
  { "__gc", bignum_gc },
  { "__mod", bignum_mod },
  { "__mul", bignum_mul },
  { "__sub", bignum_sub },
  { "__tostring", bignum_tostring },
  { "bin2bn", bignum_bin2bn },
  { "bn2bin", bignum_bn2bin },
  { "hex2bn", bignum_hex2bn },
  { "is_zero", bignum_is_zero },
  { "mod_exp", bignum_mod_exp },
  { "num_bytes", bignum_num_bytes },
  { "set_word", bignum_set_word },
  { NULL, NULL }
};

int luaopen_bignum(lua_State *L) {
  luaL_newmetatable(L, SRP_BIGNUM_MTABLE); {
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, bignum_mtable, 0);
  }

  luaL_newlib(L, bignum);
  return 1;
}
