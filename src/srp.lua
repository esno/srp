local bignum = require("bignum")
local hash = require("hash")

local _M = {
  SALT_BYTE_SIZE = 32,

  g = 7,
  N = "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
}

function _M.mkverifier(identifier, salt)
  local s

  if type(salt) == "string" then
    s = bignum.new()
    s:hex2bn(salt)
  else
    s = bignum.rand(_M.SALT_BYTE_SIZE * 8)
  end

  if s:is_zero() then
    return nil
  end

  local I, I_l = identifier:get_digest()

  local sha = hash:sha1_init()
  sha:update(string.reverse(s:bn2bin()), s:num_bytes())
  sha:update(I, I_l)
  sha:final()
  local digest, digest_l = sha:get_digest()

  local x = bignum.new()
  x:bin2bn(string.reverse(digest), digest_l)

  local g = bignum.new()
  g:set_word(_M.g)
  local N = bignum.new()
  N:hex2bn(_M.N)

  --  int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
  --       const BIGNUM *m, BN_CTX *ctx);
  -- (r=a^p % m)
  --
  -- v = g ^ x % N
  local v = g:mod_exp(x, N)

  return v, s
end

function _M.hash(username, password)
  local sha = hash.sha1_init()
  sha:update(string.format("%s:%s", string.upper(username), string.upper(password)))
  sha:final()
  return sha
end

return _M
