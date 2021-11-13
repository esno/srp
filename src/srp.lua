local bignum = require("bignum")
local hash = require("hash")

local _M = {
  SALT_NUM_BYTES = 32,
  EPHEMERAL_NUM_BYTES = 19,

  g = 7,
  N = "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
}

function _M.mkhostephemeral(verifier)
  local v = bignum.new()
  v:hex2bn(verifier)

  local b = bignum.new()
  b:rand(_M.EPHEMERAL_NUM_BYTES * 8)

  local g = bignum.new()
  g:set_word(_M.g)
  local N = bignum.new()
  N:hex2bn(_M.N)

  local gmod = g:mod_exp(b, N)
  if gmod:num_bytes() > 32 then
    return nil
  end

  return ((v * 3) + gmod) % N, b
end

function _M.mkverifier(username, password, salt)
  local identifier = _M.hash(username, password)
  local s

  if type(salt) == "string" then
    s = bignum.new()
    s:hex2bn(salt)
  else
    s = bignum.rand(_M.SALT_NUM_BYTES * 8)
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
