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

function _M.mksessionkey(userephemeral, userephemeral_l, B, b, verifier)
  local A = bignum.new()
  A:bin2bn(userephemeral, userephemeral_l)

  local N = bignum.new()
  N:hex2bn(_M.N)

  if A:is_zero() or (A % N):is_zero() then
    return nil
  end

  local sha = hash.sha1_init()
  sha:update(string.reverse(A:bn2bin()), A:num_bytes())
  sha:update(string.reverse(B:bn2bin()), B:num_bytes())
  sha:final()

  local digest, digest_l = sha:get_digest()
  local u = bignum.new()
  u:bin2bn(digest, digest_l)

  local v = bignum.new()
  v:hex2bn(verifier)

  return _M.hash_sessionkey((A * v:mod_exp(u, N)):mod_exp(b, N))
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

function _M.hash_sessionkey(key)
  local S = key:bn2bin()
  local pos

  local token = ""
  for i = 1, 16 do
    pos = i * 2 - 1
    token = token .. S:sub(pos, pos)
  end

  local sha = hash.sha1_init()
  sha:update(token, 16)
  sha:final()
  local K1, K1_l = sha:get_digest()

  local token = ""
  for i = 1, 16 do
    pos = i * 2
    token = token .. S:sub(pos, pos)
  end

  local sha = hash.sha1_init()
  sha:update(token, 16)
  sha:final()
  local K2, K2_l = sha:get_digest()

  local token = ""
  for i = 1, K1_l do
    token = token .. K1:sub(i, i) .. K2:sub(i, i)
  end

  local K = bignum.new()
  return K:bin2bn(token, K1_l * 2)
end

return _M
