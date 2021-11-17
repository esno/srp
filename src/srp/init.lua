local bignum = require("bignum")
local hash = require("hash")

local _M = {
  -- Length of salt in bytes
  SALT_NUM_BYTES = 32,
  -- Length of secret ephemeral in bytes
  EPHEMERAL_NUM_BYTES = 19,
  -- Maximum length of account name
  ACCOUNT_LENGTH = 16,

  -- generator
  g = 7,
  -- prime
  N = "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7",
  -- multiplier
  k = 3
}

function _M.hex2bn(hex)
  local bn = bignum.new()
  bn:hex2bn(hex)
  return bn
end

-- # K
-- Generates a strong session key (K).
-- The session key will be split into two tokens.
-- Odd character positions are the one while even positions
-- are the other.
-- Both will be hashed using sha1 and merged into strong session key.
-- Token one fills all odd character positions, token two even positions.
--
-- > S [bignum] the session key (S).
--
-- <   [bignum] the strong session key (K).
function _M.K(S)
  local S = string.reverse(S:bn2bin())
  local pos

  local K1, K2 = "", ""
  for i = 1, 16 do
    pos = i * 2 - 1
    K1 = K1 .. S:sub(pos, pos)

    pos = i * 2
    K2 = K2 .. S:sub(pos, pos)
  end

  local sha = hash.sha1_init()
  sha:update(K1, 16)
  sha:final()
  local K1, K1_l = sha:get_digest()

  local sha = hash.sha1_init()
  sha:update(token, 16)
  sha:final()
  local K2, K2_l = sha:get_digest()

  local token = ""
  for i = 1, K1_l do
    token = token .. K1:sub(i, i) .. K2:sub(i, i)
  end

  local K = bignum.new()
  K:bin2bn(string.reverse(token), K1_l * 2)
  return K
end

-- # p
-- Generates a hash of username and password (p).
-- The username and password will be converted to uppercase letters.
--
-- > username [string] The username (aka. identifier).
--                     Maximum length is `ACCOUNT_LENGTH`.
-- > password [string] The password of the account.
--
-- <          [sha1]   The sha1 userdata of USERNAME:PASSWORD.
function _M.p(username, password)
  if username:len() > _M.ACCOUNT_LENGTH then
    return nil
  end

  local sha = hash.sha1_init()
  sha:update(string.format("%s:%s", string.upper(username), string.upper(password)))
  sha:final()
  return sha
end

-- # u
-- Generates a random scrambling parameter (u).
--
-- > A [bignum] The user public ephemeral (A).
-- > B [bignum] The host public ephemeral (B).
--
-- <   [bignum] The random scrambling parameter (u).
function _M.u(A, B)
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
  u:bin2bn(string.reverse(digest), digest_l)

  return u
end

-- # v
-- Generates the password verifier (v).
--
-- > p [sha1]   The hash of username and password (p) of the account.
-- > s [bignum] The salt (s).
--              If nil a new salt is generated.
--
-- <   [bignum] The password verifier (v) otherwise nil.
-- <   [bignum] The salt (s) otherwise nil.
function _M.v(p, s)
  if not s then
    s = bignum.rand(_M.SALT_NUM_BYTES * 8)
  end

  if s:is_zero() then
    return nil
  end

  local IP, IP_l = p:get_digest()

  local sha = hash:sha1_init()
  sha:update(string.reverse(s:bn2bin()), s:num_bytes())
  sha:update(IP, IP_l)
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

return _M
