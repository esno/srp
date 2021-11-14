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

-- # mkverifier
-- Generates the password verifier (v).
--
-- > username [string] The username (I) aka identifier.
-- > password [string] The password (P) of the account in plaintext.
-- > salt     [string] The salt (s) as hex string.
--                     If nil a new salt is generated.
--
-- <          [bignum] The password verifier (v) otherwise nil.
-- <          [bignum] The salt (s) otherwise nil.
function _M.mkverifier(username, password, salt)
  local identifier = _M.hash(username, password)
  local s

  if not identifier then
    return nil
  end

  if type(salt) == "string" then
    s = bignum.new()
    s:hex2bn(salt)
  else
    s = bignum.rand(_M.SALT_NUM_BYTES * 8)
  end

  if s:is_zero() then
    return nil
  end

  local IP, IP_l = identifier:get_digest()

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

-- # hash
-- Generates a hash of username and password.
-- The username and password will be converted to uppercase letters.
--
-- > username [string] The username (aka. identifier).
--                     Maximum length is `ACCOUNT_LENGTH`.
-- > password [string] The password of the account.
--
-- <          [sha1]   The sha1 userdata of USERNAME:PASSWORD.
function _M.hash(username, password)
  if username:len() > _M.ACCOUNT_LENGTH then
    return nil
  end

  local sha = hash.sha1_init()
  sha:update(string.format("%s:%s", string.upper(username), string.upper(password)))
  sha:final()
  return sha
end

-- # hash_sessionkey
-- Generates a strong session key (K).
-- The session key will be split into two tokens.
-- Odd character positions are the one while even positions
-- are the other.
-- Both will be hashed using sha1 and merged into strong session key.
-- Token one fills all odd character positions, token two even positions.
--
-- > key [bignum] the session key (S).
--
-- <     [bignum] the strong session key (K).
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
