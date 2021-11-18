local bignum = require("bignum")
local hash = require("hash")

local _M = {
  -- Length of salt in bytes
  SALT_NUM_BYTES = 32,
  -- Length of secret ephemeral in bytes
  EPHEMERAL_NUM_BYTES = 19,
  -- Maximum length of account name
  ACCOUNT_LENGTH = 16,

  -- Generator
  g = 7,
  -- Prime
  N = "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7",
  -- Multiplier
  k = 3
}

-- # A
-- Generates a secret (a) and public (A) user ephemeral.
-- a is a random number with length of `EPHEMERAL_NUM_BYTES`.
-- The client MUST abort authentication if B % N is zero.
--
-- <          [bignum] The public ephemeral A otherwise nil.
-- <          [bignum] The secret ephemeral a otherwise nil.
function _M.A()
  local a = bignum.rand(_M.EPHEMERAL_NUM_BYTES * 8)

  if a:is_zero() then
    return nil
  end

  local g = _M.dec2bn(_M.g)
  local N = _M.hex2bn(_M.N)

  -- A = g ^ a % N
  return g:mod_exp(a, N), a
end

-- # bin2bn
-- Converts a binary string to bignum.
-- The binary string will be reversed before conversion.
--
-- > bin [string] A binary string.
-- > l   [number] The length of the binary string.
--
-- <     [bignum] The bignum representing the binary string.
function _M.bin2bn(bin, l)
  local bn = bignum.new()
  bn:bin2bn(string.reverse(bin), l)
  return bn
end

-- # bn2bin
-- Converts a bignum to binary string.
-- The binary string will be reversed after conversion.
--
-- > bn [bignum] The bignum to convert.
--
-- <    [string] The binary string representing the bignum.
function _M.bn2bin(bn)
  return string.reverse(bn:bn2bin())
end

-- # B
-- Generates a secret (b) and public (B) host ephemeral.
-- b is a random number with length of `EPHEMERAL_NUM_BYTES`.
-- The host MUST send B after receiving A from the client, never before.
--
-- > v [bignum] The password verifier (v).
--
-- <   [bignum] The public ephemeral B otherwise nil.
-- <   [bignum] The secret ephemeral b otherwise nil.
function _M.B(v)
  local b = bignum.rand(_M.EPHEMERAL_NUM_BYTES * 8)

  local g = _M.dec2bn(_M.g)
  local N = _M.hex2bn(_M.N)
  local k = _M.dec2bn(_M.k)

  -- gmod = g ^ b % N
  local gmod = g:mod_exp(b, N)
  if gmod:num_bytes() > 32 then
    return nil
  end

  return (v * k + gmod) % N, b
end

-- # dec2bn
-- Converts a decimal number to bignum.
--
-- > dec [number] The decimal number.
--
-- <     [bignum] The number as bignum.
function _M.dec2bn(dec)
  local bn = bignum.new()
  bn:set_word(dec)
  return bn
end

-- # hex2bn
-- Converts a hexadecimal string to bignum.
--
-- > hex [string] Hexadecimal string to convert.
--
-- <     [bignum] The bignum representing the hexadecimal string.
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
  local S = _M.bn2bin(S)
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

  return _M.bin2bn(token, K1_l * 2)
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

-- # S_host
-- Generates a session key (S).
-- The host MUST abort the authentication attempt if A % N is zero.
--
-- > b [bignum] The host secret ephemeral (b).
-- > A [bignum] The user public ephemeral (A).
-- > u [bignum] The random scrambling parameter (u).
-- > v [bignum] The password verifier (v).
--
-- <   [bignum] The session key (S) otherwise nil.
function _M.S_host(b, A, u, v)
  local N = _M.hex2bn(_M.N)

  if A:is_zero() or (A % N):is_zero() then
    return nil
  end

  -- S = (A * (v ^ u % N)) ^ b % N
  return (A * v:mod_exp(u, N)):mod_exp(b, N)
end

-- # S_user
-- Generates a session key (S).
--
-- > a [bignum] The user secret ephemeral (a).
-- > B [bignum] The host public ephemeral (B).
-- > u [bignum] The random scrambling parameter (u).
-- > x [bignum] The private key (x).
--
-- <   [bignum] The session key (S) otherwise nil.
function _M.S_user(a, B, u, x)
  local g = _M.dec2bn(_M.g)
  local N = _M.hex2bn(_M.N)
  local k = _M.dec2bn(_M.k)

  return (B - k * g:mod_exp(x, N)):mod_exp(a + u * x, N)
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
  sha:update(_M.bn2bin(A), A:num_bytes())
  sha:update(_M.bn2bin(B), B:num_bytes())
  sha:final()

  local digest, digest_l = sha:get_digest()
  return _M.bin2bn(digest, digest_l)
end

-- # v
-- Generates the password verifier (v).
--
-- > x [bignum] The private key (x).
--
-- <   [bignum] The password verifier (v) otherwise nil.
function _M.v(x)
  local g = bignum.new()
  g:set_word(_M.g)
  local N = bignum.new()
  N:hex2bn(_M.N)

  -- v = g ^ x % N
  return g:mod_exp(x, N)
end

-- # x
-- Generates a private key (x).
--
-- > p [sha1]   The hash of the password of the account.
-- > s [bignum] The salt (s).
--              If nil a new salt is generated automatically.
--
-- <   [bignum] The private key (x) otherwise nil
-- <   [bignum] The salt (s) otherwise nil.
function _M.x(p, s)
  if not s then
    s = bignum.rand(_M.SALT_NUM_BYTES * 8)
  end

  if s:is_zero() then
    return nil
  end

  local p, p_l = p:get_digest()
  local sha = hash.sha1_init()
  sha:update(_M.bn2bin(s), s:num_bytes())
  sha:update(p, p_l)
  sha:final()

  local digest, digest_l = sha:get_digest()
  return _M.bin2bn(digest, digest_l), s
end

return _M
