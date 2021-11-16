local bignum = require("bignum")
local hash = require("hash")

local srp = require("srp")

local _M = {}

-- # A
-- Generates a secret (a) and public (A) user ephemeral.
-- a is a random number with length of `EPHEMERAL_NUM_BYTES`.
-- The client MUST abort authentication if B % N is zero.
--
-- <          [bignum] The public ephemeral A otherwise nil.
-- <          [bignum] The secret ephemeral a otherwise nil.
function _M.A()
  local a = bignum.rand(srp.EPHEMERAL_NUM_BYTES * 8)

  if a:is_zero() then
    return nil
  end

  local g = bignum.new()
  g:set_word(srp.g)
  local N = bignum.new()
  N:hex2bn(srp.N)

  -- A = g ^ a % N
  return g:mod_exp(a, N), a
end

-- # K
-- Generates a strong session key (K).
--
-- > A               [bignum] The user public ephemeral (A)
-- > a               [bignum] The user secret ephemeral (a).
-- > hostephemeral   [string] The host public ephemeral (B) as binary string.
-- > hostephemeral_l [number] Length of B.
-- > x               [bignum] The private key (x).
--
-- <                 [bignum] The strong session key (K) otherwise nil.
function _M.K(A, a, hostephemeral, hostephemeral_l, x)
  local B = bignum.new()
  B:bin2bn(string.reverse(hostephemeral), hostephemeral_l)

  local g = bignum.new()
  g:set_word(srp.g)
  local N = bignum.new()
  N:hex2bn(srp.N)
  local k = bignum.new()
  k:set_word(srp.k)

  local sha = hash.sha1_init()
  sha:update(string.reverse(A:bn2bin()), A:num_bytes())
  sha:update(string.reverse(B:bn2bin()), B:num_bytes())
  sha:final()

  local digest, digest_l = sha:get_digest()
  local u = bignum.new()
  u:bin2bn(string.reverse(digest), digest_l)

  local S = (B - k * g:mod_exp(x, N)):mod_exp(a + u * x, N)
  return srp.hash_sessionkey(S)
end

-- # x
-- Generates a private key (x).
--
-- > username [string] The username to authenticate
-- > password [string] The password of the account.
-- > salt     [string] The salt as hex string.
--
-- <          [bignum] The private key (x) otherwise nil
function _M.x(username, password, salt)
  local identifier = srp.hash(username, password)
  if not identifier then
    return nil
  end

  local s = bignum.new()
  s:hex2bn(salt)

  if s:is_zero() then
    return nil
  end

  local digest, digest_l = identifier:get_digest()
  local sha = hash.sha1_init()
  sha:update(string.reverse(s:bn2bin()), s:num_bytes())
  sha:update(digest, digest_l)
  sha:final()

  local digest, digest_l = sha:get_digest()
  local x = bignum.new()
  x:bin2bn(string.reverse(digest), digest_l)

  return x
end

return _M
