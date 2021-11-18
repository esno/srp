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
  local g = bignum.new()
  g:set_word(srp.g)
  local N = bignum.new()
  N:hex2bn(srp.N)
  local k = bignum.new()
  k:set_word(srp.k)

  return (B - k * g:mod_exp(x, N)):mod_exp(a + u * x, N)
end

return _M
