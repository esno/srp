local bignum = require("bignum")
local hash = require("hash")

local srp = require("srp")

local _M = {}

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
  local b = bignum.rand(srp.EPHEMERAL_NUM_BYTES * 8)

  local g = bignum.new()
  g:set_word(srp.g)
  local N = bignum.new()
  N:hex2bn(srp.N)
  local k = bignum.new()
  k:set_word(srp.k)

  -- gmod = g ^ b % N
  local gmod = g:mod_exp(b, N)
  if gmod:num_bytes() > 32 then
    return nil
  end

  return (v * k + gmod) % N, b
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
  local N = bignum.new()
  N:hex2bn(srp.N)

  if A:is_zero() or (A % N):is_zero() then
    return nil
  end

  -- S = (A * (v ^ u % N)) ^ b % N
  return (A * v:mod_exp(u, N)):mod_exp(b, N)
end

return _M
