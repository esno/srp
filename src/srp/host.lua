local bignum = require("bignum")
local hash = require("hash")

local srp = require("srp")

local _M = {}

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
