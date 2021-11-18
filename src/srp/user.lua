local bignum = require("bignum")
local hash = require("hash")

local srp = require("srp")

local _M = {}

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
