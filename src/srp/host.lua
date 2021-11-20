local authcodes = require("wow/authcodes")
local srp = require("wow/srp")

local _meta = {}
local _M = {}

-- logon_proof
-- Process authentication logon proof request.
--
-- > A [string] The user public ephemeral (A) as binary string.
-- > M [string] The authentication proof (M).
--
-- <   [number] A number representing the auth error code.
function _meta.logon_proof(self, A, M)
  self.A = srp.hex2bn(A)
  self.u = srp.u(self.A, self.B, self.N)

  if not self.u then
    return authcodes.error_unknown1 -- check for better code
  end

  self.S = srp.S_host(self.b, self.A, self.u, self.v, self.N)
  self.K = srp.K(self.S)

  self.M1 = srp.M1(self.I, self.s, self.A, self.B, self.K, self.g, self.N)
  local M1, M1_l = self.M1
  for i = 1, M1_l do
    if M1:sub(i, i) ~= M:sub(i, i) then
      return authcodes.error_noaccess
    end
  end

  self.M2 = srp.M2(self.A, self.M1, self.K)

  return authcodes.success
end

-- # auth_challenge
-- Create a new SRP table and process authentication challenge request.
--
-- > I [string] The account identifier (I).
-- > v [bignum] The password verifier (v).
-- > s [bignum] The random salt (s).
-- > g [number] The generator (g).
--              Optional - defaults to srp.g.
-- > N [string] The prime as hex string.
--              Optional - defaults to srp.N.
-- > k [number] The multiplier.
--              Optional - defaults to srp.k
--
-- <   [table]  The SRP table.
function _M.auth_challenge(I, v, s, g, N, k)
  local t = {}

  t.g = srp.dec2bn(g or srp.g)
  t.N = srp.hex2bn(N or srp.N)
  t.k = srp.dec2bn(k or srp.k)

  t.I = I
  t.v = srp.hex2bn(v)
  t.s = srp.hex2bn(s)

  t.B, t.b = srp.B(t.v, t.g, t.N, t.k)

  return t
end

return _M
