local srp = require("wow/srp")

local _M = {}

local logon_proof = function(self, M)
  self.M2 = srp.M2(self.A, self.M1, self.K)
  local M2, M2_l = self.M2:get_digest()
  local M, M_l = M:get_digest()

  for i = 1, M2_l do
    if M2:sub(i, i) ~= M:sub(i, i) then
      return nil
    end
  end

  return true
end

-- # auth_challenge
-- Create a new SRP table and process authentication challenge response.
--
-- > I        [string] The account identifier (I).
-- > password [string] The plaintext password.
-- > s        [string] The salt (s) as hex string.
-- > B        [string] The host public ephemeral (B) as hex string.
-- > g        [number] The generator (g).
-- > N        [string] The prime (N) as hex string.
-- > k        [number] The multiplier (k).
--                     Optional - defaults to srp.k.
--
-- <          [table]  The SRP table otherwise nil on error.
function _M.auth_challenge(I, password, s, B, g, N, k)
  local t = {}

  t.logon_proof = logon_proof

  t.k = srp.dec2bn(k or srp.k)

  t.I = I
  t.p = srp.p(I, password)
  if not t.p then
    return nil
  end

  t.s = srp.hex2bn(s)
  t.B = srp.hex2bn(B)
  t.g = srp.dec2bn(g)
  t.N = srp.hex2bn(N)

  t.x = srp.x(t.p, t.s)
  if not t.x then
    return nil
  end

  t.v = srp.v(t.x, t.g, t.N)
  t.A, t.a = srp.A(t.g, t.N)
  if not t.A then
    return nil
  end

  t.u = srp.u(t.A, t.B, t.N)
  if not t.u then
    return nil
  end

  t.S = srp.S_user(t.a, t.B, t.u, t.x, t.g, t.N, t.k)
  t.K = srp.K(t.S)
  t.M1 = srp.M1(t.I, t.s, t.A, t.B, t.K, t.g, t.N)

  return t
end

return _M
