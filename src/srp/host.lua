local bignum = require("bignum")
local hash = require("hash")

local _M = require("srp")

-- # mkephemerals
-- Generates a secret (b) and public (B) host ephemeral.
-- b is a random number with length of `EPHEMERAL_NUM_BYTES`.
-- The host MUST send B after receiving A from the client, never before.
--
-- > verifier [string] The password verifier (v) as hex string.
--
-- <          [bignum] The public ephemeral B otherwise nil.
-- <          [bignum] The secret ephemeral b otherwise nil.
function _M.mkephemerals(verifier)
  local v = bignum.new()
  v:hex2bn(verifier)

  local b = bignum.new()
  b:rand(_M.EPHEMERAL_NUM_BYTES * 8)

  local g = bignum.new()
  g:set_word(_M.g)
  local N = bignum.new()
  N:hex2bn(_M.N)

  -- gmod = g ^ b % N
  local gmod = g:mod_exp(b, N)
  if gmod:num_bytes() > 32 then
    return nil
  end

  return (v * 3 + gmod) % N, b
end

-- # mksessionkey
-- Generates a strong session key (K).
-- The host MUST abort the authentication attempt if A % N is zero.
--
-- > userephemeral   [string] The user public ephemeral (A) as binary string.
-- > userephemeral_l [number] Length of A.
-- > B               [bignum] The host public ephemeral (B)
-- > b               [bignum] The host secret ephemeral (b).
-- > verifier        [string] The password verifier (v) as hex string.
--
-- <                 [bignum] The strong session key (K) otherwise nil.
function _M.mksessionkey(userephemeral, userephemeral_l, B, b, verifier)
  local A = bignum.new()
  A:bin2bn(userephemeral, userephemeral_l)

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
  u:bin2bn(digest, digest_l)

  local v = bignum.new()
  v:hex2bn(verifier)

  -- S = (A * (v ^ u % N)) ^ b % N
  return _M.hash_sessionkey((A * v:mod_exp(u, N)):mod_exp(b, N))
end

return _M
