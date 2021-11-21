#!/usr/bin/env lua

local bignum = require("bignum")
local hash = require("hash")
local srp = require("wow.srp")

local ok = "\27[32mOK\27[0m "
local nok = "\27[31mnok\27[0m"

local tests = {
  function()
    local desc = "check sha1 hash"
    local chk = nil

    -- echo -n "USERNAME:PASSWORD" | sha1sum | awk '{ print $1 }' 
    local digest = "5b039d152722e351c8bdebcf06fd8cd4e5244d78"
    local sha1 = hash.sha1_init()
    sha1:update("USERNAME:PASSWORD")
    sha1:final()
    local result = sha1:__tostring()
    if digest == result then chk = ok end

    return chk, desc
  end,

  function()
    local desc = "check password verifier"
    local chk = nil

    -- username:password
    local s = srp.hex2bn("C87C2F705F3A3DE385F4F0E49386D6688061AF13DB4653AD434C82015ECA2969")
    local v = srp.hex2bn("4BEC2A9A0BE2296F67058E1C1AD6FA1EF1E73432BB6872617FA2E3DB7610BB90")

    local p = srp.p("username", "password")
    local x, salt = srp.x(p, s)
    local verifier = srp.v(x)
    if v:__tostring() == verifier:__tostring() and s:__tostring() == salt:__tostring() then chk = ok end

    return chk, desc
  end,

  function()
    local desc = "check session key computation"
    local chk = nil

    local g = srp.dec2bn(srp.g)
    local N = srp.hex2bn(srp.N)
    local k = srp.dec2bn(srp.k)

    local username = "username"
    local password = "password"

    local p = srp.p(username, password)

    local x, s = srp.x(p)
    local v = srp.v(x)
    local A, a = srp.A()

    local B, b = srp.B(v, g, N, k)
    local u = srp.u(A, B, N)
    local S1 = srp.S_user(a, B, u, x)
    local S2 = srp.S_host(b, A, u, v, N)

    if S1:__tostring() == S2:__tostring() then chk = ok end

    return chk, desc
  end
}

local ok, desc
local rc = 0
for _, test in pairs(tests) do
  ok, desc = test()
  print(("[%s] %s"):format(ok or nok, desc))
  if not ok then rc = 1 end
end

os.exit(rc)
