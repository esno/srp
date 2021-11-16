local bignum = require("bignum")
local hash = require("hash")
local srp = require("srp")
local host = require("srp/host")
local user = require("srp/user")

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
    local s = "C87C2F705F3A3DE385F4F0E49386D6688061AF13DB4653AD434C82015ECA2969"
    local v = "4BEC2A9A0BE2296F67058E1C1AD6FA1EF1E73432BB6872617FA2E3DB7610BB90"

    local verifier, salt = srp.v("username", "password", s)
    if v == verifier:__tostring() and s == salt:__tostring() then chk = ok end

    return chk, desc
  end,

  function()
    local desc = "check session key computation"
    local chk = nil

    local username = "username"
    local password = "password"

    local v, s = srp.v(username, password)
    local A, a = user.A()
    local x = user.x(username, password, s:__tostring())

    local B, b = host.B(v:__tostring())
    local K1 = user.K(A, a, string.reverse(B:bn2bin()), B:num_bytes(), x)
    local K2 = host.K(string.reverse(A:bn2bin()), A:num_bytes(), B, b, v:__tostring())

    if K1:__tostring() == K2:__tostring() then chk = ok end

    return chk, desc
  end
}

local ok, desc
local rc = 0
for _, test in pairs(tests) do
  ok, desc = test()
  print(string.format("[%s] %s", ok or nok, desc))
  if not ok then rc = 1 end
end

os.exit(rc)
