#!/usr/bin/env lua

local srp = require("wow/srp")

if #arg ~= 1 then
  print("USAGE: wowpasswd <username>")
  os.exit(255)
end

local username = arg[1]
io.write("Password: ")
local password = io.read()

local p = srp.p(username, password)
local x, s = srp.x(p, nil)
local v = srp.v(x, srp.dec2bn(srp.g), srp.hex2bn(srp.N))

print("v: " .. tostring(v))
print("s: " .. tostring(s))
