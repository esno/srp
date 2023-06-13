#!/usr/bin/env lua

local srp = require("wow/srp")

if #arg ~= 1 then
  print("USAGE: wowpasswd <username>")
  os.exit(255)
end

local username = arg[1]
io.write("Password: ")
local password = io.read()

local v, s = srp.mkverifier(username, password)

print("v: " .. tostring(v))
print("s: " .. tostring(s))
