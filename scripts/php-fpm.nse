local shortport = require "shortport"
local nmap = require "nmap"
local string = require "string"

description = [[
PHP-FPM Daemon Detect
]]

author = "Ricter Zheng"
license = "Same as https://github.com/RicterZ/My-NSE-Scripts/blob/master/LICENSE"
categories = {"default", "safe"}


portrule = shortport.port_or_service(9000, "tcp")


action = function(host, port)
	local client = nmap.new_socket()

	local catch = function()
		client:close()
	end

	local try = nmap.new_try(catch)

	local data = "\x01\x01\x59\x01\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
	data = data .. "\x01\x04\x59\x01\x00\x26\x00\x00\x0e\x04REQUEST_METHODPOST\x0f\x01"
	data = data .. "SCRIPT_FILENAME/\x01\x04\x59\x01\x00\x00\x00\x00\x01\x05\x59\x01"
	data = data .. "\x00\x00\x00\x00"

	try(client:connect(host, port))
	try(client:send(data))

	status, ret = client:receive_lines(1)
	try(client:close())

	if status == false then
		return "not a PHP-FPM daemon"
	end

	local ret = string.match(ret, "Primary script unknown")

	if ret ~= nil then
		return "PHP-FPM daemon detected"
	end

	return "not a PHP-FPM daemon"

end

