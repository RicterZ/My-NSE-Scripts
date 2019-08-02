description = [[
FastCGI Daemon Detect
]]

author = "Ricter Zheng"
license = "Same as https://github.com/RicterZ/My-NSE-Scripts/blob/master/LICENSE"
categories = {"default", "safe"}


portrule = function(host, port)
	return true
end


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

	local ret = try(client:receive_lines(1))

	local status_code = string.match(ret, "Primary script unknown")

	try(client:close())

	if status_code ~= nil then
		return "Server Response: " .. status_code
	end

	return false

end

