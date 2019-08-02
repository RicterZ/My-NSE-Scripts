local http = require "http"

description = [[
]]

author = "Ricter Zheng"
license = "Same as https://github.com/RicterZ/My-NSE-Scripts/blob/master/LICENSE"
categories = {"default", "safe"}


portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open"
end


action = function(host, port)
        local client = nmap.new_socket()

        local catch = function()
                client:close()
                return false
        end

        local try = nmap.new_try(catch)

	local res = http.generic_request(host, port, 'GET', '/wsman', nil)
	if res.status ~= 405 then
		return false
	end

	local res = http.generic_request(host, port, 'POST', '/wsman', nil)
	if res.status ~= 401 then
		return false
	end

	return "WinRM"
end

