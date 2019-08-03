local http = require "http"
local nmap = require "nmap"
local string = require "string"


description = [[
]]

author = "Ricter Zheng"
license = "Same as https://github.com/RicterZ/My-NSE-Scripts/blob/master/LICENSE"
categories = {"default", "safe"}


portrule = function(host, port)
	return port.service == "http" or port == 5985
end


action = function(host, port)
        local client = nmap.new_socket()

        local catch = function()
                client:close()
        end

        local try = nmap.new_try(catch)

	local res = http.generic_request(host, port, 'GET', '/wsman', nil)

	if res.status == nil then
		return "WinRM not exists (not a HTTP/S service)"
	end

	if res.status ~= 405 then
		return "WinRM not exists (/wsman returns " .. res.status .. ")"
	end

	local res = http.generic_request(host, port, 'POST', '/wsman', nil)
	if res.status ~= 401 then
		return "WinRM not exists (/wsman returns " .. res.status .. ")"
	end

	return "WinRM service detected"
end

