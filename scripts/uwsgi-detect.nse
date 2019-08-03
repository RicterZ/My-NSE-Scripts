local bit = require "bit"
local nmap = require "nmap"
local string = require "string"


description = [[
Detect uWSGI Server
]]

author = "Ricter Zheng"
license = "Same as https://github.com/RicterZ/My-NSE-Scripts/blob/master/LICENSE"
categories = {"default", "safe"}


function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end


function make_headers_http(t) 
	local ret = "GET / HTTP/1.0\r\n"
	for k, v in pairs(t) do
		ret = ret .. k .. ":" .. v .. "\r\n"
	end

	ret = ret .. "\r\n"
	return ret
end


function make_headers_scgi(t)
	local ret = ""
	for k, v in pairs(t) do
		ret = ret .. k .. "\x00" .. v .. "\x00"
	end
	ret = string.len(ret) .. ":" .. ret .. ",nmap"
	return ret
end


function make_headers_uwsgi(t)
	local ret = ""
	for k, v in pairs(t) do
		ret = ret .. string.fromhex(string.format("%04x", bit.lshift(string.len(k), 8)))
		ret = ret .. k
		ret = ret .. string.fromhex(string.format("%04x", bit.lshift(string.len(v), 8)))
		ret = ret .. v
	end
	length = string.format("%04x", bit.lshift(string.len(ret), 8))
	ret = "\x00" .. string.fromhex(length) .. "\x00" .. ret
	return ret
end


portrule = function(host, port)
	return true
end


action = function(host, port)
	local ret
	local status = true

	local client = nmap.new_socket()

	local catch = function()
		client:close()
	end

	local try = nmap.new_try(catch)

	local headers = {}
	headers["REQUEST_METHOD"] = "GET"
	headers["HTTP_HOST"] = "127.0.0.1"

	client:set_timeout(10000)
	try(client:connect(host, port))

	-- first, checking not a HTTP service
	try(client:send(make_headers_http(headers)))

	status, ret = client:receive_lines(1)
	if string.match(ret, "HTTP/1.%d %d+") then
		try(client:close())
		return "not a uWSGI daemon (HTTP)"
	end
	try(client:close())

	-- second, check uwsgi protocol
	try(client:connect(host, port))
	try(client:send(make_headers_uwsgi(headers)))

	status, ret = client:receive_lines(1)
	if string.match(ret, "HTTP/1.%d %d+") then
		try(client:close())
		return "uWSGI daemon detected (uWSGI)"
	end
	try(client:close())


	-- third, check scgi protocol
	try(client:connect(host, port))
	try(client:send(make_headers_scgi(headers)))

	status, ret = client:receive_lines(1)
	if string.match(ret, "Status: %d+") then
		try(client:close())
		return "uWSGI daemon detected (SCGI)"
	end

	try(client:close())
	return "not a uWSGI daemon (unknown)"

end

