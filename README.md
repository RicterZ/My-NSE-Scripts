# My-NSE-Scripts

Scripts List:

+ [uwsgi-detect.nse](scripts/uwsgi-detect.nse): Detect uWSGI (via echoing a python function and returning 200 NMAP)
+ [fastcgi-detect.nse](scripts/fastcgi-detect.nse): Detect FastCGI port
+ [winre.nse](scripts/winrm.nse): Detect WinRE HTTP port

Usage:

    ^^/D/My-NSE-Scripts >>> nmap localhost -p9000 --script=+scripts/

    Starting Nmap 7.60 ( https://nmap.org ) at 2019-08-03 17:09 CST
    Nmap scan report for localhost (127.0.0.1)
    Host is up (0.000047s latency).

    PORT     STATE SERVICE
    9000/tcp open  cslistener
    |_php-fpm: PHP-FPM daemon detected
    |_uwsgi-detect: not a uWSGI daemon (unknown)
    |_winrm: WinRM not exists (not a HTTP/S service)

    Nmap done: 1 IP address (1 host up) scanned in 1.15 seconds
