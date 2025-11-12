nikto -h example.com – Scans for common vulns.

nikto -h example.com -p 80,443 – Targets HTTP and HTTPS.

nikto -h https://example.com -ssl – Scans secure sites.

nikto -h example.com -nossl – For non-SSL only.
nikto -update – Keeps scans current.


nikto -h example.com -maxtime 600 – Limits to 10 minutes.

nikto -h example.com -timeout 10 – Avoids hanging on slow responses.

nikto -h 192.168.1.1 -vhost example.com – For name-based hosting

nikto -h example.com -Tuning 49 – XSS and SQL injection only.

nikto -h example.com -useragent "Mozilla/5.0"