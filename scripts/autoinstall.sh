#!/bin/bash

# Automated Installation Script (CTF)

# export GITHUB_TOKEN="your_token_here"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "\n${RED}[!] Please run this script as root (use sudo).${NC}\n"
    exit 1
fi

echo -e "\n${BLUE}[*] Starting tool installation process...${NC}\n"
apt update -y

REQUIRED_TOOLS=(
  "seclists"
  "jq"
  "ffuf"
  "feroxbuster"
  "katana"
  "flameshot"
  "lsd"
  "caido"
)
 
is_installed() {
    dpkg -s "$1" &> /dev/null
}
  
install_from_github_repo() {
    local tool="$1"
    local repo="$2"
    local install_dir="/opt/$tool"

    echo -e "${YELLOW}[~] Cloning $repo into $install_dir ...${NC}"

    if [[ -d "$install_dir" ]]; then
        echo -e "${GREEN}[+] Directory $install_dir already exists.${NC}\n"
        return
    fi

    git clone "$repo" "$install_dir"

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}[✓] Cloned $tool to $install_dir.${NC}"
        echo -e "${YELLOW}[!] Manual build or usage may be required.${NC}\n"
    else
        echo -e "${RED}[✗] Failed to clone $tool from GitHub.${NC}\n"
    fi
}

# Search GitHub for tool with rate-limit and token support 
search_github_repo() {
    local tool="$1"
    local api_url="https://api.github.com/search/repositories?q=$tool+in:name&sort=stars&order=desc"

    echo -e "${YELLOW}[~] Searching GitHub for $tool...${NC}"

    # Use token if available
    if [[ -n "$GITHUB_TOKEN" ]]; then
        auth_header="Authorization: token $GITHUB_TOKEN"
    else
        auth_header=""
    fi

    response=$(curl -s -H "$auth_header" "$api_url")

    # Check for rate limit exceeded
    if echo "$response" | grep -q "API rate limit exceeded"; then
        echo -e "${RED}[✗] GitHub API rate limit exceeded. Try again later or set GITHUB_TOKEN.${NC}\n"
        return
    fi

    # Get top repo url
    repo_url=$(echo "$response" | jq -r '.items[] | select(.html_url | test("'$tool'$")) | .html_url' | head -n 1)


    if [[ -n "$repo_url" ]]; then
        echo -e "${GREEN}[+] Found repo: $repo_url${NC}"
        read -p "    Clone this repo for $tool? (y/N): " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            install_from_github_repo "$tool" "$repo_url"
        else
            echo -e "${YELLOW}[-] Skipping GitHub install for $tool.${NC}\n"
        fi
    else
        echo -e "${RED}[✗] No suitable GitHub repo found for $tool.${NC}\n"
    fi
}

for tool in "${REQUIRED_TOOLS[@]}"; do
    echo -e "${YELLOW}[*] Checking $tool...${NC}"

    if is_installed "$tool"; then
        echo -e "${GREEN}[+] $tool is already installed.${NC}\n"
    else
        echo -e "${YELLOW}[-] Installing $tool via APT...${NC}"
        if apt install -y "$tool"; then
            echo -e "${GREEN}[✓] $tool installed successfully via APT.${NC}\n"
        else
            echo -e "${RED}[✗] Failed to install $tool via APT.${NC}"
            search_github_repo "$tool"
        fi
    fi
done

echo -e "${BLUE}[✓] All tools checked and processed.${NC}\n"
