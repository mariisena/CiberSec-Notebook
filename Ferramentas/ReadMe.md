# Ferramentas

## 📖 Sobre

Scripts customizados, cheatsheets, configurações e ferramentas úteis para pentesting e cibersegurança.

## 🗂️ Estrutura
````
Ferramentas/
├── Scripts/
│   ├── Recon/
│   ├── Exploitation/
│   ├── Post-Exploitation/
│   └── Automation/
├── Cheatsheets/
│   ├── nmap-cheatsheet.md
│   ├── metasploit-cheatsheet.md
│   ├── sqlmap-cheatsheet.md
│   └── ...
├── Configs/
│   ├── .vimrc
│   ├── .tmux.conf
│   ├── burp-config.json
│   └── ...
└── Wordlists/
    ├── Custom/
    └── Generated/
````

---

## 🐍 Scripts

### Organização

Cada script deve ter:
- Header com descrição
- Usage/help
- Comentários explicativos
- Error handling

**Exemplo:**
````python
#!/usr/bin/env python3
"""
Script: port_scanner.py
Descrição: Scanner de portas TCP simples
Autor: Mariana
Data: DD/MM/YYYY
Usage: python3 port_scanner.py <target> <start_port> <end_port>
"""

import socket
import sys

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except:
        return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <target> <start_port> <end_port>")
        sys.exit(1)
    
    target = sys.argv[1]
    start = int(sys.argv[2])
    end = int(sys.argv[3])
    
    print(f"[*] Scanning {target} from port {start} to {end}")
    
    for port in range(start, end + 1):
        if scan_port(target, port):
            print(f"[+] Port {port} is OPEN")
````

---

## 📋 Cheatsheets

### Nmap Cheatsheet
````markdown
# Nmap Cheatsheet

## Basic Scans

# Quick scan
nmap TARGET

# Scan specific ports
nmap -p 22,80,443 TARGET

# Scan all ports
nmap -p- TARGET

# Fast scan (top 100 ports)
nmap -F TARGET

## Service/Version Detection

# Service version detection
nmap -sV TARGET

# OS detection
nmap -O TARGET

# Aggressive scan (OS, version, scripts, traceroute)
nmap -A TARGET

## Timing

# Paranoid (slowest, IDS evasion)
nmap -T0 TARGET

# Sneaky
nmap -T1 TARGET

# Polite (slower, less bandwidth)
nmap -T2 TARGET

# Normal (default)
nmap -T3 TARGET

# Aggressive (faster)
nmap -T4 TARGET

# Insane (fastest, may be inaccurate)
nmap -T5 TARGET

## NSE Scripts

# Default scripts
nmap -sC TARGET

# Specific script
nmap --script=vuln TARGET
nmap --script=http-enum TARGET

# Multiple scripts
nmap --script=http-*,ssh-* TARGET

## Output

# Normal output
nmap -oN output.txt TARGET

# XML output
nmap -oX output.xml TARGET

# Grepable output
nmap -oG output.grep TARGET

# All formats
nmap -oA output TARGET

## Firewall Evasion

# Fragment packets
nmap -f TARGET

# Specify MTU
nmap --mtu 24 TARGET

# Decoy scan
nmap -D RND:10 TARGET

# Spoof source port
nmap --source-port 53 TARGET

# Idle/Zombie scan
nmap -sI ZOMBIE_IP TARGET
````

---

## ⚙️ Configurações

### Kali Linux Setup
````bash
#!/bin/bash
# Kali Linux initial setup script

# Update system
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install -y \
    tmux \
    vim \
    git \
    python3-pip \
    gobuster \
    seclists \
    feroxbuster

# Python tools
pip3 install --upgrade pip
pip3 install impacket bloodhound pwntools

# Oh My Zsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# Tmux config
cat > ~/.tmux.conf << 'EOF'
# Remap prefix from 'C-b' to 'C-a'
unbind C-b
set-option -g prefix C-a
bind-key C-a send-prefix

# Split panes
bind | split-window -h
bind - split-window -v

# Mouse mode
set -g mouse on
EOF

echo "[+] Setup complete!"
````

---

## 📚 Wordlists Customizadas

### Gerando Wordlists
````bash
# CeWL - Spider website for words
cewl -d 2 -m 5 http://target.com -w wordlist.txt

# crunch - Generate wordlist
crunch 8 12 -o passwords.txt

# Custom wordlist for specific company
cat > company_passwords.txt << EOF
Company123
Company@2024
CompanyAdmin
EOF

# Combine wordlists
cat wordlist1.txt wordlist2.txt | sort -u > combined.txt
````

---

## 🛠️ Ferramentas Úteis

### Recon Automation
````bash
#!/bin/bash
# recon.sh - Automated recon script

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

mkdir -p recon/$TARGET

# Nmap
echo "[*] Running Nmap..."
nmap -sC -sV -oN recon/$TARGET/nmap.txt $TARGET

# Gobuster
echo "[*] Running Gobuster..."
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -o recon/$TARGET/gobuster.txt

# Nikto
echo "[*] Running Nikto..."
nikto -h http://$TARGET -o recon/$TARGET/nikto.txt

echo "[+] Recon complete! Check recon/$TARGET/"
````

---

## 📖 Recursos

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
- [GTFOBins](https://gtfobins.github.io/)
- [LOLBAS](https://lolbas-project.github.io/)
- [Pentester's Prompts](https://github.com/pentesteracademy)

---

**Dica:** Sempre adicione comentários e documentação nos seus scripts!