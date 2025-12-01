# 14 - Forense Digital

## 📖 Sobre

Análise forense digital para **investigar incidentes de segurança**, **responder a ataques** e **coletar evidências**. Perspectiva de **Blue Team/DFIR**.

## 🎯 Objetivo

- Identificar como o ataque aconteceu
- Coletar evidências digitais
- Determinar escopo do comprometimento
- Suportar ações legais
- Melhorar postura de segurança

---

## 📚 Áreas da Forense Digital

### 1. Disk Forensics
- Análise de filesystems
- Recuperação de dados deletados
- Timeline analysis
- Carved files

### 2. Memory Forensics
- Análise de RAM dumps
- Processos maliciosos
- Network connections
- Injeção de código

### 3. Network Forensics
- Análise de tráfego (PCAP)
- Detecção de C2
- Data exfiltration
- Lateral movement

### 4. Log Analysis
- Event logs (Windows)
- Syslog (Linux)
- Application logs
- Web server logs

### 5. Malware Analysis
- Static analysis
- Dynamic analysis
- Reverse engineering
- Indicators of Compromise (IOCs)

---

## 🛠️ Metodologia Forense

### 1. Identificação
```
- Detectar o incidente
- Determinar escopo inicial
- Identificar sistemas afetados
```

### 2. Preservação
```
- Isolar sistemas comprometidos
- Criar imagens forenses
- Chain of custody
- Documentar tudo
```

### 3. Coleta
```
- Memory dump
- Disk imaging
- Network captures
- Logs
```

### 4. Análise
```
- Timeline analysis
- Artifact examination
- IOC identification
- Root cause analysis
```

### 5. Documentação
```
- Relatório técnico
- Timeline de eventos
- IOCs
- Recomendações
```

### 6. Apresentação
```
- Relatório executivo
- Briefing técnico
- Lessons learned
```

---

## 🛠️ Disk Forensics

### Imaging
```bash
# dd - Criar imagem do disco
dd if=/dev/sda of=/mnt/evidence/disk.img bs=4M status=progress

# dc3dd - Versão melhorada
dc3dd if=/dev/sda of=/mnt/evidence/disk.img hash=md5 hash=sha256 log=/mnt/evidence/disk.log

# FTK Imager (Windows GUI)
# Autopsy (GUI multiplataforma)
```

### File System Analysis
```bash
# Montar imagem como read-only
mount -o ro,loop disk.img /mnt/analysis

# The Sleuth Kit (TSK)
# Listar arquivos
fls -r disk.img

# istat - File metadata
istat disk.img 12345

# icat - Extrair arquivo
icat disk.img 12345 > recovered_file.txt

# Timeline creation
fls -r -m C: disk.img > bodyfile
mactime -b bodyfile -d > timeline.csv
```

### Deleted File Recovery
```bash
# Foremost - File carving
foremost -t all -i disk.img -o recovered/

# Scalpel - File carving
scalpel disk.img -o recovered/

# PhotoRec - Recovery tool
photorec disk.img
```

### Tools
- **Autopsy** - Forensic platform
- **The Sleuth Kit (TSK)** - CLI tools
- **FTK Imager** - Imaging tool
- **EnCase** - Commercial suite
- **X-Ways Forensics** - Commercial

---

## 🛠️ Memory Forensics

### Memory Acquisition
```bash
# Linux - LiME (Linux Memory Extractor)
insmod lime.ko "path=/tmp/ram.lime format=lime"

# Windows - DumpIt
DumpIt.exe

# Windows - WinPMEM
winpmem_mini_x64.exe mem.raw

# FTK Imager - Memory capture
```

### Volatility Analysis
```bash
# Identify OS profile
volatility -f memory.raw imageinfo

# List processes
volatility -f memory.raw --profile=Win10x64 pslist
volatility -f memory.raw --profile=Win10x64 pstree

# Network connections
volatility -f memory.raw --profile=Win10x64 netscan

# Command line
volatility -f memory.raw --profile=Win10x64 cmdline

# DLL list
volatility -f memory.raw --profile=Win10x64 dlllist -p PID

# Dump process
volatility -f memory.raw --profile=Win10x64 procdump -p PID --dump-dir=output/

# Scan for malware
volatility -f memory.raw --profile=Win10x64 malfind
volatility -f memory.raw --profile=Win10x64 apihooks

# Registry hives
volatility -f memory.raw --profile=Win10x64 hivelist
volatility -f memory.raw --profile=Win10x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"

# Filescan
volatility -f memory.raw --profile=Win10x64 filescan | grep -i "malware"
```

### Tools
- **Volatility** - Memory analysis framework
- **Rekall** - Memory forensics
- **Redline** - FireEye tool

---

## 🛠️ Network Forensics

### PCAP Analysis
```bash
# Wireshark - GUI
wireshark capture.pcap

# tcpdump - Capture
tcpdump -i eth0 -w capture.pcap

# tshark - CLI Wireshark
# Filter HTTP traffic
tshark -r capture.pcap -Y "http"

# Extract HTTP objects
tshark -r capture.pcap --export-objects http,/tmp/http_objects

# Statistics
tshark -r capture.pcap -q -z io,stat,1
tshark -r capture.pcap -q -z conv,tcp

# NetworkMiner - Extract files/creds
NetworkMiner.exe
```

### Zeek (Bro) Analysis
```bash
# Process PCAP with Zeek
zeek -r capture.pcap

# Analyze logs
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service
cat http.log | zeek-cut ts id.orig_h method host uri
cat dns.log | zeek-cut ts id.orig_h query answers
```

### C2 Detection
```bash
# RITA - Beacon detection
rita import /path/to/zeek/logs dataset_name
rita show-beacons dataset_name
rita show-long-connections dataset_name
```

### Tools
- **Wireshark** - Packet analyzer
- **NetworkMiner** - Network forensics
- **Zeek (Bro)** - Network monitor
- **RITA** - Threat hunting

---

## 🛠️ Log Analysis

### Windows Event Logs
```powershell
# PowerShell - Query events
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624}

# Successful logons (4624)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624}

# Failed logons (4625)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}

# Account lockouts (4740)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740}

# Process creation (4688 - requires audit policy)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688}

# Export to CSV
Get-WinEvent -LogName Security | Export-Csv -Path logs.csv

# EvtxECmd - Parse EVTX files
EvtxECmd.exe -f Security.evtx --csv output/
```

### Linux Logs
```bash
# Authentication logs
cat /var/log/auth.log | grep "Failed password"
cat /var/log/secure | grep "authentication failure"

# SSH logins
last -f /var/log/wtmp
lastlog

# Sudo usage
cat /var/log/auth.log | grep sudo

# Cron jobs
cat /var/log/syslog | grep CRON
```

### Web Server Logs
```bash
# Apache access log analysis
cat access.log | awk '{print $1}' | sort | uniq -c | sort -rn

# Failed requests (4xx, 5xx)
cat access.log | grep " 404 "
cat access.log | grep " 500 "

# Suspicious patterns
cat access.log | grep -i "select\|union\|exec\|script"
cat access.log | grep -E "(\.\./|\.\.\\)"  # Directory traversal
```

### Tools
- **Chainsaw** - Windows event log analysis
- **Hayabusa** - Windows event log analyzer
- **Splunk** - SIEM platform
- **ELK Stack** - Elasticsearch, Logstash, Kibana
- **Graylog** - Log management

---

## 🛠️ Malware Analysis

### Static Analysis
```bash
# File info
file malware.exe
strings malware.exe | less
exiftool malware.exe

# Hashes
md5sum malware.exe
sha256sum malware.exe

# VirusTotal
# Upload hash (not file to avoid leaking sample)

# PE analysis
pefile malware.exe
peframe malware.exe

# Strings interesting
strings malware.exe | grep -i "http"
strings malware.exe | grep -i "password"
strings malware.exe | grep -i "key"

# Disassembly
objdump -d malware.exe
radare2 malware.exe
ghidra malware.exe  # GUI
```

### Dynamic Analysis
```bash
# Process Monitor (Windows - Sysinternals)
procmon.exe

# API Monitor
apimonitor.exe

# Regshot - Registry changes
regshot.exe

# Wireshark - Network activity
wireshark

# Linux sandbox
firejail --net=none malware.bin

# Cuckoo Sandbox - Automated analysis
cuckoo submit malware.exe
```

### Tools
- **Ghidra** - Reverse engineering
- **IDA Pro** - Disassembler (comercial)
- **x64dbg** - Debugger
- **Cuckoo Sandbox** - Automated malware analysis
- **REMnux** - Linux distro for malware analysis
- **FLARE VM** - Windows malware analysis VM

---

## 🎓 Labs Práticos

### Disk Forensics
- [ ] Criar imagem forense de disco
- [ ] Análise de filesystem com Autopsy
- [ ] Recuperar arquivos deletados
- [ ] Timeline analysis

### Memory Forensics
- [ ] Capturar memory dump
- [ ] Volatility analysis - processos, network
- [ ] Identificar processo malicioso
- [ ] Dump e análise de processo

### Network Forensics
- [ ] Análise de PCAP com Wireshark
- [ ] Extrair arquivos de tráfego HTTP
- [ ] Detectar C2 beaconing
- [ ] Zeek log analysis

### Log Analysis
- [ ] Análise de Windows Event Logs
- [ ] Identificar failed login attempts
- [ ] Correlacionar eventos de ataque
- [ ] Web server log analysis

### Malware Analysis
- [ ] Static analysis de malware
- [ ] Dynamic analysis em sandbox
- [ ] Reversing básico com Ghidra
- [ ] Extrair IOCs

---

## 📝 Key Event IDs (Windows)
```
Logon/Logoff:
4624 - Successful logon
4625 - Failed logon
4634 - Logoff
4647 - User initiated logoff
4648 - Logon with explicit credentials

Account Management:
4720 - Account created
4722 - Account enabled
4724 - Password reset attempt
4738 - Account changed
4740 - Account locked out

Process:
4688 - Process creation (requires audit policy)
4689 - Process termination

Service:
7045 - Service installed

PowerShell:
4103 - Module logging
4104 - Script block logging

Sysmon:
1 - Process creation
3 - Network connection
7 - Image loaded
10 - Process access
11 - File created
```

---

## 📚 Recursos

- [SANS DFIR Cheat Sheets](https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/)
- [Volatility Cheatsheet](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
- [Eric Zimmerman Tools](https://ericzimmerman.github.io/)
- [The Sleuth Kit](http://www.sleuthkit.org/sleuthkit/)
- [Awesome Incident Response](https://github.com/meirwah/awesome-incident-response)

---

**Anterior:** [13-ExfiltImpacto](../13-ExfiltImpacto/)