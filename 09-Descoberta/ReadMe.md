# 09 - Descoberta

**MITRE ATT&CK Tactic:** [TA0007 - Discovery](https://attack.mitre.org/tactics/TA0007/)

## 📖 Sobre

Técnicas para **obter conhecimento** sobre o sistema e ambiente interno após obter acesso. Mapear a rede, usuários, processos, serviços, etc.

## 🎯 Objetivo

Entender o ambiente comprometido: topologia de rede, sistemas conectados, usuários, grupos, processos, software instalado, etc.

## 📚 Técnicas Principais

### T1087 - Account Discovery
- **T1087.001** - Local Account
- **T1087.002** - Domain Account
- **T1087.003** - Email Account
- **T1087.004** - Cloud Account

### T1217 - Browser Bookmark Discovery
- Descobrir sites acessados
- Mapear recursos internos

### T1580 - Cloud Infrastructure Discovery
- Enumerar recursos cloud
- Metadados de instâncias

### T1538 - Cloud Service Dashboard
- Acessar dashboards cloud
- Descobrir configurações

### T1526 - Cloud Service Discovery
- Listar serviços cloud ativos

### T1613 - Container and Resource Discovery
- Docker, Kubernetes
- Containers em execução

### T1482 - Domain Trust Discovery
- Descobrir trusts do AD
- Mapear domínios relacionados

### T1083 - File and Directory Discovery
- Enumerar filesystem
- Procurar arquivos sensíveis

### T1615 - Group Policy Discovery
- GPOs aplicadas
- Políticas de domínio

### T1069 - Permission Groups Discovery
- **T1069.001** - Local Groups
- **T1069.002** - Domain Groups
- **T1069.003** - Cloud Groups

### T1057 - Process Discovery
- Listar processos em execução
- Identificar AV/EDR

### T1012 - Query Registry
- Enumerar registry keys
- Descobrir configurações

### T1018 - Remote System Discovery
- Descobrir outros sistemas na rede
- Targets para lateral movement

### T1518 - Software Discovery
- **T1518.001** - Security Software Discovery
- Software instalado
- Versões de aplicações

### T1082 - System Information Discovery
- Hostname, OS, arquitetura
- Patches instalados
- Configurações do sistema

### T1016 - System Network Configuration Discovery
- **T1016.001** - Internet Connection Discovery
- Configuração de rede
- DNS, gateways, rotas

### T1049 - System Network Connections Discovery
- Conexões ativas
- Portas listening

### T1033 - System Owner/User Discovery
- Usuário atual
- Usuários logados
- Histórico de logins

### T1007 - System Service Discovery
- Serviços instalados
- Serviços em execução

### T1124 - System Time Discovery
- Data/hora do sistema
- Timezone

## 🛠️ Comandos de Descoberta

### Windows Discovery

#### System Information
```powershell
# Informações básicas
systeminfo
hostname
whoami
whoami /priv
whoami /groups

# OS e arquitetura
wmic os get caption,version,osarchitecture

# Patches instalados
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Domínio
echo %userdomain%
wmic computersystem get domain
```

#### Network Discovery
```powershell
# Configuração de rede
ipconfig /all
route print
arp -a

# Conexões ativas
netstat -ano
netstat -anob

# Shares
net share
net view \\computername

# DNS cache
ipconfig /displaydns
```

#### User & Group Discovery
```powershell
# Usuários locais
net user
net user username

# Grupos locais
net localgroup
net localgroup Administrators

# Domain users (se em domínio)
net user /domain
net group "Domain Admins" /domain

# Usuários logados
query user
qwinsta
```

#### Process & Service Discovery
```powershell
# Processos
tasklist
tasklist /svc
wmic process get name,processid,commandline

# Serviços
sc query
net start
wmic service list brief
```

#### Software Discovery
```powershell
# Programas instalados
wmic product get name,version
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

# Antivírus
wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayname
```

#### File Discovery
```powershell
# Procurar arquivos interessantes
dir /s *pass*.txt
dir /s *admin*.txt
dir /s *.config

# Procurar em todos os drives
dir C:\ /s /b | findstr /i "password credential"
```

#### Active Directory Discovery
```powershell
# PowerView (PowerShell)
Get-NetDomain
Get-NetDomainController
Get-NetUser
Get-NetGroup
Get-NetComputer
Get-DomainTrust

# Native commands
nltest /domain_trusts
nltest /dclist:domain.local
```

### Linux Discovery

#### System Information
```bash
# Informações básicas
uname -a
hostname
cat /etc/issue
cat /etc/os-release
lsb_release -a

# Informações de hardware
lscpu
lsmem
free -h
df -h
```

#### Network Discovery
```bash
# Configuração de rede
ifconfig
ip a
ip route
cat /etc/resolv.conf

# Conexões ativas
netstat -antup
ss -tulpn

# ARP table
arp -a
ip neigh

# Network shares
showmount -e IP
```

#### User & Group Discovery
```bash
# Usuários
cat /etc/passwd
cat /etc/group
w
who
last
lastlog

# Usuário atual
id
groups

# Sudoers
sudo -l
cat /etc/sudoers
```

#### Process Discovery
```bash
# Processos
ps aux
ps -ef
top
htop

# Procurar processos específicos
ps aux | grep -i root
pgrep -u root
```

#### Service Discovery
```bash
# Systemd
systemctl list-units --type=service
systemctl status servicename

# SysV init
service --status-all
chkconfig --list
```

#### File Discovery
```bash
# Procurar arquivos sensíveis
find / -name "*.conf" 2>/dev/null
find / -name "*.config" 2>/dev/null
find / -name "*password*" 2>/dev/null
find / -name "*credential*" 2>/dev/null

# Arquivos recentemente modificados
find / -type f -mtime -7 2>/dev/null

# SUID files
find / -perm -4000 2>/dev/null
```

#### Installed Software
```bash
# Debian/Ubuntu
dpkg -l
apt list --installed

# RedHat/CentOS
rpm -qa
yum list installed

# Versões
python --version
gcc --version
```

### Network Scanning (Post-Exploitation)
```bash
# Ping sweep (descobrir hosts vivos)
for i in {1..254}; do ping -c 1 192.168.1.$i | grep "64 bytes"; done

# Nmap (se disponível)
nmap -sn 192.168.1.0/24  # Host discovery
nmap -p- -T4 192.168.1.10  # Port scan

# Netcat port scan
nc -zv 192.168.1.10 1-1000

# PowerShell ping sweep
1..254 | % {Test-Connection -ComputerName "192.168.1.$_" -Count 1 -Quiet}
```

## 🎓 Labs Práticos

### Windows
- [ ] Enumerar informações do sistema
- [ ] Descobrir usuários e grupos do domínio
- [ ] Mapear rede interna (hosts, shares)
- [ ] Identificar AV/EDR instalado
- [ ] Descobrir processos e serviços sensíveis

### Linux
- [ ] Enumerar sistema e usuários
- [ ] Descobrir configuração de rede
- [ ] Procurar arquivos sensíveis
- [ ] Mapear processos executando como root
- [ ] Identificar serviços vulneráveis

### Active Directory
- [ ] Enumerar domínio com PowerView
- [ ] Descobrir Domain Admins
- [ ] Mapear trusts de domínio
- [ ] Listar GPOs aplicadas
- [ ] Descobrir SPNs (prep para Kerberoasting)

## 🛠️ Ferramentas de Enumeration

### Windows
- **PowerView** - AD enumeration
- **SharpHound** - BloodHound collector
- **ADRecon** - AD reconnaissance
- **WinPEAS** - Automated enumeration
- **Seatbelt** - Security enumeration

### Linux
- **LinEnum** - Automated enumeration
- **LinPEAS** - Privilege escalation enumeration
- **linux-smart-enumeration (lse)**
- **enum4linux** - SMB enumeration

### Network
- **Nmap** - Network mapper
- **Netdiscover** - ARP scanner
- **Responder** - LLMNR/NBT-NS poisoner
- **CrackMapExec** - SMB/AD enumeration

### Multi-platform
- **BloodHound** - AD attack paths
- **Impacket scripts** - Various enumeration tools

## 📝 Checklist de Descoberta

### Sistema
```
[ ] Hostname e domínio
[ ] Sistema operacional e versão
[ ] Arquitetura (x86/x64)
[ ] Patches instalados
[ ] Antivírus/EDR
[ ] Software instalado
```

### Rede
```
[ ] Endereços IP e interfaces
[ ] Rotas e gateways
[ ] DNS servers
[ ] Conexões ativas
[ ] Shares de rede
[ ] Outros hosts na rede
```

### Usuários
```
[ ] Usuário atual e privilégios
[ ] Usuários locais
[ ] Grupos locais
[ ] Domain users (se aplicável)
[ ] Usuários logados
[ ] Histórico de logins
```

### Processos e Serviços
```
[ ] Processos em execução
[ ] Serviços instalados
[ ] Scheduled tasks/cron jobs
[ ] Aplicações sensíveis
```

## 🔍 Detecção

### Indicadores
- Enumeração excessiva de AD
- Queries de registry suspeitas
- Network scanning interno
- Múltiplas consultas LDAP
- BloodHound/SharpHound executando
- PowerView commands

### Defesa
- Monitorar enumeração de AD
- Detectar BloodHound ingestion
- Logs de LDAP queries
- Network IDS para scans internos

## 📚 Recursos

- [HackTricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [PowerView Cheatsheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
- [PayloadsAllTheThings - Windows Discovery](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

---

**Anterior:** [08-AcessoCredenciais](../08-AcessoCredenciais/) | **Próximo:** [10-MovLateral](../10-MovLateral/)