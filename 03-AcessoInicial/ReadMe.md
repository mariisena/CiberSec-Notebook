# 03 - Acesso Inicial

**MITRE ATT&CK Tactic:** [TA0001 - Initial Access](https://attack.mitre.org/tactics/TA0001/)

## 📖 Sobre

Como o atacante consegue o **primeiro pé na rede** da vítima. É a entrada inicial no sistema.

## 🎯 Objetivo

Obter acesso inicial ao sistema/rede alvo usando diversas técnicas de exploração.

## 📚 Técnicas Principais

### T1190 - Exploit Public-Facing Application
- Exploração de vulnerabilidades web
- OWASP Top 10
- SQL Injection, RCE, File Upload
- Exploits de CVEs conhecidas

### T1133 - External Remote Services
- VPN mal configurada
- RDP exposto
- SSH com credenciais fracas
- Telnet, FTP

### T1566 - Phishing
- **T1566.001** - Spearphishing Attachment
- **T1566.002** - Spearphishing Link
- **T1566.003** - Spearphishing via Service

### T1078 - Valid Accounts
- Credenciais padrão (admin/admin)
- Credenciais vazadas
- Password spraying
- Credential stuffing

### T1189 - Drive-by Compromise
- Watering hole attacks
- Malvertising
- Exploit kits

## 🛠️ Técnicas por Categoria

### Web Application Attacks
```
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Remote Code Execution (RCE)
- File Upload vulnerabilities
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Insecure Deserialization
```

### Network Service Exploitation
```
- SMB (EternalBlue, MS17-010)
- SSH brute force
- FTP anonymous login
- Telnet exploitation
- SMTP open relay
```

### Client-Side Attacks
```
- Malicious Office macros
- PDF exploits
- Browser exploits
- USB rubber ducky
```

## 🎓 Labs Práticos

- [ ] Explorar SQLi em aplicação vulnerável (DVWA, SQLi-Labs)
- [ ] Upload de webshell
- [ ] Explorar EternalBlue no Metasploitable
- [ ] Phishing simulation (SET - Social Engineering Toolkit)
- [ ] Brute force SSH com Hydra

## 🛠️ Ferramentas

### Web Exploitation
- Burp Suite
- SQLmap
- Nikto
- Dirb/Gobuster
- Wfuzz

### Network Exploitation
- Metasploit Framework
- Searchsploit
- Hydra
- Medusa
- Ncrack

### Phishing
- SET (Social Engineering Toolkit)
- Gophish
- King Phisher

## 📝 Metodologia
```
1. Identificar serviços expostos (da fase de Recon)
2. Pesquisar vulnerabilidades conhecidas (CVE, Exploit-DB)
3. Testar credenciais padrão/fracas
4. Explorar vulnerabilidades identificadas
5. Obter shell/acesso inicial
6. Documentar vetor de ataque
```

## ⚠️ Red Flags - O que chamar atenção

- Múltiplas tentativas de login falhadas
- Scans de vulnerabilidades
- Tentativas de exploração
- Upload de arquivos suspeitos

## 📚 Recursos

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks - Initial Access](https://book.hacktricks.xyz/)
- [DVWA](https://github.com/digininja/DVWA)

---

**Anterior:** [02-DesenvRecursos](../02-DesenvRecursos/) | **Próximo:** [04-Execucao](../04-Execucao/)