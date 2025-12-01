# 02 - Desenvolvimento de Recursos

**MITRE ATT&CK Tactic:** [TA0042 - Resource Development](https://attack.mitre.org/tactics/TA0042/)

## 📖 Sobre

Criar, comprar ou roubar recursos necessários para o ataque. Preparação de payloads, infraestrutura, ferramentas customizadas.

## 🎯 Objetivo

Desenvolver e preparar recursos técnicos que serão usados nas próximas fases do ataque.

## 📚 Técnicas

### T1583 - Acquire Infrastructure
- Domínios para C2
- Servidores VPS
- Infraestrutura cloud

### T1585 - Establish Accounts
- Email accounts
- Social media accounts
- Cloud service accounts

### T1586 - Compromise Accounts
- Contas comprometidas para phishing
- Credenciais vazadas

### T1587 - Develop Capabilities
- **Malware customizado**
- **Exploits (0-day ou public)**
- **Payloads (reverse shells, bind shells)**
- Certificados digitais

### T1588 - Obtain Capabilities
- Malware de terceiros
- Exploits públicos (Exploit-DB)
- Ferramentas (Metasploit, Cobalt Strike)

## 🛠️ O que vai nesta pasta

### Payloads/
- Reverse shells (Python, Bash, PowerShell)
- Meterpreter payloads
- Web shells (PHP, ASP, JSP)
- Ofuscação de payloads

### Exploits/
- PoCs de CVEs
- Exploits customizados
- Buffer overflow exploits

### Scripts/
- Automação de tarefas
- Scanners customizados
- Brute force scripts
- Password crackers

### Wordlists/
- Wordlists customizadas
- Senhas comuns BR
- Usuários comuns

### Phishing/
- Templates de email
- Páginas de phishing (clone)
- Documentos maliciosos (macros)

## 🎓 Exercícios Práticos

- [ ] Criar reverse shell em Python
- [ ] Gerar payload com msfvenom
- [ ] Ofuscar payload com encoders
- [ ] Criar wordlist customizada com CeWL
- [ ] Desenvolver scanner de portas em Python

## 🛠️ Ferramentas Essenciais

- **msfvenom** - Geração de payloads
- **TheFatRat** - Wrapper para payloads
- **Veil Framework** - Evasion de AV
- **CeWL** - Custom wordlist generator
- **Ghidra/IDA** - Engenharia reversa

## ⚠️ Disclaimer

**Desenvolva apenas para fins educacionais e em ambientes controlados.** Criação de malware para uso não autorizado é crime.

## 📚 Recursos

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [Exploit-DB](https://www.exploit-db.com/)
- [Metasploit Unleashed](https://www.metasploit.com/unleashed/)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)

---

**Anterior:** [01-Reconhecimento](../01-Reconhecimento/) | **Próximo:** [03-AcessoInicial](../03-AcessoInicial/)