# 🔐 CiberSec-Notebook

> Repositório de estudos e labs ofensiva/defensiva de cibersegurança. Testes em ambientes controlados + notas técnicas documentadas.

[![GitHub](https://img.shields.io/badge/GitHub-CiberSec--Notebook-blue?logo=github)](https://github.com/seu-usuario/CiberSec-Notebook)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Em%20Desenvolvimento-yellow)]()
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)

---

## ⚠️ Disclaimer Legal

**IMPORTANTE:** Este repositório é exclusivamente para fins **educacionais e de pesquisa em segurança da informação**.

- ✅ Todos os testes são realizados em **ambientes controlados e autorizados**
- ✅ Labs pessoais: VMs isoladas (Kali Linux, Metasploitable, etc.)
- ✅ Plataformas legais: HackTheBox, TryHackMe, VulnHub, CTFs oficiais
- ❌ **NUNCA** realizar testes em sistemas sem autorização explícita
- ❌ O uso indevido dessas técnicas é **ilegal** e pode resultar em processos criminais

**Você é responsável por suas ações. Pratique ética hacker.**

---

## 📚 Sobre o Projeto

Este repositório documenta minha jornada de aprendizado em **Segurança Ofensiva e Defensiva**, seguindo as fases do Cyber Kill Chain e frameworks como CyBOK, OWASP e PTES.

### 🎯 Objetivos

- Documentar conhecimentos teóricos e práticos em cibersegurança
- Criar biblioteca pessoal de técnicas, ferramentas e scripts
- Desenvolver portfólio de habilidades em pentest e blue team
- Compartilhar conhecimento com a comunidade

---

## 🗂️ Estrutura do Repositório

### 📖 Framework MITRE ATT&CK

A estrutura segue as táticas do [MITRE ATT&CK Framework](https://attack.mitre.org/):

```
📁 00-Fundamentos/              # Base: redes, SO, criptografia, programação
📁 01-Reconhecimento/           # TA0043 - OSINT, passive/active recon
📁 02-DesenvRecursos/           # TA0042 - Payloads, exploits, scripts
📁 03-AcessoInicial/            # TA0001 - Web exploits, phishing, brute force
📁 04-Execucao/                 # TA0002 - Command execution, scripts
📁 05-Persistencia/             # TA0003 - Backdoors, scheduled tasks, services
📁 06-ElevacaoPrivilegios/      # TA0004 - SUID, sudo, UAC bypass, kernel exploits
📁 07-EvasaoDefesa/             # TA0005 - AV bypass, obfuscation, log clearing
📁 08-AcessoCredenciais/        # TA0006 - Credential dumping, password cracking
📁 09-Descoberta/               # TA0007 - System/network enumeration
📁 10-MovLateral/               # TA0008 - PSExec, WMI, RDP, Pass-the-Hash
📁 11-Coleta/                   # TA0009 - Data gathering, screenshots, keylogging
📁 12-ComandoControle/          # TA0011 - C2 frameworks, tunneling
📁 13-ExfiltImpacto/            # TA0010 + TA0040 - Data exfil, ransomware, wipers
📁 14-Forense/                  # DFIR - Disk/memory/network forensics
```

### 🛠️ Recursos Adicionais

```
📁 Labs-Completos/              # Walkthroughs HTB, THM, VulnHub, CTFs
    ├── HackTheBox/
    ├── TryHackMe/
    ├── VulnHub/
    └── CTF-Writeups/

📁 Ferramentas/                 # Scripts, cheatsheets, configs
    ├── Scripts/
    ├── Cheatsheets/
    ├── Configs/
    └── Wordlists/

📁 Resources/                   # Certificações, referências, glossário
    ├── Certificacoes/
    ├── Livros/
    ├── Cursos/
    └── Referencias/
```

---

## 🛠️ Ambiente de Lab

### Configuração Atual

- **Host:** Windows 11 / Linux
- **Virtualização:** VirtualBox
- **VMs:**
  - Kali Linux 2024.x (Offensive)
  - Metasploitable 2/3 (Target)
  - Windows 10/11 (Target)
- **Networking:** Host-Only + NAT

### Ferramentas Principais

#### Reconhecimento

- Nmap, Masscan, Gobuster, Feroxbuster
- theHarvester, Shodan, Recon-ng

#### Exploitation

- Metasploit Framework, Burp Suite, SQLmap
- Impacket, Responder, Nikto

#### Post-Exploitation

- Mimikatz, BloodHound, CrackMapExec
- LinPEAS, WinPEAS, PowerView

#### Análise

- Wireshark, Volatility, Autopsy
- Ghidra, Radare2, x64dbg

---

## 📖 Como Usar Este Repo

1. **Estudo Teórico:** Navegue pelas pastas seguindo o framework ATT&CK
2. **Prática:** Siga os labs documentados em `Labs-Completos/`
3. **Referência Rápida:** Use os cheatsheets em `Ferramentas/`
4. **Writeups:** Consulte soluções de CTFs anteriores
5. **Scripts:** Utilize ou adapte scripts em `Ferramentas/Scripts/`

### 📝 Template de Documentação

Cada lab/estudo segue o padrão:

- **Objetivo:** O que será testado/aprendido
- **Ambiente:** Configuração usada
- **Passos:** Metodologia detalhada
- **Ferramentas:** Comandos e tools utilizados
- **Resultados:** Findings e conclusões
- **Referências:** Links e materiais consultados

---

## 🎓 Trilha de Estudos

### ✅ Fase Atual: Fundamentos & Reconhecimento

**Concluído:**

- [x] Setup do ambiente de lab (Kali + Metasploitable)
- [x] Fundamentos de redes e protocolos
- [x] Primeiros scans com Nmap
- [x] Estruturação do repositório GitHub

**Em Andamento:**

- [ ] Reconhecimento ativo e passivo
- [ ] Enumeração de serviços
- [ ] Web exploitation básico (OWASP Top 10)

### 📋 Próximas Fases

**Q1 2025:**

- [ ] Exploitation básico (OWASP Top 10)
- [ ] Metasploit framework
- [ ] Privilege Escalation - Linux
- [ ] 20 máquinas TryHackMe (Easy)

**Q2 2025:**

- [ ] Web Application Pentesting avançado
- [ ] Privilege Escalation - Windows
- [ ] Active Directory basics
- [ ] **META: Certificação eJPT**
- [ ] 10 máquinas HackTheBox (Easy/Medium)

**Q3 2025:**

- [ ] Active Directory attacks
- [ ] Buffer Overflow
- [ ] Preparação intensiva OSCP
- [ ] CTF competitions
- [ ] **META: Certificação OSCP**

---

## 📊 Progresso por Área

### Offensive Security

**Reconhecimento**           ░░░░░░░░░░ 0%
**Scanning & Enumeration**   ░░░░░░░░░░ 0%
**Exploitation**             ░░░░░░░░░░ 0%
**Post-Exploitation**        ░░░░░░░░░░ 0%
**Privilege Escalation**     ░░░░░░░░░░ 0%  

### Defensive Security

**Hardening**                ░░░░░░░░░░ 0%
**Monitoring & Detection**   ░░░░░░░░░░ 0%
**Incident Response**        ░░░░░░░░░░ 0%
**Forensics**                ░░░░░░░░░░ 0%

### Skills Técnicas

**Python Scripting**         ░░░░░░░░░░ 0%  
**Bash Scripting**           ░░░░░░░░░░ 0%  
**Web Technologies**         ░░░░░░░░░░ 0%  
**Networking**               ░░░░░░░░░░ 0%  
**Linux**                    ░░░░░░░░░░ 0%  
**Windows**                  ███░░░░░░░ 30%  

---

## 🗺️ Roadmap de Estudos

### 2024

#### 📅 Novembro

- ✅ **Início dos estudos em Pentest**
  - Setup do ambiente de laboratório
  - Primeira VM comprometida (Metasploitable 2)
  - Participação no Café com Ciber

#### 📅 Dezembro  

- ✅ **Fundamentos consolidados**
  - 50+ horas de estudo em redes
  - Domínio básico do Nmap
  - Primeiros writeups documentados
  - Estruturação do CiberSec-Notebook

---

### 2025

#### 📅 Janeiro (Q1)

- 🔄 **Em andamento**
  - [ ] OWASP Top 10 - Web exploitation
  - [ ] 20 máquinas TryHackMe
  - [ ] Python para automação de pentest
  - [ ] Documentação completa de labs

#### 📅 Fevereiro-Março (Q1)

- 📋 **Planejado**
  - Privilege Escalation completo (Linux + Windows)
  - Metasploit framework avançado
  - Active Directory basics
  - **META: Certificação eJPT**

#### 📅 Abril-Junho (Q2)

- 🎯 **Objetivo**
  - Active Directory pentesting
  - Buffer Overflow (preparação OSCP)
  - 30+ máquinas HTB resolvidas
  - **META: Inscrição OSCP**

#### 📅 Julho-Setembro (Q3)

- 🚀 **Ambição**
  - Preparação intensiva OSCP
  - Red Team operations
  - Participação em CTFs
  - **META: Certificação OSCP**

---

## 🏆 Conquistas

### 🥉 Bronze Tier

- [x] 🔓 **First Blood** - Primeira VM comprometida
- [x] 🌐 **Network Ninja** - 100+ scans com Nmap
- [x] 🐍 **Script Kiddie** - Primeiro script Python funcional
- [x] 📝 **Documentador** - 10+ writeups publicados
- [x] ☕ **Café com Ciber** - Membro ativo da comunidade

### 🥈 Silver Tier (Em Progresso)

- [x] 🎯 **OSINT Master** - 50+ técnicas de reconhecimento
- [ ] 💉 **Exploit Developer** - 5 exploits custom funcionais
- [ ] 🔐 **Web Hacker** - OWASP Top 10 dominado (5/10)
- [ ] 📜 **eJPT Certified** - Primeira certificação
- [ ] 🏴 **CTF Player** - 10 CTFs participados

### 🥇 Gold Tier (Objetivos)

- [ ] 👑 **OSCP Certified** - A certificação dos sonhos
- [ ] 🎖️ **HTB Hacker** - Rank "Hacker" no HackTheBox
- [ ] 🛡️ **Blue Team** - Defender certificado
- [ ] 🌟 **Bug Bounty** - Primeira vulnerabilidade reportada
- [ ] 📚 **Mentor** - Ajudando outros na jornada

---

## 📚 Recursos e Referências

### Plataformas de Prática

- [HackTheBox](https://hackthebox.eu) - Labs e máquinas
- [TryHackMe](https://tryhackme.com) - Guided learning paths
- [VulnHub](https://vulnhub.com) - VMs vulneráveis
- [PentesterLab](https://pentesterlab.com) - Web app pentest

### Frameworks e Metodologias

- [MITRE ATT&CK](https://attack.mitre.org/) - Framework principal
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web vulnerabilities
- [CyBOK](https://www.cybok.org/) - Cybersecurity Body of Knowledge
- [PTES](http://www.pentest-standard.org/) - Penetration Testing Standard

### Recursos Essenciais

- [HackTricks](https://book.hacktricks.xyz/) - Técnicas e metodologias
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Payloads repository
- [GTFOBins](https://gtfobins.github.io/) - Unix binaries exploitation
- [LOLBAS](https://lolbas-project.github.io/) - Windows binaries

### Comunidades

- **Café com Ciber** - Grupo de estudos em cibersegurança

---

## 🤝 Contribuições

Este é um repositório de estudo **pessoal**, mas feedbacks e sugestões são bem-vindos!

- 💡 Encontrou algum erro? Abra uma issue
- 🚀 Tem uma sugestão de melhoria? Pull requests são aceitos
- 💬 Quer trocar ideias sobre ciber? Me manda mensagem!

---

## 📫 Contato

- GitHub: [@mariisena](https://github.com/mariisena)
- LinkedIn: [marianarsena](https://www.linkedin.com/in/marianarsena/)
- Email: [...]

---

## 📄 Licença

Este projeto está sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## 🙏 Agradecimentos

- **Café com Ciber (UnB)** - Comunidade de cibersegurança

---

<h3 align="center">
  <i>"Hack the planet, but ethically!" 🌍🔓</i>
</h3>

<h3 align="center">
  <b>Stay curious. Stay ethical. Keep hacking.</b>
</h3>

<h2 align="center">
  Made with ☕ and 💻 by Mariana
</h2>

<p align="center">
  <img src="https://img.shields.io/github/last-commit/seu-usuario/CiberSec-Notebook?style=flat-square" alt="Last Commit">
  <img src="https://img.shields.io/github/stars/seu-usuario/CiberSec-Notebook?style=flat-square" alt="Stars">
</p>
