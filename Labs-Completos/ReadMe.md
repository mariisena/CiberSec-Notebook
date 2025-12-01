# Labs Completos

## 📖 Sobre

Walkthroughs completos de máquinas, CTFs e labs práticos. Documentação end-to-end desde reconhecimento até pwned.

## 🗂️ Estrutura
````
Labs-Completos/
├── HackTheBox/
│   ├── Easy/
│   ├── Medium/
│   ├── Hard/
│   └── Insane/
├── TryHackMe/
│   ├── Beginner/
│   ├── Intermediate/
│   └── Advanced/
├── VulnHub/
├── CTF-Writeups/
│   ├── 2024/
│   └── 2025/
├── Custom-Labs/
└── Certificacoes/
    ├── eJPT-Prep/
    └── OSCP-Prep/
````

---

## 📝 Template de Writeup

Cada writeup deve seguir esta estrutura:
````markdown
# [Nome da Máquina/CTF]

## Informações

- **Plataforma:** HackTheBox / TryHackMe / VulnHub / CTF
- **Dificuldade:** Easy / Medium / Hard
- **OS:** Linux / Windows / Other
- **Data:** DD/MM/YYYY
- **IP:** 10.10.10.X
- **Pontos:** XX pts

## Skills Aprendidas

- Skill 1
- Skill 2
- Skill 3

## Ferramentas Utilizadas

- Nmap
- Gobuster
- Metasploit
- etc

---

## Reconhecimento

### Nmap Scan
```bash
# Initial scan
nmap -sC -sV -oN nmap/initial 10.10.10.X

# Full port scan
nmap -p- -oN nmap/full 10.10.10.X
```

**Resultados:**
- Porta 22: SSH
- Porta 80: HTTP
- Porta 445: SMB

### Web Enumeration
```bash
gobuster dir -u http://10.10.10.X -w /usr/share/wordlists/dirb/common.txt
```

---

## Exploitation

### Initial Access

Descrever como obteve acesso inicial:
- Vulnerabilidade explorada
- Comandos utilizados
- Screenshots importantes

### User Flag

Como obteve a flag de usuário.

### Privilege Escalation

Enumeração:
```bash
linpeas.sh / winpeas.exe
```

Vetor de escalação:
- Técnica utilizada
- Comandos

### Root Flag

Como obteve a flag de root.

---

## Lições Aprendidas

- Lição 1
- Lição 2
- Lição 3

## Referências

- Link 1
- Link 2
````

---

## 🎯 Objetivos de Progresso

### HackTheBox
- [ ] 10 máquinas Easy
- [ ] 5 máquinas Medium
- [ ] 3 máquinas Hard
- [ ] 1 máquina Insane

### TryHackMe
- [ ] 20 rooms completadas
- [ ] 5 learning paths
- [ ] King of the Hill participation

### VulnHub
- [ ] 10 VMs pwned
- [ ] Diversas categorias (boot2root, CTF-style, etc)

### CTFs
- [ ] 5 CTFs participados
- [ ] Top 100 placement em 1 CTF

---

## 📊 Estatísticas

### Por Plataforma
- **HackTheBox:** X máquinas
- **TryHackMe:** X rooms
- **VulnHub:** X VMs
- **CTFs:** X participações

### Por Dificuldade
- **Easy:** X
- **Medium:** X
- **Hard:** X
- **Insane:** X

### Por OS
- **Linux:** X
- **Windows:** X
- **Other:** X

---

## 🏆 Máquinas Favoritas

1. **[Nome]** - Motivo
2. **[Nome]** - Motivo
3. **[Nome]** - Motivo

---

## 📚 Recursos

- [HackTheBox](https://www.hackthebox.com)
- [TryHackMe](https://tryhackme.com)
- [VulnHub](https://vulnhub.com)
- [CTFtime](https://ctftime.org)
- [IppSec YouTube](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) - HTB walkthroughs

---

**Dica:** Sempre documente enquanto resolve! Não deixe para depois.