# 01 - Reconhecimento

**MITRE ATT&CK Tactic:** [TA0043 - Reconnaissance](https://attack.mitre.org/tactics/TA0043/)

## 📖 Sobre

Primeira fase do kill chain. Coletar informações sobre o alvo SEM interagir diretamente com os sistemas (passive) ou COM interação mínima (active).

## 🎯 Objetivo

Mapear superfície de ataque, identificar alvos, coletar informações públicas.

## 📚 Técnicas

### Reconhecimento Passivo (OSINT)
- **T1589** - Gather Victim Identity Information
  - LinkedIn, redes sociais
  - Vazamentos de dados (HaveIBeenPwned)
  - Google Dorking
  - Shodan, Censys
  
- **T1590** - Gather Victim Network Information
  - Whois, DNS records
  - ASN lookups
  - Subdomain enumeration (passivo)

- **T1591** - Gather Victim Org Information
  - Site da empresa
  - Notícias, comunicados
  - Tecnologias usadas (Wappalyzer, BuiltWith)

### Reconhecimento Ativo
- **T1595** - Active Scanning
  - Port scanning (Nmap)
  - Service enumeration
  - Vulnerability scanning
  - Web crawling

## 🛠️ Ferramentas

### Passive OSINT
- theHarvester
- Maltego
- Recon-ng
- Shodan
- Google Dorks
- WHOIS lookup

### Active Recon
- Nmap
- Masscan
- DNSrecon
- Sublist3r
- Amass

## 📝 Metodologia
```
1. Definir escopo
2. OSINT - Coletar info pública
3. Mapear infraestrutura (IPs, domínios, subdomínios)
4. Identificar tecnologias
5. Scan ativo (portas, serviços)
6. Documentar findings
```

## 🎓 Labs Sugeridos

- [ ] OSINT de empresa fictícia
- [ ] Enumerar subdomínios de site público
- [ ] Scan completo com Nmap (SYN, UDP, scripts NSE)
- [ ] Google Dorking challenges

## ⚠️ Atenção

**Reconhecimento ativo pode ser detectado!** IDS/IPS podem identificar scans. Em ambientes reais, sempre ter autorização por escrito.

## 📚 Recursos

- [OSINT Framework](https://osintframework.com/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)

---

**Anterior:** [00-Fundamentos](../00-Fundamentos/) | **Próximo:** [02-DesenvRecursos](../02-DesenvRecursos/)