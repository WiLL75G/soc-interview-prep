# SOC Analyst Interview Prep Complete Guide
### Tier 1 & Tier 2 | Blue Team | Entry to Mid Level

---

## What SOC Interviews Actually Test

Interviewers probe 6 core areas. Every section below covers what to know, how to answer, and what follow up questions to expect.

---

## 1. Security Fundamentals

### Networking

**TCP IP Model Layers (Know All 4)**

| Layer | Name | Examples |
|-------|------|---------|
| 4 | Application | HTTP, DNS, FTP, SMTP |
| 3 | Transport | TCP, UDP |
| 2 | Internet | IP, ICMP |
| 1 | Network Access | Ethernet, ARP |

**TCP vs UDP**

| Feature | TCP | UDP |
|---------|-----|-----|
| Connection | Connection oriented | Connectionless |
| Reliability | Guaranteed delivery | Best effort |
| Speed | Slower | Faster |
| Use Cases | HTTP, SSH, SMTP | DNS, VoIP, streaming |
| Handshake | 3 way (SYN, SYN ACK, ACK) | None |

**Common Ports, Memorize These**

| Port | Protocol | Service |
|------|----------|---------|
| 20 and 21 | TCP | FTP (data and control) |
| 22 | TCP | SSH |
| 23 | TCP | Telnet (insecure) |
| 25 | TCP | SMTP |
| 53 | TCP or UDP | DNS |
| 67 and 68 | UDP | DHCP |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 |
| 143 | TCP | IMAP |
| 389 | TCP or UDP | LDAP |
| 443 | TCP | HTTPS |
| 445 | TCP | SMB |
| 3306 | TCP | MySQL |
| 3389 | TCP | RDP |
| 8080 | TCP | HTTP Alternate |

**DNS Resolution (Full Answer)**

Q: What happens when you type a URL in a browser?

1. Browser checks local cache
2. OS checks hosts file
3. Recursive DNS query sent to configured DNS resolver
4. Resolver queries root to TLD to authoritative nameserver
5. IP returned and cached (TTL-based)
6. TCP 3 way handshake with web server (SYN to SYN ACK to ACK)
7. TLS handshake if HTTPS (certificate exchange, session key negotiation)
8. HTTP GET request sent
9. Server responds with content

**OSI Model (Common Trap Question)**

| Layer | Name | Protocol Examples |
|-------|------|------------------|
| 7 | Application | HTTP, DNS, FTP |
| 6 | Presentation | SSL and TLS, encoding |
| 5 | Session | NetBIOS, RPC |
| 4 | Transport | TCP, UDP |
| 3 | Network | IP, ICMP, ARP |
| 2 | Data Link | Ethernet, MAC |
| 1 | Physical | Cables, NICs |

> SOC context: Attacks happen at all layers. Phishing = Layer 7. ARP poisoning = Layer 2. IP spoofing = Layer 3.

---

### Core Security Concepts

**CIA Triad**

| Pillar | Definition | Attack Example | Control Example |
|--------|-----------|----------------|----------------|
| Confidentiality | Data only accessible to authorized users | Data exfiltration, eavesdropping | Encryption, access controls |
| Integrity | Data is accurate and unmodified | Man in the Middle, ransomware | Hashing (MD5, SHA), digital signatures |
| Availability | Systems accessible when needed | DDoS, ransomware | Redundancy, backups, failover |

**Vulnerability vs Risk vs Threat**

- **Vulnerability**: A weakness in a system (e.g., unpatched CVE)
- **Threat**: An actor or event that could exploit it (e.g., a ransomware group)
- **Risk**: The likelihood x impact of that exploitation

**Least Privilege**

Users and systems should have the minimum permissions needed to do their job. Why it matters in SOC: privilege escalation attacks fail faster when privilege is constrained.

**Defense in Depth**

Layered security controls so no single failure is catastrophic. Example layers: firewall to IDS and IPS to endpoint AV to SIEM alerting to user training.

---

## 2. Windows Event IDs, Critical for SOC

These appear in real alerts. Know what they mean.

| Event ID | Meaning | Why It Matters |
|----------|---------|----------------|
| 4624 | Successful logon | Baseline; look for unusual times and locations |
| 4625 | Failed logon | Brute force indicator |
| 4634 | Account logoff | Session tracking |
| 4648 | Logon with explicit credentials | Pass the hash, lateral movement |
| 4662 | Object accessed in AD | Possible AD enumeration |
| 4672 | Special privileges assigned | Admin-level logon |
| 4688 | New process created | Malware execution |
| 4697 | Service installed | Persistence technique |
| 4719 | Audit policy changed | Attacker covering tracks |
| 4720 | User account created | Backdoor account creation |
| 4728 | User added to security group | Privilege escalation |
| 4732 | User added to local admin group | Privilege escalation |
| 4768 and 4769 | Kerberos ticket requests | Kerberoasting detection |
| 4776 | NTLM authentication | Credential attacks |
| 7045 | New service installed | Persistence |
| 1102 | Audit log cleared | Attacker covering tracks, CRITICAL |

**Example answer if asked about brute force detection:**

"I'd correlate Event ID 4625 (failed logon) looking for multiple failures against a single account from the same source IP within a short window, followed by 4624 (success). That pattern suggests a successful brute force. I'd then check 4648 for any lateral movement using the compromised credential."

---

## 3. Linux Commands for SOC Analysis

You will be asked "what command would you use to..."

**Log Analysis**

```bash
# View authentication logs
cat /var/log/auth.log
tail -f /var/log/auth.log          # Live follow

# Search for failed logins
grep "Failed password" /var/log/auth.log
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# Search for successful logins
grep "Accepted password" /var/log/auth.log

# Count failed attempts by IP
grep "Failed password" /var/log/auth.log | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn
```

**Process & Network Investigation**

```bash
# Running processes
ps aux
ps aux | grep suspicious_name

# Network connections
netstat -tulnp           # Active listening ports
ss -tulnp                # Modern equivalent
netstat -anp | grep ESTABLISHED

# Find what process owns a connection
lsof -i :4444            # Who is using port 4444?
lsof -i -n -P           # All network connections with PIDs

# Check for unusual cron jobs
crontab -l
cat /etc/crontab
ls /etc/cron.*
```

**File Investigation**

```bash
# Recently modified files
find / -mmin -60 -type f 2>/dev/null         # Modified in last 60 min
find /tmp /var/tmp -type f -executable        # Executables in temp dirs

# File hashing (integrity checking)
md5sum suspicious_file
sha256sum suspicious_file

# Check file type (don't trust extensions)
file suspicious_file

# String analysis of a binary
strings malware_sample | grep -i "http"
```

**User & Account Investigation**

```bash
# Last logins
last
lastb                    # Failed login attempts
who                      # Currently logged in users
w                        # Who and what they're doing

# Check sudoers
cat /etc/sudoers
sudo -l -U username

# Accounts with shells (potential backdoors)
grep -v nologin /etc/passwd | grep -v false
```

---

## 4. Incident Detection & Response

### IR Lifecycle

1. **Preparation** — Policies, playbooks, tools in place
2. **Detection & Identification** Alert fires, analyst triages
3. **Containment** Stop the bleeding (isolate host, block IP)
4. **Eradication** Remove malware, close access vector
5. **Recovery** Restore systems, verify clean state
6. **Lessons Learned** Post-incident review, improve defenses

### Triage Priority (Very Common Interview Question)

Q: "You have 3 alerts firing at once, how do you prioritize?"

Answer framework:

1. **Severity**: Critical and High before Medium and Low
2. **Asset value**: Domain controller over standard workstation
3. **Active vs historical**: Is it happening now?
4. **Blast radius**: Can it spread? Ransomware = immediate
5. **Context**: Is it during business hours? Expected activity?

### Alert Validation, False Positive vs True Positive

Before escalating any alert:

1. Check the alert rule and logic, is it well tuned?
2. Correlate with related logs (not just the triggered event)
3. Check asset context, who owns the machine? What do they do?
4. Look for baseline behavior, is this normal for this user?
5. Check threat intel, is the IP, domain, or hash known malicious?
6. Only escalate when you've validated with evidence

**Example scenario answer:**

Q: "You see an alert for port scanning from an internal IP. What do you do?"

"First I'd validate, is this a known vulnerability scanner like Nessus or Qualys that our team runs? I'd check the asset owner and correlate with change management. If it's unauthorized, I'd capture current network connections from that host, review process logs for scanning tools, check if any credentials were used across the network, isolate the host if compromise is suspected, and escalate to Tier 2 with evidence documented."

---

## 5. SIEM, Deep Dive

### What Is a SIEM?

A SIEM (Security Information and Event Management) collects logs from across the environment, normalizes them, correlates events across sources, and generates alerts when rules or baselines are violated. It also provides a search interface for investigations.

Examples: Splunk, Microsoft Sentinel, IBM QRadar, Elastic SIEM, Wazuh.

### Splunk, Key SPL Queries

```splunk
| Know these for interviews |

# Search failed logins
index=auth sourcetype=linux_secure "Failed password"
| stats count by src_ip, user
| sort -count

# Detect brute force (10+ failures, then success)
index=wineventlog EventCode=4625
| stats count by src_ip, Account_Name
| where count > 10

# Detect port scanning
index=network
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 20
| sort -unique_ports

# Top talkers on network
index=network
| stats sum(bytes) as total_bytes by src_ip
| sort -total_bytes
| head 10

# Timeline of a specific user's activity
index=* user="jsmith"
| timechart count by sourcetype
```

### SIEM Concepts to Know

- **Log sources**: Firewalls, endpoints, AD, web proxies, DNS, email gateways
- **Correlation rules**: Logic that fires alerts when multiple conditions are met
- **Baseline**: Normal behavior profile; deviations trigger alerts
- **UEBA**: User and Entity Behavior Analytics, ML driven anomaly detection
- **Retention**: How long logs are stored (compliance often requires 1 year+)
- **Normalization**: Converting different log formats into a common schema

---

## 6. Common Attacks, Know These Cold

### Phishing

- **What**: Email, SMS, or call impersonating a trusted source to steal credentials or deliver malware
- **Variants**: Spear phishing (targeted), whaling (executives), vishing (voice), smishing (SMS)
- **SOC indicators**: Suspicious sender domain, mismatched links, unexpected attachments, urgency language
- **Detection**: Email gateway logs, proxy logs (user clicking link), EDR alerts

### Brute Force and Credential Attacks

- **What**: Repeated login attempts using wordlists or previously leaked credentials
- **Variants**: Password spray (one password, many accounts, avoids lockout), credential stuffing (leaked creds)
- **SOC indicators**: Many 4625 events, multiple accounts hit from one IP
- **Detection**: SIEM alert on failed login threshold, geographic anomaly

### Malware Categories

| Type | Behavior | Example |
|------|---------|---------|
| Ransomware | Encrypts files, demands payment | LockBit, REvil |
| RAT | Remote access trojan, full attacker control | DarkComet |
| Keylogger | Records keystrokes | Various |
| Rootkit | Hides presence deep in OS | Necurs |
| Worm | Self-replicates across network | WannaCry |
| Trojan | Disguised as legitimate software | |

### Privilege Escalation

- **What**: Attacker moves from low-privilege user to admin or root
- **Windows**: Token impersonation, unquoted service paths, misconfigured ACLs
- **Linux**: SUID binaries, sudo misconfigs, kernel exploits
- **SOC detection**: 4672 (special privileges), 4732 (added to admin group), sudo logs

### Lateral Movement

- **What**: Attacker moves from one compromised host to others in the network
- **Techniques**: Pass the hash, PsExec, RDP, WMI, SMB
- **SOC detection**: 4648 (explicit credential logon), unusual RDP sessions, SMB connections between workstations

### SQL Injection

- **What**: Malicious SQL inserted into input fields to query or modify databases
- **SOC detection**: WAF logs, unusual DB query patterns, error responses in web logs

### Man in the Middle (MITM)

- **What**: Attacker intercepts traffic between two parties
- **Techniques**: ARP poisoning, SSL stripping, rogue Wi-Fi
- **SOC detection**: ARP anomalies, certificate warnings, unusual gateway traffic

---

## 7. Tools, What You'd Actually Do

### IDS vs IPS

| | IDS | IPS |
|-|-----|-----|
| Function | Detects and alerts | Detects and blocks |
| Placement | Out of band (mirror or tap) | Inline (traffic passes through) |
| Response | Passive | Active |
| Risk | None (no traffic impact) | Can block legitimate traffic |
| Example | Suricata (detection mode), Zeek | Suricata (inline), Snort |

Bonus: Mention that Suricata can operate as both IDS and IPS depending on deployment mode.

### Wireshark, What to Look For

- **Unusual ports**: Traffic on non standard ports
- **Cleartext protocols**: HTTP, Telnet, FTP carrying sensitive data
- **High frequency beaconing**: Regular outbound calls at fixed intervals = C2
- **Large data transfers**: Outbound to unusual destinations = exfiltration
- **DNS tunneling**: Abnormally long DNS queries and responses

```
Useful Wireshark filters:
tcp.port == 4444              # Metasploit default
http.request.method == POST   # POST traffic (possible data upload)
dns                           # All DNS traffic
ip.addr == 192.168.1.100      # Filter by host
tcp.flags.syn == 1            # SYN packets (port scan detection)
```

### Nmap, Common Flags

```bash
nmap -sV 192.168.1.0/24       # Service version detection
nmap -sS target               # SYN scan (stealthy)
nmap -O target                # OS detection
nmap -p 22,80,443 target      # Specific ports
nmap -A target                # Aggressive (OS + service + scripts)
```

In a SOC context: Nmap results help during investigation to understand what's exposed on a compromised host or to baseline the environment.

---

## 8. MITRE ATT&CK Framework

Know the 14 Tactics in order. This is the attack kill chain.

| # | Tactic | What Attacker Is Doing |
|---|--------|----------------------|
| 1 | Reconnaissance | Gathering info before attack |
| 2 | Resource Development | Setting up infrastructure |
| 3 | Initial Access | Getting into the environment |
| 4 | Execution | Running malicious code |
| 5 | Persistence | Maintaining foothold |
| 6 | Privilege Escalation | Gaining higher permissions |
| 7 | Defense Evasion | Avoiding detection |
| 8 | Credential Access | Stealing credentials |
| 9 | Discovery | Learning the environment |
| 10 | Lateral Movement | Moving through the network |
| 11 | Collection | Gathering target data |
| 12 | Command & Control (C2) | Communicating with attacker |
| 13 | Exfiltration | Stealing data out |
| 14 | Impact | Ransomware, destruction |

**How to use this in an interview:**

When asked about any attack scenario, map it to MITRE tactics. Example:

Q: "Walk me through a ransomware attack."

"The attacker begins with Initial Access, commonly via phishing (T1566). They achieve Execution by running a malicious attachment (T1204). They establish Persistence via a scheduled task (T1053). They escalate privileges if needed (T1078), then move Laterally using SMB (T1021). Finally they reach Impact, encrypting files with T1486 (Data Encrypted for Impact)."

---

## 9. Log Analysis, Reading Real Logs

### Linux auth.log, SSH Brute Force

```
Nov 15 02:13:44 server sshd[1234]: Failed password for root from 185.220.101.5 port 51234 ssh2
Nov 15 02:13:45 server sshd[1234]: Failed password for root from 185.220.101.5 port 51235 ssh2
Nov 15 02:13:47 server sshd[1235]: Accepted password for admin from 185.220.101.5 port 51240 ssh2
```

What this tells you:
- Repeated failures from external IP = brute force
- Eventual success = compromise
- "root" targeted = attacker wants full control
- 185.220.101.5 = known Tor exit node range

### Windows Security Log, Lateral Movement

```
Event ID: 4648
Account Name: svc_backup
Target Account: administrator
Workstation: WKSTN-004
Network Address: 10.0.0.15
```

What this tells you:
- Service account logging in as administrator across the network
- Explicit credential use = possible pass the hash or stolen cred
- Pivot from WKSTN-004 to target

### Firewall Log, C2 Beaconing

```
2024-11-15 03:00:01 ALLOW TCP 10.0.0.55 → 185.220.44.12:443
2024-11-15 03:05:01 ALLOW TCP 10.0.0.55 → 185.220.44.12:443
2024-11-15 03:10:01 ALLOW TCP 10.0.0.55 → 185.220.44.12:443
```

What this tells you:
- Exact 5 minute interval = automated and scripted = C2 beacon
- External IP should be checked against threat intel
- Host 10.0.0.55 is likely compromised

---

## 10. Scenario Questions, Full Worked Answers

**Formula for every scenario: Investigate to Validate to Contain to Escalate to Document**

---

**Q: You receive an alert for possible malware infection. What do you do?**

1. Pull the alert details, what triggered it? (Hash match, behavior, network IOC?)
2. Identify the affected host and user
3. Check EDR for process tree, what spawned the malicious process?
4. Check network logs, is the host beaconing outbound?
5. Validate: Is this a known FP? Check threat intel for the hash, IP, or domain
6. If confirmed: Isolate the host from network (not power off, preserve memory)
7. Escalate to Tier 2 with timeline, IOCs, and affected scope
8. Document everything, time of detection, actions taken, evidence collected

---

**Q: Multiple failed SSH logins from different countries. What do you do?**

1. Identify source IPs, are they Tor exit nodes, VPNs, or residential?
2. Identify target accounts, is it root, service accounts, or specific users?
3. Determine attack type, credential stuffing (many users) or brute force (one user)?
4. Check for successful logins after failures, most critical finding
5. If no success: Tune alert threshold, consider geo-blocking, notify account owners
6. If success: Treat as compromise, rotate credentials, isolate if needed, escalate

---

**Q: A user reports their computer is "acting weird." What's your process?**

1. Ask: What specifically? Slow? Popups? Files changed? Unexpected programs?
2. Remotely pull EDR data, running processes, recent file changes, network connections
3. Check SIEM for alerts tied to this host in the past 24 to 48 hours
4. Look for: Unusual parent child process relationships (e.g., Word spawning PowerShell)
5. Check for persistence: Startup items, scheduled tasks, new services
6. If indicators present: Isolate, escalate, preserve forensic artifacts
7. If clean: Document the investigation and outcome

---

**Q: You see outbound traffic to an IP on port 443 that's not on any allow list. What do you do?**

1. Look up the IP, threat intel (VirusTotal, AbuseIPDB, Shodan)
2. Check if it's a CDN or known SaaS, could be legitimate
3. Check frequency, one-off vs regular beaconing
4. Check the process making the connection, lsof or EDR
5. Check for certificate details, is it a legit cert or self signed?
6. If suspicious: Block IP, isolate host, escalate with evidence

---

## 11. Threat Intelligence, Tools to Know

| Tool | Use Case |
|------|---------|
| VirusTotal | Hash, URL, IP reputation |
| AbuseIPDB | IP reputation, abuse reports |
| Shodan | What's exposed on an IP |
| AlienVault OTX | Open threat intelligence |
| URLScan.io | Analyze suspicious URLs safely |
| ANY.RUN | Interactive malware sandbox |
| Joe Sandbox | Deep malware analysis |
| MITRE ATT&CK | TTP mapping |
| Hybrid Analysis | File or URL detonation |

**IOC Types to Know**

- **IP addresses**: C2 servers, scanners
- **Domains**: Phishing, C2, malware distribution
- **File hashes** (MD5, SHA1, SHA256): Malware identification
- **URLs**: Phishing pages, payload delivery
- **Email headers**: Phishing source tracing
- **Mutex names**: Malware fingerprints (advanced)

---

## 12. HR and Behavioral Questions, Full Answers

**"Why do you want to work in a SOC?"**

"I'm drawn to the investigation side of security, taking a raw alert, digging through logs, and determining whether it's a false positive or a real threat. I've been building hands on skills in log analysis and SIEM work through my home lab, and I want to apply that in a real environment where the stakes matter. A SOC role is where I can develop fast through real world exposure."

---

**"Tell me about yourself."**

Use: Present to Past to Why This Role

"I'm currently building my skills as a blue team security analyst, focusing on threat detection, log analysis, and incident response. I've been running a home lab where I've set up Splunk, Wazuh, and Suricata. I've simulated attacks like SSH brute force and analyzed the alerts end to end. My background is in Linux systems and scripting, which gives me a strong foundation for the hands on parts of this role. I'm looking for a SOC position where I can take what I've built in the lab and apply it to real threats."

---

**"What's your biggest weakness?"**

Don't say something fake. Example of a real, professional answer:

"I haven't worked with enterprise scale SIEM environments yet, my experience is with self hosted Splunk and Wazuh. I know the concepts and query logic well, but I'm aware that a production SIEM at scale is a different environment. I'm actively working on this through lab work and training, and I'm confident I'd close that gap quickly once I'm in a real environment."

---

**"Where do you see yourself in 3 years?"**

"I'd like to move from Tier 1 triage to Tier 2 analysis, leading investigations, tuning detection rules, and building correlation logic rather than just responding to existing alerts. Long term, I'm interested in threat hunting and possibly threat intelligence."

---

## 13. Certifications, Ranked by Value

| Cert | Level | Value for SOC |
|------|-------|---------------|
| CompTIA Security+ | Entry | Baseline, often required just to apply |
| Blue Team Labs Online | Entry | Practical labs, good for portfolio |
| TryHackMe SOC Level 1 | Entry | Structured, beginner-friendly |
| EC-Council CSA | Entry to Mid | Purpose built for SOC analysts |
| CompTIA CySA+ | Mid | Threat analysis focus, strong |
| GIAC GCIH | Mid to Senior | Incident handling, highly respected |
| Splunk Core Certified User | Speciality | Validates SIEM skills specifically |

---

## 14. What to Say If You Don't Know the Answer

Never bluff. Never guess randomly.

Good structure when you don't know:

1. State what you do know about the area
2. Describe how you would find the answer
3. Mention you'd document findings for team knowledge

Example:

Q: "What's the difference between Kerberoasting and AS REP Roasting?"

"I know both are Active Directory credential attacks that target service account hashes. Kerberoasting specifically involves requesting service tickets for SPNs and cracking them offline. I've read about this in the context of MITRE T1558. AS REP Roasting targets accounts with pre-authentication disabled. I haven't worked through the specific technical difference in a lab yet, but I know they'd both appear in Kerberos related Event IDs like 4768 and 4769."

That answer shows knowledge, honesty, and process.

---

## 15. Mock Interview, Practice Questions

### Technical
- What is the CIA triad? Give an example of each.
- What's the difference between IDS and IPS?
- What is a firewall and what can it not protect against?
- What is a SIEM and what are its limitations?
- Explain a 3 way TCP handshake.
- What Event ID would you look for in a brute force investigation?
- What Linux command shows active network connections?
- What is lateral movement and how would you detect it?

### Scenario
- You see a spike in DNS queries from one internal host. What do you do?
- An executive reports receiving a suspicious email. Walk me through your response.
- An alert shows PowerShell running from a Word document process. What's your concern and what do you do?
- A user's account logs in from two countries at the same time. What does that indicate and how do you respond?

### HR
- Why cybersecurity?
- Tell me about a time you had to solve a difficult technical problem.
- How do you stay current with the threat landscape?
- What would you do if you disagreed with a senior analyst's decision?

---

## Quick Reference, Interview Day Checklist

```
Before the interview:
✅ Review CIA triad with examples
✅ Know the IR lifecycle cold (6 steps)
✅ Know 10+ Windows Event IDs
✅ Know IDS vs IPS difference
✅ Review MITRE tactics (14)
✅ Have 2-3 scenario answers ready using Investigate to Validate to Contain to Escalate
✅ Know your own projects well, be ready to be drilled on them
✅ Prepare "tell me about yourself" using Present to Past to Why This Role

During the interview:
✅ Pause before answering, structure beats speed
✅ If you don't know: say what you do know, how you'd find out
✅ Use tool names (Splunk, Suricata, Wireshark), not just generic terms
✅ Map scenarios to MITRE tactics when possible
✅ Document everything, say this phrase at least once naturally
```

---

*Built for SOC Analyst interviews, Tier 1 and Tier 2, Blue Team, Entry to Mid Level*
