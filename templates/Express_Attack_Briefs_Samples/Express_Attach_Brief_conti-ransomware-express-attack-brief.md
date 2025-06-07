# Express Attack Brief
## Conti Ransomware

**Classification:** GENERAL  
**Publisher:** nccgroup

---

## Table of Contents

1. Introduction ..................................................................... 3
   - 1.1 Attack description ...................................................... 3
2. Attack path ...................................................................... 3
   - 2.1 Hijacking legitimate email conversation ................................. 3
   - 2.2 Spearphishing email containing link to malicious Excel file ............. 3
   - 2.3 Malicious Excel file drops SquirrelWaffle .............................. 4
   - 2.4 SquirrelWaffle drops QakBot ............................................ 4
   - 2.5 Collect emails using QakBot ............................................ 5
   - 2.6 SquirrelWaffle drops Cobalt Strike ..................................... 5
   - 2.7 Privilege escalation by harvesting Domain Administrator credentials ...... 5
   - 2.8 Lateral movement to domain controller using Cobalt Strike ............... 6
   - 2.9 Map Active Directory domains using BloodHound .......................... 6
   - 2.10 Map Active Directory domains using AdFind ............................. 6
   - 2.11 Lateral movement between domains using bidirectional trust relationships 6
   - 2.12 Hyper-V host discovery by querying Active Directory ................... 7
   - 2.13 Data collection from host and network shares .......................... 7
   - 2.14 Data exfiltration using RClone ........................................ 7
   - 2.15 Orchestrate ransomware deployment with PowerShell and WMI ............. 7
   - 2.16 Disable Microsoft Defender for Endpoints .............................. 8
   - 2.17 Delete Volume Shadow Copies ........................................... 8
   - 2.18 Deploy Conti ransomware ............................................... 8
   - 2.19 Encrypt files using Conti ransomware .................................. 8

---

## 1. Introduction

This document describes the attack path observed during a recent cyber security incident. It presents the steps taken by the threat actor, including associated Tactic, Technique, and Procedure (TTP) details. Where possible the TTPs are expressed in MITRE ATT&CK terminology to aid in correlation and crossreferencing with other threat intelligence sources. This document is aimed at helping the reader learn from the incident and prepare to defend against possible future attacks. Its attack path structure is designed to show how the latest cyber attacks actually happen in the real world. The inclusion of TTP details allows readers to map the attack steps to their own organization, validating their security posture, and feeding into their risk management process.

### 1.1 Attack description

| Attribute | Value |
|-----------|-------|
| **Period** | Q4 2021 |
| **Threat type** | Ransomware |
| **Sector relevance** | All |
| **Geographic relevance** | Global |

A large organization was hit by Conti ransomware in Q4 2021. The threat actor gained initial access to one of the organization's subsidiaries by hijacking an existing email conversation to spearphish a staff member. The threat actor performed lateral movement and privilege escalation to achieve domain administrator-level access covering the entire organization and multiple subsidiaries. The threat actor subsequently exfiltrated data and encrypted files using Conti ransomware. We see this as a typical attack path for Conti ransomware attacks at the time of writing. Noteworthy is the threat actor's focus on getting as much network access as possible, even though that increased the risk of the attack being detected before ransomware was deployed. The threat actor moved from initial access at a subsidiary domain to the main domain, and from there continued to try to get domain ownership of more subsidiaries. That is interesting behavior on the part of the threat actor, because it is common for large organizations to have varying levels of security maturity among their subsidiaries, increasing the chance of detection at a subsidiary with effective detection in place. We interpret this behavior as indicating the threat actor's preference for delivering maximum impact over premature detection.

---

## 2. Attack path

### 2.1 Hijacking legitimate email conversation

| Attribute | Value |
|-----------|-------|
| **Procedure** | Hijacking legitimate email conversation |

The threat actor gained access to an email conversation between the victim and a third party that started over two months prior, and sent an apparently related follow-up mail to a group email address of the victim. This abuse of a legitimate email thread increased the persuasiveness of the malicious email, thereby increasing the likelihood of the recipient falling victim to its malicious contents. We were not able to determine how the threat actor got access to the existing mail conversation in this specific case. It is possible that it was collected during a previous intrusion in this or another organization, as such email collection from compromised hosts is a typical part of this threat actor's modus operandi; see the section on QakBot collecting emails further on in this document.

### 2.2 Spearphishing email containing link to malicious Excel file

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0001 Initial Access |
| **Technique** | T1566.002 Phishing: Spearphishing Link |
| **Procedure** | Spearphishing email containing link to malicious Excel file |

The threat actor gained initial access by using a spearphishing email. The email contained a short, one line message requesting the recipient to examine a report provided as a zip file at the provided URL. To increase persuasiveness of the email, its body further contained a legitimate email conversation between the victim and a third party. The threat actor used the name of one of the legitimate participants of the mail thread as sender. The actual spearphishing message was short and simple. Compared to other phishing activity, such as documented by Sanne Maasakkers (https://blog.sannemaasakkers.com/2021/08/07/werkwijzen-aptphishing/), this case suggests that the threat actor did not spend much manual effort on crafting a specific message. The email was sent to a group email address of the victim, probably to increase the chance of a recipient falling victim to its malicious contents. The threat actor sent the malicious email from an external email address, not from an actual email address of one of the conversation participants. The external email address used by the threat actor was registered recently at a small email provider in Asia. The URL included in the spearphishing email pointed to a zip file hosted on a compromised web server. A staff member downloaded and unzipped the file, and opened the malicious document it contained.

**Mitigation:**
- **M1017: User Training** - Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction.
- **M1054: Software Configuration** - Implement configuration changes to software (other than the operating system) to mitigate security risks associated to how the software operates.

### 2.3 Malicious Excel file drops SquirrelWaffle

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0002 Execution |
| **Technique** | T1204.002 User Execution: Malicious File<br>T1059.005 Command and Scripting Interpreter: Visual Basic |
| **Procedure** | Malicious Excel file drops SquirrelWaffle |
| **Tools** | Microsoft Excel, SquirrelWaffle |
| **OS** | Windows 10 Pro |

A user opened a malicious Excel file with .xls extension. Based on the available telemetry, we infer that the malicious Excel file contained a Visual Basic macro that downloaded and executed SquirrelWaffle. SquirrelWaffle provided an initial foothold on the compromised system and functioned as a malware stager, which the threat actor used to subsequently drop QakBot and Cobalt Strike. The compromised host was protected by an endpoint security solution, specifically Microsoft Defender for Endpoint. However, neither the malicious Excel file nor SquirrelWaffle were detected as being malicious.

**Mitigation:**
- **M1038: Execution Prevention** - Block execution of code on a system through application control, and/or script blocking.

### 2.4 SquirrelWaffle drops QakBot

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0002 Execution<br>TA0011 Command and Control |
| **Technique** | T1105 Ingress Tool Transfer |
| **Procedure** | SquirrelWaffle drops QakBot |
| **Tools** | SquirrelWaffle, QakBot |
| **OS** | Windows 10 Pro |

SquirrelWaffle provided an initial foothold on the compromised system. The threat actor used it as a malware loader to download and run QakBot. QakBot is a type of malware often referred to as an information-stealer. It offers powerful functionality for discovery of the compromised environment, and collection and exfiltration of sensitive data such as email messages. QakBot can be automated for efficient operations, and is commonly used by threat actors for their initial assessment of a victim's IT environment. Microsoft Defender was present on the compromised host. It detected at least one of the QakBot files as being malicious. However, after several attempts the threat actor was able to run QakBot successfully.

### 2.5 Collect emails using QakBot

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0009 Collection<br>TA0010 Exfiltration |
| **Technique** | T1020 Automated Exfiltration<br>T1074.001 Data Staged: Local Data Staging<br>T1114.001 Email Collection: Local Email Collection |
| **Procedure** | Collect emails using QakBot |
| **Tools** | QakBot |
| **OS** | Windows 10 Pro |

The threat actor used a QakBot module to collect and exfiltrate email messages from the compromised host. Such email collection is a typical part of this threat actor's modus operandi because it provides valuable data that can be leveraged in future attacks against this organization and any others contained within the emails. The QakBot email collection module automatically scanned for Outlook present on the host and extracted emails from to it. It copied the emails into a newly created directory named EmailStorage under the context of the compromised user in preparation of exfiltration.

### 2.6 SquirrelWaffle drops Cobalt Strike

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0002 Execution<br>TA0011 Command and Control |
| **Technique** | T1105 Ingress Tool Transfer |
| **Procedure** | SquirrelWaffle drops Cobalt Strike |
| **Tools** | SquirrelWaffle, Cobalt Strike |
| **OS** | Windows 10 Pro |

SquirrelWaffle provided an initial foothold on the compromised system. The threat actor used it as a malware loader to download and run Cobalt Strike. Cobalt Strike is a penetration testing tool that offers powerful post-exploitation functionality. It is frequently used by threat actors for persistence, lateral movement, and privilege escalation within compromised environments. Microsoft Defender was present on the compromised host. However it did not block Cobalt Strike.

### 2.7 Privilege escalation by harvesting Domain Administrator credentials

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0006 Credential Access<br>TA0004 Privilege Escalation |
| **Technique** | T1003 OS Credential Dumping<br>T1110.002 Brute Force: Password Cracking<br>T1078.002 Valid Accounts: Domain Accounts |
| **Procedure** | Privilege escalation by harvesting Domain Administrator credentials |
| **OS** | Windows |

The threat actor was able to gain access to the credentials of multiple user accounts, including at least one member of the Domain Administrators group, effectively giving the threat actor full access to the victim's domain. Available telemetry did not give insight into the method used by the threat actor to harvest those credentials. We assume that the domain administrator credentials were likely obtained by extracting them from the memory of compromised hosts. It is also possible that brute force password cracking was used on the domain controllers' database files, given the complexity of the passwords in use.

### 2.8 Lateral movement to domain controller using Cobalt Strike

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0008 Lateral Movement |
| **Technique** | T1021.002 Remote Services: SMB/Windows Admin Shares |
| **Procedure** | Lateral movement to domain controller using Cobalt Strike |
| **Tools** | Cobalt Strike |
| **OS** | Windows |

The threat actor moved laterally within the domain of initial access and escalated privilege to domain admin. Based on the limited telemetry available, we assume that these actions were performed using standard Cobalt Strike functionality. Microsoft Defender was present on admin workstation. Flagged some, but not immediately.

### 2.9 Map Active Directory domains using BloodHound

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0007 Discovery |
| **Technique** | T1087.002 Account Discovery: Domain Account<br>T1482 Domain Trust Discovery |
| **Procedure** | Map Active Directory domains using BloodHound |
| **Tools** | BloodHound |
| **OS** | Windows |

The threat actor used BloodHound to map out the victim's domains and privileged user accounts. This information provides detailed insight into potential paths for lateral movement and privilege escalation, including the quickest path to gaining Domain Administrator privileges.

### 2.10 Map Active Directory domains using AdFind

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0007 Discovery |
| **Technique** | T1018 Remote System Discovery |
| **Procedure** | Map Active Directory domains using AdFind |
| **Tools** | AdFind |
| **OS** | Windows |

The threat actor used AdFind to discover remote systems by querying the victim's Active Directory.

### 2.11 Lateral movement between domains using bidirectional trust relationships

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0008 Lateral Movement |
| **Procedure** | Lateral movement between domains using bidirectional trust relationships |

The threat actor was able to move laterally between domains within the victim's organization due to the presence of bidirectional trust relationships.

### 2.12 Hyper-V host discovery by querying Active Directory

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0007 Discovery<br>TA0002 Execution |
| **Technique** | T1018 Remote System Discovery<br>T1059.001 Command and Scripting Interpreter: PowerShell |
| **Procedure** | Hyper-V host discovery by querying Active Directory |
| **Tools** | listHyperVHostsInForests.ps1 |
| **OS** | Windows |

The threat actor used a PowerShell script to obtain a list of Hyper-V hosts by querying Active Directory. The script was similar to listHyperVHostsInForests.ps1 published at https://kimconnect.com/powershell-obtain-listof-hyper-v-hosts-via-active-directory/. This listing of Hyper-V hosts indicated the threat actor was shifting from lateral movement to increase network access, to preparing for action on its objectives, specifically deploying ransomware. This information on virtual machines running within the victim's environment would help the threat actor maximize the impact of its ransomware.

### 2.13 Data collection from host and network shares

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0009 Collection |
| **Technique** | T1005 Data from Local System<br>T1039 Data from Network Shared Drive |
| **Procedure** | Data collection from host and network shares |
| **OS** | Windows Server 2019 |

The threat actor collected files for exfiltration that were located on a compromised Windows host itself and on network shares reachable from it.

### 2.14 Data exfiltration using RClone

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0010 Exfiltration |
| **Technique** | T1048 Exfiltration Over Alternative Protocol |
| **Procedure** | Data exfiltration using RClone |
| **Tools** | RClone |
| **OS** | Windows Server 2019 |

The threat actor used RClone to exfiltrate data from the compromised host to a remote server. The server authenticated itself with a self-signed TLS certificate and a non-descript common name.

### 2.15 Orchestrate ransomware deployment with PowerShell and WMI

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0002 Execution |
| **Technique** | T1047 Windows Management Instrumentation<br>T1059.001 Command and Scripting Interpreter: PowerShell<br>T1570 Lateral Tool Transfer |
| **Procedure** | Orchestrate ransomware deployment with PowerShell and WMI |
| **OS** | Windows |

The threat actor used PowerShell to orchestrate the automated deployment of ransomware. Multiple jobs were run in parallel to distribute files to multiple target hosts via the Server Message Block (SMB) protocol and to start remote commands via Windows Management Instrumentation (WMI).

### 2.16 Disable Microsoft Defender for Endpoints

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0005 Defense Evasion |
| **Technique** | T1562.001 Impair Defenses: Disable or Modify Tools |
| **Procedure** | Disable Microsoft Defender for Endpoints |
| **OS** | Windows |

The threat actor's automated process of preparing target systems for ransomware deployment included disabling of Microsoft Defender for Endpoints to minimize the chance of its attack being blocked.

### 2.17 Delete Volume Shadow Copies

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0040 Impact |
| **Technique** | T1490 Inhibit System Recovery |
| **Procedure** | Delete Volume Shadow Copies |
| **OS** | Windows |

The threat actor deleted Volume Shadow Copies of target systems to frustrate system recovery.

### 2.18 Deploy Conti ransomware

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0002 Execution |
| **Technique** | T1059.003 Command and Scripting Interpreter: Windows Command Shell<br>T1569.002 System Services: Service Execution |
| **Procedure** | Deploy Conti ransomware |
| **Tools** | Conti |
| **OS** | Windows |

The threat actor used the Windows Command Shell via batch scripts to download and execute the Conti ransomware payload.

### 2.19 Encrypt files using Conti ransomware

| Attribute | Value |
|-----------|-------|
| **Tactic** | TA0040 Impact |
| **Technique** | T1486 Data Encrypted for Impact |
| **Procedure** | Encrypt files using Conti ransomware |
| **Tools** | Conti |
| **OS** | Windows |

The threat actor used Conti ransomware to encrypt files. The Conti ransomware was detected by some of the endpoint protection solutions present on target systems. Even so, the ransomware was still able to inflict significant damage by successfully encrypting large amounts of files.

---

*Express Attack Brief - Conti Ransomware*  
*nccgroup*  
*Page 8 of 8*