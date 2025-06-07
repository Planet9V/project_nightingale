# Express Attack Brief 010
## SunnyDay ransomware casting shadows

**Version:** 1.0  
**Publication date:** 2022-08-12  
**Prepared for:** Fox-IT

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
   - 3.1. [Public RDP access](#31-public-rdp-access)
   - 3.2. [AnyDesk for persistence](#32-anydesk-for-persistence)
   - 3.3. [Preparing for network discovery](#33-preparing-for-network-discovery)
   - 3.4. [Inspect the network using Advanced Port Scanner](#34-inspect-the-network-using-advanced-port-scanner)
   - 3.5. [Successful persistence using PoshC2](#35-successful-persistence-using-poshc2)
   - 3.6. [Network discovery using NetScan](#36-network-discovery-using-netscan)
   - 3.7. [Possible lateral movement using RDP](#37-possible-lateral-movement-using-rdp)
   - 3.8. [Staging exfiltrated data](#38-staging-exfiltrated-data)
   - 3.9. [Exfiltrate data](#39-exfiltrate-data)
   - 3.10. [Executing the ransomware](#310-executing-the-ransomware)
4. [MITRE ATT&CK TTPs](#4-mitre-attck-ttps)

---

## 1. Introduction

### 1.1. Document purpose

This document has been prepared for Fox-IT.

This document describes the attack path observed during a recent cyber security incident. It presents the steps taken by the threat actor, including associated Tactic, Technique, and Procedure (TTP) details. Where possible the TTPs are expressed in MITRE ATT&CK terminology to aid in correlation and cross-referencing with other threat intelligence sources.

This document is aimed at helping readers learn from the incident and prepare to defend against possible future attacks. Its attack path structure is designed to show how the latest cyber attacks actually happen in the real world. The inclusion of TTP details allows readers to map the attack steps to their own organization, validating their security posture, and feeding into their risk management process.

### 1.2. Document structure

**Chapter 2** describes the overall attack and gives a summary of the steps taken by the threat actor.

**Chapter 3** describes the attack steps in detail, including possible prevention and detection opportunities where appropriate.

**Chapter 4** lists the MITRE ATT&CK TTPs observed in the attack in a convenient table format.

### 1.3. Document classification

This document is shared with Fox-IT as **TLP:AMBER** according to the Traffic Light Protocol (TLP). Recipients may only share this document with members of their own organization. Recipients may additionally share this document with their IT service providers for the sole purpose of validating or improving the security delivered to the recipients.

This document is classified as **RESTRICTED**. Any information published in this document is intended exclusively for Fox-IT. Any use by a party other than Fox-IT is prohibited unless explicitly granted by Fox-IT. The information contained in this document may be RESTRICTED in nature and fall under a pledge of secrecy.

Misuse of this document or any of its information is prohibited and will be prosecuted to the maximum penalty possible. Fox-IT cannot be held responsible for any misconduct or malicious use of this document by a third party or damage caused by its contained information.

---

## 2. Attack overview

### 2.1. Attack description

| **Timeframe** | 2022 Q1 |
|---|---|
| **Threat type** | Ransomware |
| **Sector relevance** | All sectors |
| **Geographic relevance** | Global |

This document describes an attack involving SunnyDay ransomware that impacted a European organization in the Civil Society sector. The attack happened in the first quarter of this year.

The attack started with a misconfigured RDP service which was accessible over the Internet. The attackers were able to login to the RDP server using Domain Administrator credentials, likely obtained through a brute-force attack. They then were able to exfiltrate over 2,200 files and encrypt three servers with the SunnyDay ransomware. The servers included a Domain Controller and SharePoint server, therefore, the attack caused a significant disruption. Using the forensic data available, we could not determine whether data exfiltration actually took place. However, the discovery of a 7-Zip archive containing important organizational information, which was created and later deleted by the attacker, makes it likely that data exfiltration could have taken place. This is because often threat actors archive the exfiltrated data and later delete the archive to cover their tracks.

The attacker described in this report does not seem sophisticated. We will mention this throughout this report at certain moments.

This attack was initially caused by a misconfiguration. However, the lack of a good password policy, multi-factor authentication, and network segmentation resulted in a relatively easy attack path for the threat actor.

### 2.2. Attack path summary

| **Time** | **Tactic** | **Action** | **Target tech** |
|---|---|---|---|
| Day 1, 19:19 | Initial Access, Credential Access | Public RDP access | RDP |
| Day 1, 20:04 | Command and Control | AnyDesk for persistence | Windows |
| Day 4, 21:24 | Command and Control | Preparing for network discovery | Windows |
| Day 4, 22:26 | Discovery | Inspect the network using Advanced Port Scanner | Windows |
| Day 4, 23:13 | Persistence, Command and Control, Execution | Successful persistence using PoshC2 | Windows |
| Day 6, 19:25 | Discovery | Network discovery using NetScan | Windows |
| Day 6, 19:31 | Lateral Movement | Possible lateral movement using RDP | Windows |
| Day 6, 19:51 | Collection | Staging exfiltrated data | Windows |
| Day 6, 19:56 | Exfiltration | Exfiltrate data | Windows |
| Day 1, 20:56 | Impact | Executing the ransomware | Windows |

Times of day are expressed in the primary timezone of the victim organization where our incident response activities took place.

---

## 3. Attack path

This chapter describes the attack steps in detail, including possible prevention and detection opportunities where appropriate.

### 3.1. Public RDP access

| **Timestamp** | Day 1, 19:19 |
|---|---|
| **Techniques** | T1133 External Remote Services to achieve TA0001 Initial Access<br>T1110.001 Password Guessing to achieve TA0006 Credential Access |
| **Target tech** | RDP |

The attacker gained initial access through a publicly exposed RDP service. Due to deletion of login event logs, we are unable to state when exactly the attacker logged onto the RDP server. The open RDP service was a misconfiguration.

Unfortunately, the attacker was able to login with the Domain Administrator account. Though unsure, it is likely that the attacker was able to bruteforce the credentials as they were rather weak, however, the attacker could also have bought the credentials from an initial access broker (IAB).

It is worth noting that Shodan, a tool which scans the Internet for open ports, showed the RDP service being accessible to the Internet for over two weeks before attacker activity was observed.

#### Prevention

**Limit Access to Resource Over Network**  
Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc.

Limit access to remote services through centrally managed concentrators such as VPNs and other managed remote access systems. (Source: ATT&CK mitigation M1035)

**Password Policies**  
Set and enforce secure password policies for accounts. (Source: ATT&CK mitigation M1027)

**Multi-factor Authentication**  
Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator.

Use strong two-factor or multi-factor authentication for remote service accounts to mitigate an adversary's ability to leverage stolen credentials, but be aware of Two-Factor Authentication Interception techniques for some two-factor authentication implementations. (Source: ATT&CK mitigation M1032)

**Password Policies**  
Set and enforce secure password policies for accounts.

Refer to NIST guidelines when creating password policies.(Citation: NIST 800-63-3) (Source: ATT&CK mitigation M1027)

#### Detection

**Asset management**  
Monitoring of public-facing infrastructure can help a company in finding services or servers which should not be connected to the Internet. In this case, the RDP service had been open for at least two weeks, meaning that it could have been detected if asset management was in place.

### 3.2. AnyDesk for persistence

| **Timestamp** | Day 1, 20:04 |
|---|---|
| **Techniques** | T1219 Remote Access Software to achieve TA0011 Command and Control |
| **Target tech** | Windows |

The adversary tried to execute AnyDesk, a legitimate remote access tool (RAT), in order to create a form of persistence. Though they already had access through RDP, having AnyDesk would allow them to get back into the network once the public RDP service would have been disabled. The AnyDesk connections, however, were blocked by the firewall, which resulted in AnyDesk failing to work.

#### Prevention

**Execution Prevention**  
Block execution of code on a system through application control, and/or script blocking.

Use application control to mitigate installation and use of unapproved software that can be used for remote access. (Source: ATT&CK mitigation M1038)

**Filter Network Traffic**  
Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic.

Properly configure firewalls, application firewalls, and proxies to limit outgoing traffic to sites and services used by remote access tools. (Source: ATT&CK mitigation M1037)

**Network Intrusion Prevention**  
Use intrusion detection signatures to block traffic at network boundaries.

Network intrusion detection and prevention systems that use network signatures may be able to prevent traffic to remote access services. (Source: ATT&CK mitigation M1031)

#### Detection

**Detect remote access software with network monitoring**  
Monitoring network communication can alert on suspicious network connections, for example a user-agent which indicates usage of AnyDesk. If this tool is normally not used in the network, this is reason for suspicion.

### 3.3. Preparing for network discovery

| **Timestamp** | Day 4, 21:24 |
|---|---|
| **Techniques** | T1105 Ingress Tool Transfer to achieve TA0011 Command and Control |
| **Target tech** | Windows |

The adversary used various tools during the attack. What was remarkable, was the fact that the attacker copied at least fifty tools to the victim network and only using a fraction of them. The threat actor downloaded the tools to directories "C:\Users\Administrator\Documents" and "C:\Users\Administrator\Music", some of these included:

• MimiKatz, used to dump various information related to Windows authentication, e.g. password hashes or Kerberos tickets  
• Advanced Port Scanner, a tool for network enumeration  
• xDedicLogCleaner, a tool to clear logging on Windows systems  
• NetScan, a tool for network enumeration  
• PC Hunter, a tool to disable certain antivirus software

The adversary used these tools in subsequent steps of the attack. Since the attacker already had Domain Administrator privileges, it is strange why certain credential dumping tools were downloaded as well. We think that the adversary might have drag-and-dropped a large folder onto the machine via RDP. This shows lack of sophistication as these programs could be flagged by antivirus software and generates more noise in comparison to only using the tools required for the attack.

#### Prevention

**Filter Network Traffic**  
Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic. (Source: ATT&CK mitigation M1037)

Servers and other endpoints that do not require full Internet access should be limited in their connectivity to the minimum necessary. Many internal servers don't need any direct Internet communication or only to a small number of services. Such connectivity restrictions can make it somewhat more difficult for many adversaries to use those systems in their attacks.

**Network Intrusion Prevention**  
Use intrusion detection signatures to block traffic at network boundaries.

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware or unusual data transfer over known tools and protocols like FTP can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures over time or construct protocols in such a way as to avoid detection by common defensive tools.(Citation: University of Birmingham C2) (Source: ATT&CK mitigation M1031)

**Antivirus/Antimalware**  
Use signatures or heuristics to detect malicious software. (Source: ATT&CK mitigation M1049)

Some antivirus solutions will generate an alert when common adversarial tools are downloaded onto the machine.

### 3.4. Inspect the network using Advanced Port Scanner

| **Timestamp** | Day 4, 22:26 |
|---|---|
| **Techniques** | T1046 Network Service Scanning to achieve TA0007 Discovery |
| **Tools** | Advanced Port Scanner |
| **Target tech** | Windows |

The adversary used Advanced Port Scanner to enumerate the victim's network and discover available machines.

Although the attacker deleted most of the logs and the victim had not enabled logging for process creation events, we were able to confirm execution of the tool by the file creation of the output log file.

#### Prevention

**Network Segmentation**  
Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems.

Ensure proper network segmentation is followed to protect critical servers and devices. (Source: ATT&CK mitigation M1030)

#### Detection

**Detect suspicious network scanning activity**  
Monitoring network communication can alert on suspicious network scanning activity that may indicate a malicious actor is performing reconnaissance.

### 3.5. Successful persistence using PoshC2

| **Timestamp** | Day 4, 23:13 |
|---|---|
| **Techniques** | T1543.003 Windows Service to achieve TA0003 Persistence<br>T1008 Fallback Channels to achieve TA0011 Command and Control<br>T1059.001 PowerShell to achieve TA0002 Execution |
| **Tools** | Windows Services, PoshC2 |
| **Target tech** | Windows |

The adversary used a Windows service with the name "CPUpdater" which invoked a PowerShell script that retrieves commands from a command-and-control (C2) server of the attacker. This would allow the threat actor to remain in the network in case the RDP service got disabled.

The service name of the service that was created ("CPUpdater") is also present in an open-source C2 framework, named PoshC2. Furthermore, the PowerShell script that was launched was similar to the dropper that PoshC2 uses. PoshC2 is, therefore, likely a tool used by the attacker.

#### Prevention

**Antivirus/Antimalware**  
Use signatures or heuristics to detect malicious software. (Source: ATT&CK mitigation M1049)

**Code Signing**  
Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing. (Source: ATT&CK mitigation M1045)

#### Detection

**PoshC2 beaconing with network monitoring**  
Monitoring network communication can result in detection of the beaconing of C2 servers. Either by matching on specific data, like SSL certificates, or by recognizing a pattern of beaconing.

### 3.6. Network discovery using NetScan

| **Timestamp** | Day 6, 19:25 |
|---|---|
| **Techniques** | T1046 Network Service Scanning to achieve TA0007 Discovery |
| **Tools** | NetScan |
| **Target tech** | Windows |

The adversary used SoftPerfect Network Scanner (NetScan) to perform reconnaissance in the victim's network and identify potential interesting machines.

#### Prevention

**Network Segmentation**  
Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems.

Ensure proper network segmentation is followed to protect critical servers and devices. (Source: ATT&CK mitigation M1030)

#### Detection

**Detect suspicious network scanning activity**  
Monitoring network communication can alert on suspicious network scanning activity that may indicate a malicious actor is performing reconnaissance.

### 3.7. Possible lateral movement using RDP

| **Timestamp** | Day 6, 19:31 |
|---|---|
| **Techniques** | T1021 Remote Services to achieve TA0008 Lateral Movement |
| **Tools** | RDP |
| **Target tech** | Windows |

Though we cannot prove how the attacker moved laterally throughout the network, as logs were removed, we do know that there was no network segmentation in place. This would allow the attacker, who had Domain Administrator privileges, to log onto any machine via RDP and execute commands on it.

#### Prevention

**User Account Management**  
Manage the creation, modification, use, and permissions associated to user accounts.

Limit the accounts that may use remote services. Limit the permissions for accounts that are at higher risk of compromise; for example, configure SSH so users can only run specific programs. (Source: ATT&CK mitigation M1018)

**Network Segmentation**  
Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems. (Source: ATT&CK mitigation M1030)

### 3.8. Staging exfiltrated data

| **Timestamp** | Day 6, 19:51 |
|---|---|
| **Techniques** | T1560.001 Archive via Utility to achieve TA0009 Collection |
| **Tools** | 7z |
| **Target tech** | Windows |

The adversary created a 7-Zip archive containing more than 2,200 files, named "88.7z". The adversary most likely did this to exfiltrate the collected documents as a single file, which is easier to exfiltrate.

Today, most ransomware threat actors perform double extortion. This means that the attacker both encrypts the data of a company, but also exfiltrates potential interesting information. Then, when attackers request the ransom, companies are more likely to pay it as they do not want their data published. Secondly, the stolen data could be sold elsewhere, generating additional revenue.

### 3.9. Exfiltrate data

| **Timestamp** | Day 6, 19:56 |
|---|---|
| **Techniques** | T1537 Transfer Data to Cloud Account to achieve TA0010 Exfiltration |
| **Target tech** | Windows |

Since the attacker deleted most of the logging, we could not prove data exfiltration took place. However, we do know that the attacker successfully created the 7-Zip archive and later deleted it, which makes it likely that the data was exfiltrated, given that the attacker had access to the machine the whole time.

#### Prevention

**Restrict outgoing traffic**  
Restricting outgoing traffic limits the communication channels available to adversaries. Whitelisting necessary connections is generally an effective method to frustrate many attack techniques.

This mitigation is a specific variant of ATT&CK mitigation M1037: Filter Network Traffic.

### 3.10. Executing the ransomware

| **Timestamp** | Day 1, 20:56 |
|---|---|
| **Techniques** | T1486 Data Encrypted for Impact to achieve TA0040 Impact |
| **Tools** | SunnyDay |
| **Target tech** | Windows |

Following the data staging part, which is often one of the last stages before a ransomware attack, the attackers executed the SunnyDay ransomware, named "64RA_Sun.exe", on three systems. The servers included a Domain Controller and a SharePoint server, significantly disrupting the company network. Remarkably, there were significant delays (ten and forty minutes) between the ransomware execution on the three systems. This hints at manual execution and is another reason why we think that this attacker was not very sophisticated.

The ransomware was executed in the evening, the following day in the morning, Fox-IT CERT was called and an investigation was started.

---

## 4. MITRE ATT&CK TTPs

This chapter lists the MITRE ATT&CK Tactics, Techniques, and Procedures (TTPs) of the attack described in this report. The TTPs are listed in the order they were observed in the attack. They are formatted in a table to facilitate ingestion of this data into other tools, such as Threat Intelligence Platforms (TIPs).

Note that each tactic-technique-procedure combination is listed here, which can lead to apparent duplication. For example, if a procedure is linked to more than one technique, it will be listed repeatedly for each technique.

| **Tactic** | **Technique** | **Procedure** |
|---|---|---|
| Initial Access | T1133 External Remote Services | The attacker gained initial access through a publicly exposed RDP service. Due to deletion of login event logs, we are unable to state when exactly the attacker logged onto the RDP server. The open RDP service was a misconfiguration. |
| Credential Access | T1110.001 Password Guessing | The attacker gained initial access through a publicly exposed RDP service. Due to deletion of login event logs, we are unable to state when exactly the attacker logged onto the RDP server. The open RDP service was a misconfiguration. |
| Command and Control | T1219 Remote Access Software | The adversary tried to execute AnyDesk, a legitimate remote access tool (RAT), in order to create a form of persistence. Though they already had access through RDP, having AnyDesk would allow them to get back into the network once the public RDP service would have been disabled. The AnyDesk connections, however, were blocked by the firewall, which resulted in AnyDesk failing to work. |
| Command and Control | T1105 Ingress Tool Transfer | The adversary used various tools during the attack. What was remarkable, was the fact that the attacker copied at least fifty tools to the victim network and only using a fraction of them. The threat actor downloaded the tools to directories "C:\Users\Administrator\Documents" and "C:\Users\Administrator\Music", some of these included: |
| Discovery | T1046 Network Service Scanning | The adversary used Advanced Port Scanner to enumerate the victim's network and discover available machines. |
| Persistence | T1543.003 Windows Service | The adversary used a Windows service with the name "CPUpdater" which invoked a PowerShell script that retrieves commands from a command-and-control (C2) server of the attacker. This would allow the threat actor to remain in the network in case the RDP service got disabled. |
| Command and Control | T1008 Fallback Channels | The adversary used a Windows service with the name "CPUpdater" which invoked a PowerShell script that retrieves commands from a command-and-control (C2) server of the attacker. This would allow the threat actor to remain in the network in case the RDP service got disabled. |
| Execution | T1059.001 PowerShell | The adversary used a Windows service with the name "CPUpdater" which invoked a PowerShell script that retrieves commands from a command-and-control (C2) server of the attacker. This would allow the threat actor to remain in the network in case the RDP service got disabled. |
| Discovery | T1046 Network Service Scanning | The adversary used SoftPerfect Network Scanner (NetScan) to perform reconnaissance in the victim's network and identify potential interesting machines. |
| Lateral Movement | T1021 Remote Services | Though we cannot prove how the attacker moved laterally throughout the network, as logs were removed, we do know that there was no network segmentation in place. This would allow the attacker, who had Domain Administrator privileges, to log onto any machine via RDP and execute commands on it. |
| Collection | T1560.001 Archive via Utility | The adversary created a 7-Zip archive containing more than 2,200 files, named "88.7z". The adversary most likely did this to exfiltrate the collected documents as a single file, which is easier to exfiltrate. |
| Exfiltration | T1537 Transfer Data to Cloud Account | Since the attacker deleted most of the logging, we could not prove data exfiltration took place. However, we do know that the attacker successfully created the 7-Zip archive and later deleted it, which makes it likely that the data was exfiltrated, given that the attacker had access to the machine the whole time. |
| Impact | T1486 Data Encrypted for Impact | Following the data staging part, which is often one of the last stages before a ransomware attack, the attackers executed the SunnyDay ransomware, named "64RA_Sun.exe", on three systems. The servers included a Domain Controller and a SharePoint server, significantly disrupting the company network. Remarkably, there were significant delays (ten and forty minutes) between the ransomware execution on the three systems. This hints at manual execution and is another reason why we think that this attacker was not very sophisticated. |

---

*Prepared for Fox-IT*  
*Page 11*