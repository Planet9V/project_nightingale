# Technical MITRE Analysis Generation Prompt
## Companion Document for Optimized Express Attack Briefs

**Created:** Saturday, June 7, 2025  
**Purpose:** Generate detailed technical MITRE ATT&CK analysis complementing Optimized Express Attack Briefs  
**Quality Standard:** SOC analyst and incident responder technical depth  
**Template Reference:** Express_Attack_Brief_10_sunnyday-ransomware.md structure  

---

## Core Generation Prompt

### **Master Prompt for Technical MITRE Analysis**

```markdown
Create a comprehensive Technical MITRE Attack Path Analysis following the exact structure, format, and technical depth of Express_Attack_Brief_10_sunnyday-ransomware.md for the threat actor/campaign: [THREAT_NAME].

This document will serve as the technical companion to the Optimized Express Attack Brief, providing SOC analysts and incident responders with detailed forensic evidence and step-by-step attack methodology.

CRITICAL STRUCTURE REQUIREMENTS:
1. **Follow Exact Format**: Mirror the structure of Express_Attack_Brief_10_sunnyday-ransomware.md precisely
2. **Incident-Specific Analysis**: Present as analysis of specific incident, not general campaign overview
3. **Forensic Authenticity**: Include realistic log entries, command lines, file paths, network traffic
4. **MITRE Integration**: Map every attack step to specific tactics and techniques with IDs
5. **Technical Depth**: SOC analyst level detail for immediate deployment

INPUT VARIABLES (Required):
- Threat Actor/Malware: [THREAT_NAME]
- Incident Reference: [INCIDENT_ID] 
- Target Organization: [ORG_TYPE and SECTOR]
- Attack Timeline: [SPECIFIC_DAY_HOUR_TIMELINE]
- Initial Access Vector: [ACCESS_METHOD]
- Tools/Techniques Used: [TOOL_LIST]
- Final Impact: [RANSOMWARE/DATA_THEFT/DISRUPTION]
- Primary CVEs Exploited: [CVE_LIST]

EXACT STRUCTURE TO FOLLOW:

# Express Attack Brief [NUMBER]
## [Threat Name] - [Technical Description]

**Version:** 1.0  
**Publication date:** [Current Date]  
**Prepared for:** [Organization Name]

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
   - 3.1. [Initial Access Method]
   - 3.2. [Persistence Establishment]
   - 3.3. [Discovery Activities]
   - 3.4. [Lateral Movement]
   - 3.5. [Collection/Exfiltration]
   - 3.6. [Impact/Encryption]
   - [Continue for each attack step...]
4. [MITRE ATT&CK TTPs](#4-mitre-attck-ttps)

SECTION CONTENT REQUIREMENTS:

## 1. Introduction
### 1.1. Document purpose
"This document has been prepared for [Organization].

This document describes the attack path observed during a recent cyber security incident. It presents the steps taken by the threat actor, including associated Tactic, Technique, and Procedure (TTP) details. Where possible the TTPs are expressed in MITRE ATT&CK terminology to aid in correlation and cross-referencing with other threat intelligence sources.

This document is aimed at helping readers learn from the incident and prepare to defend against possible future attacks. Its attack path structure is designed to show how the latest cyber attacks actually happen in the real world. The inclusion of TTP details allows readers to map the attack steps to their own organization, validating their security posture, and feeding into their risk management process."

### 1.2. Document structure
[Follow exact format from sample]

### 1.3. Document classification
[Standard classification language]

## 2. Attack overview
### 2.1. Attack description
| **Timeframe** | [Quarter/Year] |
|---|---|
| **Threat type** | [Ransomware/APT/Malware] |
| **Sector relevance** | [Primary Sector] |
| **Geographic relevance** | [Region] |

[2-3 paragraph narrative describing the attack, sophistication level, and overall impact]

### 2.2. Attack path summary
| **Time** | **Tactic** | **Action** | **Target tech** |
|---|---|---|---|
| Day X, HH:MM | [MITRE Tactic] | [Specific Action] | [Technology] |
[Continue for each major attack step...]

## 3. Attack path
[For each attack step, follow this exact format:]

### 3.X. [Attack Step Name]

| **Timestamp** | Day X, HH:MM |
|---|---|
| **Techniques** | [MITRE Technique ID] [Technique Name] to achieve [MITRE Tactic ID] [Tactic Name] |
| **Target tech** | [Specific Technology] |

[Technical narrative explaining what happened, how it was accomplished, and why it was effective]

FORENSIC EVIDENCE REQUIREMENTS:
- Include realistic log entries: `[2024-XX-XX HH:MM:SS] Source_IP - Action details`
- Add command line examples: `command.exe /parameter "C:\\realistic\\path\\file.ext"`
- Provide registry modifications: `HKLM\\Software\\Microsoft\\Windows\\...`
- Include network traffic patterns: `GET /api/endpoint HTTP/1.1`
- Add file system artifacts: `C:\\Users\\[User]\\AppData\\Local\\Temp\\malware.exe`

#### Prevention
[Include 2-3 specific prevention measures with MITRE mitigation references]

#### Detection
[Include 2-3 specific detection methods with data sources and monitoring guidance]

## 4. MITRE ATT&CK TTPs
[Create comprehensive table:]

| **Tactic** | **Technique** | **Procedure** |
|---|---|---|
| [TA####] [Tactic Name] | [T####.###] [Technique Name] | [Specific procedure observed in this incident] |
[Continue for all observed TTPs...]

QUALITY STANDARDS:
1. **Forensic Authenticity**: All evidence must appear realistic and actionable
2. **Technical Accuracy**: Commands, paths, and procedures must be technically valid
3. **MITRE Compliance**: Every technique must be properly mapped and documented
4. **SOC Deployment**: All detection guidance must be immediately implementable
5. **Incident Focus**: Maintain incident-specific rather than general campaign focus

FORENSIC EVIDENCE EXAMPLES:
```
Log Entry Format:
[2024-03-15 14:23:42] 192.168.1.100 - POST /login HTTP/1.1 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

Command Line Format:
powershell.exe -ExecutionPolicy Bypass -File "C:\\Windows\\Temp\\stage2.ps1"

Registry Modification Format:
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate

Network Traffic Format:
GET /api/v1/download?file=../../etc/passwd HTTP/1.1
Host: victim-server.local
User-Agent: [THREAT_NAME] Scanner v1.2
```

Generate the complete Technical MITRE Analysis now, following this structure exactly.
```

---

## Enhancement Prompts

### **Forensic Evidence Enhancement Prompt**

```markdown
Enhance the Technical MITRE Analysis with comprehensive forensic evidence:

REQUIREMENTS:
1. **Log Entries**: Create realistic log entries for each attack step with proper timestamps, source IPs, and action details
2. **Command Lines**: Include actual command syntax with realistic file paths, parameters, and execution context
3. **Network Traffic**: Add packet capture examples, communication patterns, and protocol-specific details
4. **Registry Artifacts**: Specify exact registry keys, values, and modification timestamps
5. **File System Evidence**: Include file creation patterns, naming conventions, hash values, and storage locations
6. **Process Details**: Add parent-child process relationships, execution arguments, and memory indicators

FORENSIC EVIDENCE FORMAT STANDARDS:
- Timestamps: [YYYY-MM-DD HH:MM:SS] format
- IP Addresses: Use realistic private IP ranges (192.168.x.x, 10.x.x.x)
- File Paths: Windows-specific paths with realistic directory structures
- Command Syntax: Actual executable parameters and argument structures
- Hash Values: MD5/SHA256 format (can be example hashes)
- User Accounts: Realistic username formats and privilege levels

EXAMPLE ENHANCEMENTS:
```
Windows Event Log Entry:
[2024-03-15 14:23:42] Event ID 4624 - Account Logon
Account Name: admin_service
Source Network Address: 192.168.100.45
Logon Process: Kerberos
Authentication Package: Kerberos

Command Line Execution:
C:\\Windows\\System32\\cmd.exe /c "wmic process call create 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\ProgramData\\update.ps1'"

Registry Persistence:
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
Value Name: WindowsSecurityUpdate
Value Data: "C:\\Windows\\System32\\svchost.exe -k SecurityUpdate"
Timestamp: 2024-03-15 14:24:15
```

Apply these enhancements to every attack step in the Technical MITRE Analysis.
```

### **MITRE ATT&CK Integration Enhancement Prompt**

```markdown
Strengthen MITRE ATT&CK framework integration throughout the Technical Analysis:

REQUIREMENTS:
1. **Precise Technique Mapping**: Use exact MITRE technique IDs (T####.###) including subtechniques
2. **Tactic Progression**: Ensure logical progression through MITRE tactics (TA0001 → TA0040)
3. **Data Source Correlation**: Map detection methods to MITRE data sources
4. **Mitigation Alignment**: Connect prevention measures to MITRE mitigation IDs (M####)
5. **Procedure Documentation**: Detail specific procedures as observed in this incident

MITRE INTEGRATION REQUIREMENTS:
- Every attack step must map to specific MITRE technique
- Include primary technique and relevant subtechniques
- Reference appropriate MITRE data sources for detection
- Align prevention measures with MITRE mitigations
- Maintain technique accuracy and current framework version

EXAMPLE MITRE INTEGRATION:
```
### 3.2. Persistence via Registry Modification

| **Timestamp** | Day 1, 14:24 |
|---|---|
| **Techniques** | T1547.001 Registry Run Keys / Startup Folder to achieve TA0003 Persistence |
| **Target tech** | Windows Registry |

The threat actor established persistence by modifying the Windows Registry Run key...

#### Prevention
**M1024 Restrict Registry Permissions**
Source: ATT&CK mitigation M1024 in the context of technique T1547.001

#### Detection
**Monitor Windows Registry Key Modification**
Source: ATT&CK data component Windows Registry Key Modification in the context of technique T1547.001
```

Complete MITRE TTP Table:
| **Tactic** | **Technique** | **Procedure** |
|---|---|---|
| TA0001 Initial Access | T1190 Exploit Public-Facing Application | [Specific procedure observed] |
| TA0003 Persistence | T1547.001 Registry Run Keys / Startup Folder | [Specific registry modification] |
[Continue for all techniques...]

Apply comprehensive MITRE integration to the entire Technical Analysis.
```

### **SOC Deployment Optimization Prompt**

```markdown
Optimize the Technical MITRE Analysis for immediate SOC team deployment:

REQUIREMENTS:
1. **SIEM Rules**: Provide specific detection rules for security information and event management systems
2. **Network Signatures**: Include IDS/IPS rules for network monitoring platforms
3. **Endpoint Queries**: Add hunting queries for endpoint detection and response platforms
4. **Threat Intelligence**: Format IoCs for threat intelligence platform ingestion
5. **Response Procedures**: Detail step-by-step incident response procedures

SOC DEPLOYMENT FORMATS:

SIEM DETECTION RULES:
```
Sigma Rule Format:
title: [THREAT_NAME] PowerShell Execution
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4103
        CommandLine|contains: 
            - '-ExecutionPolicy Bypass'
            - '-WindowStyle Hidden'
    condition: selection
```

NETWORK SIGNATURES:
```
Suricata Rule Format:
alert http any any -> any any (msg:"[THREAT_NAME] C2 Communication"; 
content:"GET"; http_method; content:"/api/update"; http_uri; 
reference:url,threat-intel.com/[THREAT_NAME]; sid:2024001;)
```

ENDPOINT HUNTING QUERIES:
```
KQL Query (Defender):
ProcessCreationEvents
| where ProcessCommandLine contains "powershell" and ProcessCommandLine contains "-ExecutionPolicy Bypass"
| where TimeGenerated > ago(7d)
```

THREAT INTELLIGENCE IoCs:
```
STIX Format:
indicator_type: file
pattern: [file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']
labels: malicious-activity
```

Apply SOC deployment optimization to every technical section of the analysis.
```

---

## Quality Validation Checklist

### **Technical Accuracy Validation**
- [ ] All command lines are syntactically correct and executable
- [ ] File paths follow realistic Windows/Linux directory structures  
- [ ] Registry keys use proper Windows registry hierarchy
- [ ] Network traffic examples use valid protocol formats
- [ ] Hash values follow proper MD5/SHA256 formats
- [ ] IP addresses use realistic private network ranges

### **MITRE ATT&CK Compliance**
- [ ] Every attack step maps to specific MITRE technique with ID
- [ ] Tactic progression follows logical attack timeline
- [ ] Subtechniques are used where appropriate (T####.###)
- [ ] Data sources align with detection recommendations
- [ ] Mitigation IDs are properly referenced (M####)
- [ ] Complete TTP table includes all observed techniques

### **Forensic Evidence Quality**
- [ ] Log entries include realistic timestamps and formatting
- [ ] Command execution includes proper parent-child relationships
- [ ] Network traffic shows realistic communication patterns
- [ ] File system artifacts include creation times and locations
- [ ] Registry modifications show proper key-value structures
- [ ] Process details include execution context and arguments

### **SOC Deployment Readiness**
- [ ] Detection rules are immediately deployable in SIEM platforms
- [ ] Network signatures follow proper IDS/IPS rule syntax
- [ ] Hunting queries are validated for endpoint platforms
- [ ] IoCs are formatted for threat intelligence platform ingestion
- [ ] Response procedures include specific step-by-step actions
- [ ] All technical guidance includes implementation details

### **Document Structure Compliance**
- [ ] Follows exact structure of Express_Attack_Brief_10_sunnyday-ransomware.md
- [ ] Table of contents includes all required sections
- [ ] Introduction sections use standard language
- [ ] Attack path sections include prevention and detection
- [ ] MITRE TTP table is comprehensive and accurate
- [ ] Document classification and metadata are complete

---

## Implementation Workflow

### **Step 1: Input Collection**
```bash
# Required inputs for Technical MITRE Analysis generation
THREAT_NAME="[Specific threat actor or malware family]"
INCIDENT_ID="[Unique incident reference number]"
TARGET_ORG="[Organization type and sector]" 
TIMELINE="[Specific day/hour attack progression]"
ACCESS_METHOD="[Initial compromise vector]"
TOOLS_USED="[Complete tool and technique list]"
FINAL_IMPACT="[Ransomware encryption, data theft, etc.]"
CVE_LIST="[Primary vulnerabilities exploited]"
```

### **Step 2: Primary Document Generation**
```markdown
Apply Core Generation Prompt with:
- Exact structure compliance
- Forensic evidence integration
- MITRE ATT&CK mapping
- Technical depth requirements
- SOC deployment optimization
```

### **Step 3: Enhancement Application**
```markdown
Apply Enhancement Prompts sequentially:
1. Forensic Evidence Enhancement
2. MITRE ATT&CK Integration Enhancement  
3. SOC Deployment Optimization
```

### **Step 4: Quality Validation**
```markdown
Validate against all checklist criteria:
- Technical accuracy
- MITRE compliance
- Forensic evidence quality
- SOC deployment readiness
- Document structure compliance
```

### **Step 5: Cross-Reference with Optimized Brief**
```markdown
Ensure consistency with paired Optimized Express Attack Brief:
- Same incident timeline and evidence
- Consistent threat actor attribution
- Aligned technical findings
- Complementary audience value
```

---

**CRITICAL SUCCESS FACTOR**: The Technical MITRE Analysis must provide SOC analysts and incident responders with immediately actionable intelligence for threat detection, hunting, and response - complementing the executive-focused Optimized Express Attack Brief for comprehensive threat intelligence coverage.

---

**Template Authority**: Based on Express_Attack_Brief_10_sunnyday-ransomware.md structure  
**Validation**: Proven forensic evidence formats and MITRE ATT&CK integration standards  
**Deployment Status**: Ready for immediate implementation across all threat scenarios