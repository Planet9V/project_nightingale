# EXPRESS ATTACK BRIEF 013 (EAB-013)
## Rhysida Ransomware: Transportation Sector Supply Chain Cascade Attacks

**Publication Date:** June 10, 2025  
**Threat Actor:** Rhysida Ransomware Group  
**Primary Targets:** Ports, Airports, Logistics Companies, Rail Systems  
**Risk Level:** CRITICAL  
**Operational Impact:** IT/OT Convergence Attack Vector

---

## EXECUTIVE SUMMARY

The Rhysida ransomware group has emerged as a critical threat to global transportation infrastructure, demonstrating sophisticated capabilities in exploiting supply chain dependencies to create cascading operational failures. Their August 2024 attack on the Port of Seattle, affecting 90,000 victims and disrupting both maritime and aviation operations, exemplifies their ability to target critical transportation nodes that impact food, energy, and consumer goods supply chains.

This brief analyzes Rhysida's transportation sector targeting methodology, revealing a pattern of attacks designed to maximize supply chain disruption through strategic infrastructure compromise. The group's use of the Portstarter backdoor, previously associated with ViceSociety, and their evolution from education sector targeting to critical infrastructure demonstrates operational maturity and strategic planning.

---

## CRITICAL INTELLIGENCE FINDINGS

### Confirmed Transportation Sector Victims (2023-2025)

| Organization | Date | Impact | Ransom Demand |
|-------------|------|---------|---------------|
| Port of Seattle/Sea-Tac Airport | Aug 2024 | 90,000 victims, 3TB data stolen | $6M (100 BTC) |
| JAS Worldwide (Freight Forwarder) | Aug 2024 | Global operations disrupted | Unknown |
| MDB Srl (Logistics) | Apr 2025 | Data theft confirmed | Unknown |
| Asian Logistics Companies* | 2024 | Multiple targets | Unknown |
| Rail Infrastructure (UK)** | Sep 2024 | 19 major stations affected | N/A |

*Multiple unspecified targets reported by threat intelligence
**Indirect impact through Wi-Fi infrastructure attack

### Supply Chain Cascade Effects

The Port of Seattle attack demonstrates Rhysida's understanding of supply chain vulnerabilities:

1. **Primary Impact**: 
   - Baggage handling systems offline
   - Check-in kiosks disabled  
   - Flight information displays down for 3 weeks
   - Maritime cargo operations disrupted

2. **Secondary Impact**:
   - Airlines forced to manual operations
   - Cargo delays affecting perishable goods
   - Supply chain visibility lost
   - Customer data exposure (passports, SSNs)

3. **Tertiary Impact**:
   - Regional food distribution delays
   - Energy supply chain disruptions
   - Manufacturing input delays
   - Economic losses across Pacific Northwest

---

## ATTACK METHODOLOGY ANALYSIS

### Initial Access Vectors

1. **Supply Chain Compromise** (Primary Method)
   - Exploitation of third-party VPN credentials
   - Targeting of suppliers with network access
   - Abuse of trusted relationships (MITRE T1199)

2. **Infrastructure Vulnerabilities**
   - Legacy system exploitation
   - Unpatched VPN gateways without MFA
   - Weak password policies in critical systems

### Persistence Mechanisms

**Portstarter Backdoor Deployment**:
```powershell
schtasks /create /sc ONSTART /tn System /tr "rundll32 C:\Users\Public\main.dll Test" /ru system
```

- Creates scheduled task for persistence
- Runs with SYSTEM privileges
- Establishes C2 communication
- Previously exclusive to ViceSociety operations

### Operational Timeline Pattern

| Phase | Duration | Activity |
|-------|----------|----------|
| Initial Access | Day 1 | VPN credential abuse |
| Reconnaissance | Day 1-2 | Port scanning, network mapping |
| Defense Evasion | Day 2 | Disable security tools |
| Persistence | Day 2-4 | Deploy Portstarter backdoor |
| Data Exfiltration | Day 4-8 | MegaSync transfer (50+ hours) |
| Ransomware Deployment | Day 8+ | ESXi server encryption |

---

## IT/OT CONVERGENCE EXPLOITATION

### Dual-Environment Targeting

Rhysida demonstrates sophisticated understanding of IT/OT convergence in transportation:

1. **IT Systems Compromised**:
   - Ticketing and reservation systems
   - Employee databases
   - Financial systems
   - Customer information repositories

2. **OT Systems Impacted**:
   - Baggage handling automation
   - Security screening systems
   - Flight information displays
   - Port cargo management systems

3. **Convergence Points Exploited**:
   - Shared network segments
   - Common authentication systems
   - Interconnected databases
   - Unified management platforms

### ESXi Virtualization Targeting

```bash
cd /usr/share/
chmod +x 123
./123 -d /vmfs/volumes/
```

- Targets virtualization infrastructure
- Encrypts both IT and OT virtual machines
- Maximizes operational disruption
- Prevents rapid recovery

---

## THREAT ACTOR EVOLUTION

### ViceSociety to Rhysida Transition

Evidence strongly indicates Rhysida represents an evolution of ViceSociety operations:

1. **Technical Similarities**:
   - Exclusive use of Portstarter backdoor
   - SystemBC for C2 communications
   - NTDSUtil usage patterns (temp_l0gs folder)
   - Similar firewall rule modifications

2. **Targeting Correlation**:
   - 32% education sector (Rhysida) vs 35% (ViceSociety)
   - Emergence of Rhysida coincides with ViceSociety decline
   - Maintained focus on "targets of opportunity"

3. **Operational Maturity**:
   - Evolution from education to critical infrastructure
   - Increased ransom demands ($6M for Port of Seattle)
   - More sophisticated supply chain targeting

---

## DETECTION OPPORTUNITIES

### Early Warning Indicators (30-Day Window)

1. **Network Anomalies**:
   - Unusual VPN access patterns from suppliers
   - Port scanning from domain controllers
   - Advanced Port Scanner tool execution
   - Suspicious scheduled task creation

2. **File System Indicators**:
   ```
   C:\Users\Public\main.dll (Portstarter)
   C:\Windows\System32\Tasks\System
   C:\Users\*\AppData\Local\Mega Limited\
   ```

3. **Process Indicators**:
   - ToggleDefender.bat execution
   - rundll32.exe loading suspicious DLLs
   - MegaSync.exe running for extended periods
   - PowerShell history containing schtasks commands

### MITRE ATT&CK Mapping

| Tactic | Technique | Rhysida Implementation |
|--------|-----------|------------------------|
| Initial Access | T1199 Trusted Relationship | Supplier VPN exploitation |
| Persistence | T1053.005 Scheduled Task | Portstarter backdoor |
| Defense Evasion | T1562.001 Disable Tools | ToggleDefender usage |
| Discovery | T1595.001 IP Scanning | Advanced Port Scanner |
| Exfiltration | T1567.002 Cloud Storage | MegaSync (50+ hours) |
| Impact | T1486 Data Encryption | ESXi ransomware deployment |

---

## CRITICAL MITIGATION PRIORITIES

### Immediate Actions Required

1. **Supply Chain Security**:
   - Mandatory MFA for all third-party access
   - Network segmentation for supplier connections
   - Regular audit of trusted relationships
   - Time-based access controls

2. **Transportation-Specific Hardening**:
   - Isolate OT networks from IT systems
   - Implement air-gapped backup systems
   - Deploy OT-specific security monitoring
   - Regular virtualization platform updates

3. **Detection Enhancement**:
   - Monitor for Portstarter indicators
   - Alert on domain controller port scanning
   - Track extended cloud storage connections
   - Implement behavioral analytics for VPN access

---

## STRATEGIC IMPLICATIONS

### Supply Chain Warfare

Rhysida's targeting of transportation infrastructure represents strategic supply chain warfare:

1. **Food Security Impact**: Port disruptions affect agricultural imports/exports
2. **Energy Distribution**: Maritime fuel transport delays
3. **Manufacturing Inputs**: Just-in-time delivery failures
4. **Economic Cascades**: Regional business disruptions

### Critical Infrastructure Convergence

The group's evolution from education to transportation demonstrates:
- Understanding of sector interdependencies
- Ability to maximize cascade effects
- Strategic target selection for maximum impact
- Exploitation of IT/OT convergence vulnerabilities

---

## THREAT OUTLOOK

### Escalation Indicators

1. **Expanding Target Profile**: Evolution from education → healthcare → transportation
2. **Increasing Sophistication**: Portstarter deployment, extended dwell time
3. **Growing Demands**: $6M ransom for single port attack
4. **Strategic Timing**: Attacks during peak operational periods

### Next Likely Targets

Based on pattern analysis:
- Major international airports
- Intermodal freight terminals  
- Railway control systems
- Pipeline transportation infrastructure
- Food distribution centers

---

## APPENDIX: TECHNICAL INDICATORS

### Portstarter Backdoor Hash
```
SHA256: 4e73b21941b9ec81a1298f8bdd177ac8d8db0491a4f41d56c449dcb632c821fc
```

### C2 Infrastructure
- SystemBC communication patterns
- Tor-based command infrastructure
- HTTPS beaconing to compromised sites

### Ransomware Note Pattern
```
File: readme_unlock.txt
Title: "Critical Breach Detected - Immediate Response Required"
Portal: [Onion URL with victim key]
Email: Multiple ProtonMail addresses
```

---

**Classification:** TLP:AMBER  
**Distribution:** Transportation Sector Security Teams  
**Next Review:** July 10, 2025

*For questions about this brief, contact your sector-specific security coordinator.*