# Critical Infrastructure Threat Actors Notecard - June 2025

**Generated**: June 14, 2025
**Classification**: TLP:CLEAR
**Sources**: CISA, Dragos, Microsoft Security, Industry Reports

## Executive Summary

The critical infrastructure threat landscape in June 2025 is characterized by sophisticated nation-state actors, evolving ransomware groups, and the emergence of OT-specific malware families. Key trends include:
- 87% increase in ransomware activity targeting OT/ICS environments
- Discovery of 9th and 10th ICS-specific malware variants (Fuxnet, FrostyGoop)
- Significant restructuring of ransomware ecosystem following law enforcement actions
- Continued focus on living-off-the-land techniques and supply chain compromises

---

## Nation-State Threat Actors

### VOLT TYPHOON (China)
**Aliases**: Insidious Taurus, Bronze Silhouette
**Primary Targets**: Energy, Water, Communications, Transportation
**Active Since**: Mid-2021 (possibly earlier)

**Key Capabilities**:
- Living-off-the-land (LOTL) techniques using native Windows tools
- Persistent presence (300+ days in US electric grid undetected)
- Pre-positioning for potential conflict scenarios
- Targeting of smaller, strategic infrastructure sites critical for recovery

**Recent Activity (2025)**:
- Confirmed Chinese acknowledgment of operations in Geneva summit (December 2024)
- Active campaigns against Taiwan critical infrastructure
- Focus on developing capabilities to disrupt US-Asia communications during potential conflicts

**TTPs**:
- Compromise of edge devices (routers, firewalls, VPNs)
- Use of compromised infrastructure as relay points
- Minimal use of malware, preferring legitimate tools
- Target heating, ventilation, and air conditioning in server rooms

### VOLTZITE (China - OT Unit of Volt Typhoon)
**Primary Targets**: Electric, Oil & Gas, Water/Wastewater, Government
**Significance**: Most crucial threat group for critical infrastructure

**Key Characteristics**:
- Dedicated focus on OT data and systems
- Uses peer-to-peer relay networks from compromised organizations
- Targets smallest and most strategic sites needed for recovery
- Enumeration of internet-exposed critical infrastructure

### BAUXITE (Iran)
**Attribution**: IRGC Cyber and Electronic Command
**Primary Targets**: Oil & Gas, Electric, Water/Wastewater, Chemical Manufacturing
**Geographic Focus**: US, Europe, Australia, Middle East

**Key Capabilities**:
- Stage 2 ICS Cyber Kill Chain capabilities
- PLC compromise and custom backdoor deployment
- Technical alignment with CyberAv3ngers hacktivist persona
- Exploitation of Sophos firewalls and exposed ICS devices

**2025 Projection**: Expected to enhance capabilities and conduct disruptive operations globally

### GRAPHITE (Russia)
**Attribution**: Strong overlaps with APT28
**Primary Targets**: Energy, Oil & Gas, Logistics, Government in Eastern Europe
**Focus**: Organizations relevant to Ukraine military situation

**Key Activities**:
- Spear-phishing campaigns against hydroelectric and gas pipeline operators
- Has not yet demonstrated Stage 2 ICS capabilities
- May shift targeting based on geopolitical developments

---

## Ransomware Groups - June 2025 Landscape

### Active Groups

#### RANSOMHUB
**Status**: Most active (434 victims in 2024)
**Origin**: Former ALPHV/BlackCat affiliates
**Targets**: Manufacturing, Professional Services, Consumer Products
**Significance**: Second-most cyber extortion victims in 2024

#### CICADA3301
**Status**: Emerging threat
**Origin**: Code similarities with ALPHV/BlackCat
**Capabilities**: Recruited high-level affiliate teams from defunct groups

#### BLACK BASTA
**Status**: Active but showing signs of fatigue
**Recent**: Internal chat logs leaked (February 2024)
**Activity**: Recording all-time high transfer numbers despite disbanding rumors

### Defunct/Declining Groups

#### LOCKBIT 3.0
**Status**: Becoming irrelevant, likely to disband
**Reason**: Indictments and sanctions preventing ransom collection
**Impact**: Affiliates migrating to other RaaS operations

#### ALPHV/BLACKCAT
**Status**: Dissolved (early 2024)
**Exit**: Received $22 million from Optum before going dark
**Legacy**: Infrastructure and affiliates absorbed by RansomHub and Cicada3301

---

## ICS-Specific Malware Families

### FROSTYGOOP (9th Known ICS Malware)
**First Seen**: January 2024 (Ukraine heating attack)
**Impact**: 600+ apartment buildings lost heating in sub-zero temperatures

**Technical Details**:
- First malware to use Modbus TCP/502 protocol for commands
- Avoids deploying malware on network assets (reduces detection)
- Can read/write data to ICS devices via Modbus
- Global threat: ~46,000 internet-exposed Modbus devices worldwide

### FUXNET (8th Known ICS Malware)
**Attribution**: Pro-Ukraine hacktivist group BlackJack
**Target**: Russian Moskollektor (Moscow utilities)
**Impact**: Disabled 87,000 sensors across Russian infrastructure

**Capabilities**:
- Targets industrial sensor gateways (RS485, Meter-Bus)
- Deletes critical files and corrupts routing tables
- Reprograms firmware and destroys NAND storage
- Sends random data to overload communication channels

**Significance**: "Very escalatory and proliferation style of malware" - demonstrates tradecraft that other actors can adopt

---

## Supply Chain Attack Trends (June 2025)

### Current Statistics
- **25% increase** in supply chain attacks (Oct 2024 - May 2025)
- **22 of 24 sectors** hit in first 5 months of 2025
- **$60 billion** estimated global cost in 2025

### Recent Campaigns (April-May 2025)
1. **Killsec Group**: Compromised Australian IT/telecom provider
2. **Crypto24**: Stole 3TB from Singapore technology company
3. **Unknown Actor**: Admin access to Indian fintech cloud infrastructure

### Geographic Distribution
- **US**: 31 incidents (highest)
- **Europe**: 27 incidents (France: 10)
- **APAC**: 26 incidents (India: 9, Taiwan: 4)
- **Middle East/Africa**: 10 incidents

---

## Key Vulnerabilities and Attack Vectors

### Most Exploited
1. **Default/Weak Credentials**: Primary vector for PLC compromise
2. **Exposed ICS Devices**: Direct internet connectivity
3. **Sophos Firewall Vulnerabilities**: Active exploitation by BAUXITE
4. **Remote Access Solutions**: Industrial remote connectivity
5. **Supply Chain Trust**: Third-party vendor compromises

### Emerging Techniques
- AI-powered reconnaissance (ChatGPT for target research)
- Living-off-the-land avoiding traditional malware
- Double-extortion ransomware techniques
- Compromised infrastructure as attack relays

---

## Defensive Priorities

### Immediate Actions
1. **Patch Sophos Firewalls**: Critical vulnerabilities actively exploited
2. **Secure PLCs**: Change all default passwords, implement MFA
3. **Network Segmentation**: Isolate OT from IT networks
4. **Remote Access**: VPN/Zero-trust for all industrial connectivity
5. **Supply Chain**: Verify third-party security practices

### Strategic Recommendations
- Deploy OT-specific threat detection (traditional IT tools insufficient)
- Subscribe to threat intelligence (Dragos WorldView, CISA alerts)
- Implement continuous OT network monitoring
- Develop incident response plans for physical consequences
- Regular vulnerability assessments of ICS environments

---

## Intelligence Gaps and Future Concerns

### Key Uncertainties
- Full extent of Volt Typhoon pre-positioning in critical infrastructure
- Potential collaboration between threat groups
- Next generation of ICS-specific malware capabilities
- Impact of AI on attack sophistication

### Emerging Risks
- Satellite provider attacks causing widespread outages
- Escalation of ICS malware development and proliferation
- Geopolitically motivated physical destruction via cyber means
- Exploitation of AI/ML systems in critical infrastructure

---

**Next Update**: July 2025
**Distribution**: Security Operations, Executive Leadership, OT Engineering
**Action Required**: Review defensive priorities and implement immediate actions