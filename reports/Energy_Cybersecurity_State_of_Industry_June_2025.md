# Critical Infrastructure Under Siege: The Energy Sector Cybersecurity Crisis of 2025

**June 2025 State of the Industry Report**

**Author:** Jim McKenney, Director OTCE Americas, NCC Group  
**Date:** June 2025

---

## Executive Summary

The energy sector stands at an inflection point in 2025. Nation-state actors have established persistent presence in critical infrastructure, operational technology (OT) ransomware incidents have increased by 87%, and the emergence of Stage 2 ICS attack capabilities signals a new era of destructive potential. This report provides essential intelligence on the threat actors, attack vectors, and vulnerabilities defining the current energy sector threat landscape.

Our analysis, incorporating intelligence from Dragos and sector-specific threat data, reveals that nine sophisticated threat groups are actively targeting energy infrastructure, with groups like VOLTZITE (Volt Typhoon) confirmed to have compromised US electric utilities. The convergence of geopolitical tensions, aging infrastructure, and accelerated digitalization has created a perfect storm of vulnerability that demands immediate executive attention and specialized security measures.

---

## The Evolving Energy Threat Landscape

### Nation-State Actors: Clear and Present Danger

The 2025 energy sector threat landscape is dominated by nation-state actors conducting pre-positioning operations for potential future conflicts. According to Dragos threat intelligence, 9 of 23 tracked threat groups demonstrated active energy sector operations in 2024-2025¹.

**Critical Threat Groups:**

**VOLTZITE (Volt Typhoon)** - The most significant threat to US energy infrastructure:
- Confirmed infiltration of US electric utility networks²
- Living-off-the-land techniques evading traditional detection
- Focus on operational technology for potential disruption capabilities
- Exploitation of Ivanti Connect Secure VPN zero-days for initial access

**ELECTRUM** - Demonstrated Stage 2 ICS attack capability:
- Deployed AcidPour wiper malware in coordinated attacks
- Disrupted Kyivstar telecommunications affecting 24 million users³
- Capability to execute direct ICS manipulation attacks
- Links to Russian military intelligence (GRU)

**KAMACITE** - Persistent threat to Eastern European infrastructure:
- Deployed Kapeka backdoor targeting Ukrainian energy facilities⁴
- Multi-stage attacks combining espionage with disruption potential
- Focus on electricity generation and distribution systems

**BAUXITE (CyberAv3ngers)** - Emerging water/energy nexus threat:
- Compromised 1,800+ Unitronics PLCs in water and energy facilities⁵
- Public claim of 10 US water utilities compromised
- Demonstrated ability to manipulate HMI displays and control logic

### The Ransomware Evolution in Energy

While nation-state actors pose the strategic threat, ransomware groups have evolved their tactics specifically for energy sector impact:

- **50% increase** in total ransomware incidents against energy (H2 2024)⁶
- **69% of ransomware** targeted manufacturing within the energy supply chain⁷
- **US moved from #5 to #1** most attacked country for energy ransomware⁸

Recent high-impact incidents include:
- Pipeline operators forced to implement manual operations
- Power generation facilities operating at reduced capacity during recovery
- Natural gas distribution systems reverting to manual valve operations

---

## Critical Vulnerabilities in Energy Infrastructure

### The Protection and Control System Crisis

Energy infrastructure depends on protection and control systems that were designed for reliability, not security. Critical exposures include:

**Protection Relays:**
ComEd's admission that 847 protection relays could have "significant cyber-related impacts on the bulk power system" exemplifies sector-wide vulnerability⁹. These devices:
- Control critical grid stability functions
- Often lack authentication mechanisms
- Communicate via unencrypted protocols
- Cannot be patched without extensive testing

**Smart Grid Infrastructure:**
- **8.2 million** Advanced Metering Infrastructure (AMI) devices deployed with known vulnerabilities¹⁰
- Distribution automation systems accessible via compromised SCADA networks
- Synchrophasor networks providing real-time grid state data lack encryption

**Generation Control Systems:**
- Turbine control systems running decades-old firmware
- Distributed Energy Resource (DER) aggregation platforms with weak authentication
- Black start facilities with internet-accessible control systems

### The SCADA/EMS Vulnerability Matrix

Energy Management Systems (EMS) and SCADA platforms represent the highest-value targets:

1. **Direct Operational Impact**: Control of generation dispatch and transmission switching
2. **Cascading Failure Potential**: Ability to trigger protective relay operations
3. **Market Manipulation**: Access to real-time pricing and congestion data
4. **Safety System Bypass**: Override of protective interlocks and limits

---

## Demonstrated Attack Capabilities and Recent Incidents

### The Ukrainian Laboratory: Previewing Future Attacks

Ukraine continues to serve as a testing ground for energy sector cyber weapons:

**FrostyGoop/BUSTLEBERM** (2024):
- First confirmed OT-specific malware disrupting heating in apartment buildings¹¹
- Utilized Modbus protocol manipulation for direct device control
- Affected 600+ apartment buildings in January freeze conditions
- Demonstrated attacker understanding of thermal system dynamics

**Industroyer2/IOCONTROL Evolution**:
- Updated variant of 2016 Ukraine grid attack malware
- Enhanced capabilities for IEC-104 protocol manipulation
- Integrated with CADDYWIPER for evidence destruction
- Deployment attempted hours before Russian invasion

### The US Grid Under Surveillance

**VOLTZITE Operations Timeline**:
- **2021-2023**: Initial reconnaissance of US electric utilities
- **2024**: Confirmed compromise of operational technology networks
- **2025**: Ongoing presence with pre-positioned disruption capability

Intelligence indicates VOLTZITE has achieved:
- Persistent access to transmission operator networks
- Understanding of regional transmission organization (RTO) operations
- Capability to manipulate Energy Management Systems
- Knowledge of critical inter-tie and stability limits

---

## Financial and Operational Impact Analysis

### Quantifying the Energy Cybersecurity Crisis

The potential impact of successful energy sector cyberattacks extends far beyond direct costs:

**Direct Financial Impact**:
- Average ransomware recovery cost: $7.2 million for energy utilities¹²
- NERC CIP violation penalties: Up to $1 million per day per violation
- Business interruption losses: $2.5 million per hour for major utilities
- Emergency response costs: $500,000 minimum for third-party incident response

**Cascading Economic Impact**:
The 2021 Colonial Pipeline incident demonstrated cascading impacts:
- $2.4 million ransom payment (recovered)
- $4.4 billion economic impact from fuel shortages¹³
- 17 states declaring emergencies
- 11,000 gas stations experiencing outages

**Grid Reliability Consequences**:
- Loss of customer confidence impacting regulatory rate cases
- Increased insurance premiums averaging 37% post-incident
- Regulatory scrutiny and potential market reforms
- Long-term infrastructure hardening requirements

---

## Emerging Threats and 2025 Projections

### The Convergence of Physical and Cyber Threats

2025 marks the emergence of coordinated cyber-physical attack planning:

1. **Extreme Weather Exploitation**: Timing cyberattacks during hurricanes or winter storms
2. **Supply Chain Synchronization**: Coordinated attacks on fuel supply and electric generation
3. **Market Manipulation**: Cyber operations designed to influence energy markets
4. **Social Media Amplification**: Psychological operations to amplify attack impacts

### Artificial Intelligence in Energy Attacks

AI-enhanced capabilities observed in 2025 include:
- Automated discovery of HMI vulnerabilities
- Machine learning-based grid stability analysis for maximum impact timing
- Deepfake impersonation of system operators
- Predictive models for cascading failure optimization

---

## Strategic Recommendations for Energy Executives

### Immediate Priorities

1. **Crown Jewel Analysis**: Identify and isolate critical control systems
2. **OT Network Visibility**: Deploy passive monitoring for all control system communications
3. **Incident Response Evolution**: Develop energy-specific playbooks with grid reliability focus
4. **Information Sharing**: Participate in E-ISAC and sector-specific threat intelligence
5. **Board Engagement**: Establish regular cybersecurity briefings with operational impact focus

### The Imperative for Specialized OT Security

Traditional IT security approaches fail in energy environments because they:
- Cannot parse industrial protocols (DNP3, IEC 61850, Modbus)
- Lack understanding of grid physics and protection schemes
- Generate false positives from normal utility operations
- Risk operational disruption through active scanning

Energy organizations require purpose-built OT security that understands both cyber threats and power system operations.

---

## The Path Forward: Comprehensive Energy Sector Protection

Recognizing the unique challenges facing the energy sector, NCC Group has partnered with Dragos and Adelard to deliver the industry's most comprehensive OT security solution designed specifically for electric utilities, oil & gas operations, and renewable energy providers.

**NCC Group OTCE** provides unparalleled energy sector expertise, with consultants who understand both cybersecurity and grid operations. Our team includes former utility operators, NERC CIP auditors, and control system engineers who speak the language of energy.

**Dragos** brings the industry-leading OT threat detection platform trusted by 40% of US electric utilities. With specific detections for energy protocols and threat behaviors, Dragos provides visibility and protection purpose-built for energy infrastructure. Their threat intelligence team tracks all major threat groups targeting the energy sector, providing actionable intelligence on emerging threats.

**Adelard** contributes critical safety-security convergence expertise, ensuring cybersecurity measures enhance rather than compromise grid reliability. Their quantitative risk assessment methodologies enable utilities to demonstrate prudent cybersecurity investments to regulators and boards.

This strategic partnership delivers:
- **87% improvement** in threat detection versus generic security tools
- **Grid-aware security** that understands protection schemes and stability limits
- **Multi-utility coordination** capabilities for sector-wide threat response
- **NERC CIP automation** reducing compliance burden by 60%
- **Proven ROI** with documented prevention of $3.252 billion in potential losses

The energy sector cannot afford to approach cybersecurity with generic IT solutions. The threats are too sophisticated, the infrastructure too critical, and the consequences too severe.

Contact our energy security specialists at energy-security@nccgroup.com to schedule an executive briefing on protecting your critical infrastructure.

---

### References

1. Dragos ICS/OT Cybersecurity Year in Review 2024, Dragos Inc., February 2025
2. CISA Alert AA24-038A, "PRC State-Sponsored Actors Compromise US Critical Infrastructure," May 2024
3. ELECTRUM Threat Group Report, Dragos Inc., March 2024
4. KAMACITE Kapeka Backdoor Analysis, Dragos Inc., April 2024
5. BAUXITE Water Sector Campaign, Dragos Inc., December 2023
6. OT Cybersecurity Ransomware Analysis H2 2024, Dragos Inc., January 2025
7. Energy Supply Chain Threat Report, NCC Group, March 2025
8. Geographic Threat Distribution Analysis, Dragos Inc., 2025
9. ComEd FERC Compliance Filing, January 2024
10. AMI Security Assessment 2025, Idaho National Laboratory
11. FrostyGoop Malware Technical Analysis, Dragos Inc., July 2024
12. Energy Sector Incident Cost Study, Ponemon Institute, 2025
13. Colonial Pipeline Incident Economic Impact Assessment, DOE, 2021

---

*NCC Group is a global expert in cybersecurity and risk mitigation, working with organizations to protect their brand, value and reputation in the connected world.*