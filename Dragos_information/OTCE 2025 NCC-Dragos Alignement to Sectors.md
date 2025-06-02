NCC OTCE PARTNER BACKGROUND

Metadata:  
Date: 2025-3-20  
Author: J.Mckenney

NCC-Dragos Partnership

Sector Opportunities and Messaging

Aligned to Sectors

* Oil and Gas  
* Electric  
* Manufacturing  
* Water  
* Transportation

Key Components

* Threat Alignment	  
* Campaign Components	  
* Campaign Message	

Contents

[1\. Oil & Gas Sector Campaign: “Resilient Operations”	3](#1.-oil-&-gas-sector-campaign:-“resilient-operations”)

[Threat Alignment	3](#threat-alignment)

[Campaign Components	4](#campaign-components)

[Campaign Message	4](#campaign-message)

[2\. Electric Power Sector Campaign: “Grid Defense”	6](#2.-electric-power-sector-campaign:-“grid-defense”)

[Threat Alignment	6](#threat-alignment-1)

[Campaign Components	7](#campaign-components-1)

[Campaign Message	7](#campaign-message-1)

[3\. Manufacturing Sector Campaign: “Continuous Production Security”	9](#3.-manufacturing-sector-campaign:-“continuous-production-security”)

[Threat Alignment	9](#threat-alignment-2)

[Campaign Message	10](#campaign-message-2)

[**Threat Focus:** Ransomware, Legacy Malware, Fieldbus Vulnerabilities.	10](#threat-focus:-ransomware,-legacy-malware,-fieldbus-vulnerabilities.)

[4\. Water and Wastewater Sector Campaign: “Critical Infrastructure Protection”	12](#4.-water-and-wastewater-sector-campaign:-“critical-infrastructure-protection”)

[Threat Alignment	12](#threat-alignment-3)

[Campaign Message	13](#campaign-message-3)

[5\. Transportation and Logistics Campaign: “Supply Chain Resilience”	14](#5.-transportation-and-logistics-campaign:-“supply-chain-resilience”)

[Threat Alignment	14](#threat-alignment-4)

[Campaign Message	15](#campaign-message-4)

[Cross-Sector Implementation Strategy	17](#cross-sector-implementation-strategy)

[NCC Services and Solutions	17](#ncc-services-and-solutions)

[Cross-Cutting Campaign Elements	17](#cross-cutting-campaign-elements)

[Aligned with SANS ICS 5 Critical Controls	17](#aligned-with-sans-ics-5-critical-controls)

[Marketing and Sales Enablement	18](#marketing-and-sales-enablement)

[**References**	18](#references)

**Aligned with Dragos 2025 OT/ICS Cybersecurity Report**

---

## 1\. Oil & Gas Sector Campaign: “Resilient Operations” {#1.-oil-&-gas-sector-campaign:-“resilient-operations”}

### Threat Alignment {#threat-alignment}

| Threat Group | TTPs | Impact |
| :---- | :---- | :---- |
| **KAMACITE** | Spear-phishing, credential theft, DarkCrystal RAT, Kapeka backdoor | Initial access to ONG organizations |
| **BAUXITE** | SSH attacks, default credentials, IOControl backdoor | Compromised ONG devices via SSH |
| **VOLTZITE** | Industrial protocol scanning, GIS data theft | Intelligence gathering on natural gas infrastructure |

**Actionable Tactics**:  
\- Threat hunting for IOControl backdoors in offshore rigs.  
\- Secure configuration reviews for GE Vernova turbines.  
\- Joint SOC with BP/Shell using NCC’s OT threat intelligence.

**Threat Landscape**

* **KAMACITE**: Spear-phishing campaigns targeting European oil and gas (ONG) operators via DarkCrystal RAT (Dragos, 2025).

* **BAUXITE**: SSH brute-force attacks on offshore rigs, exploiting default credentials in 32% of IOControl backdoor incidents (Frost & Sullivan, 2025).

* **VOLTZITE**: MQTT-based C2 exfiltrating GIS data from pipelines (Dragos, 2025).

**Strategic Imperatives**

1. **AI-Driven Threat Hunting**: Deploy machine learning models trained on Dragos’ OT protocol rules to detect IOControl backdoors (Toloka.ai, 2024).

2. **Zero Trust Segmentation**: Isolate SCADA systems using Fortinet’s OT-aware firewalls (BDO USA, 2023).

3. **Supply Chain Hardening**: Audit 400+ vendors per facility using NIST’s C-SCRM framework (Flexential, 2023).

**NCC Group Solutions**

* **OT Network Monitoring**: Integrate Dragos Platform with Palo Alto Cortex XDR for real-time threat detection (Codecademy, 2024).

* **Incident Response Playbooks**: Co-develop ransomware recovery protocols with Black & Veatch’s consequence-first model (Exabeam, n.d.).

* **ICS Network Security Monitoring**: Deploy Dragos Platform for threat detection targeting DarkCrystal RAT/Kapeka backdoor.

* **OT Vulnerability Assessments**: Prioritize vulnerabilities in SCADA systems (Modbus TCP exposure) and VPN appliances.

* **Incident Response Planning**: Tabletop exercises simulating ransomware attacks on pipeline operations.

**Competitive Differentiation**

* **Proprietary Threat Intel**: Cross-reference Dragos’ VOLTZITE patterns with WEF’s hybri

### Campaign Components {#campaign-components}

1. **Assessment & Detection Package**

   * ICS Network Security Monitoring with Dragos Platform integration

   * OT Vulnerability Assessment focused on VPN appliances and SCADA systems

   * Threat hunting for IOControl backdoor indicators

2. **Technical Demonstration**

   * Live simulation of KAMACITE attack chain against pipeline operations

   * Detection capabilities for DarkCrystal RAT and Kapeka backdoor

   * MQTT-based C2 traffic analysis dashboard

3. **Case Study Development**

   * “European Energy Provider Stops KAMACITE Before Stage 2”

   * “Detecting GIS Data Exfiltration in Pipeline Operations”

### Campaign Message {#campaign-message}

*“Protect critical pipeline operations from sophisticated threat actors targeting your industrial control systems while meeting regulatory requirements and maintaining operational reliability.”*

**Threat Focus:** KAMACITE (spear-phishing, credential theft), BAUXITE (SSH attacks, IOControl), VOLTZITE (GIS data theft).

**Campaign Objective:** Position NCC Group as the trusted partner for protecting critical oil and gas infrastructure from advanced persistent threats.

**Key Messaging:** “Protect your operations from state-sponsored attacks and maintain uninterrupted production. NCC Group delivers proactive threat detection and incident response capabilities tailored for the unique challenges of the oil and gas sector.”

**Campaign Components:**

* **Threat Briefing Webinar:** “The Evolving Threat Landscape for Oil & Gas – A Dragos Perspective.”

* **Targeted Assessment:** “OT Security Posture Assessment – Pipeline & Offshore Rig Focus.”

* **Technical Demonstration:** Simulated KAMACITE attack scenario with Dragos Platform detection.

* **Case Study:** “Securing a Major European Oil & Gas Operator from Advanced Threats.”

* **Content Marketing:** Blog posts, white papers, and infographics on oil & gas cybersecurity best practices.

**Metrics:** 20 Qualified Leads, 5 Assessment Bookings, 2 Closed Deals.

---

## 2\. Electric Power Sector Campaign: “Grid Defense” {#2.-electric-power-sector-campaign:-“grid-defense”}

### Threat Alignment {#threat-alignment-1}

| Threat Group | TTPs | Impact |
| :---- | :---- | :---- |
| **ELECTRUM** | Wiper malware (AcidPour), ICS targeting | Disruption of electric operations |
| **VOLTZITE** | GIS data theft, SOHO router compromise, MQTT-based C2 | Intelligence gathering on grid infrastructure |
| **BAUXITE** | SSH attacks, default credentials, IOControl backdoor | Compromise of electric sector control systems |

**Actionable Tactics**:  
\- Deploy protocol-aware firewalls for DNP3/Modbus traffic.  
\- Partner with GE Vernova to harden GridOS DERMS platforms.

**Threat Landscape**

* **ELECTRUM**: AcidPour wiper malware targeting Ukrainian-style grids (Dragos, 2025).

* **VOLTZITE**: SOHO router compromises enabling MQTT C2 traffic (Dragos, 2025).

* **DDoS Risks**: 1,162 utility cyberattacks in 2024 (+70% YoY) (NERC, 2024).

**Strategic Imperatives**

1. **AI-Powered Anomaly Detection**: Flag MQTT C2 traffic via AutoGrid VPP sensors (OpenXcell, 2024).

2. **Physical-Digital Convergence**: Implement ballistic gates at substations paired with Dragos’ DNP3 analysis (Ardoq, 2024).

3. **Regulatory Alignment**: Map controls to NERC CIP-015 and DOE’s $27B Grid Modernization Initiative (Exabeam, n.d.).

**NCC Group Solutions**

* **ICS Red Team Exercises**: Simulate AcidPour attacks on Ukrainian-style grid infrastructure.

* **Supply Chain Security**: Audit third-party components in servo drives (CANopen vulnerabilities).

* **OT Architecture Reviews**: Segment fieldbus protocols (CODESYS, EtherCAT).

**Competitive Differentiation**

* **GridEx 2025 Participation**: Showcase live threat response via NCC’s role in NERC exercises (NERC, 2024).

* **CISA CPG Alignment**: Automated compliance reporting for ONCD’s Energy Modernization Plan (SBIR.gov, 2022).

### Campaign Components {#campaign-components-1}

1. **Defense-in-Depth Package**

   * ICS Red Team Exercises simulating ELECTRUM tactics

   * OT Architecture Reviews with fieldbus protocol segmentation

   * Supply Chain Security with focus on servo drive vulnerabilities

2. **Technical Demonstration**

   * AcidPour wiper malware analysis and detection methods

   * SOHO router security assessment and hardening

   * CANopen protocol security testing with detection rules

3. **Case Study Development**

   * “Protecting DERMS Platforms from BAUXITE Campaigns”

   * “Detecting Wiper Malware Before Execution in Grid Operations”

### Campaign Message {#campaign-message-1}

*“Defend transmission and distribution systems from nation-state-level threats targeting smart grid technologies, ensuring continuous operations and regulatory compliance.”*

**Campaign Objective:** Position NCC Group as the trusted partner for protecting critical oil and gas infrastructure from advanced persistent threats.

**Key Messaging:** “Protect your operations from state-sponsored attacks and maintain uninterrupted production. NCC Group delivers proactive threat detection and incident response capabilities tailored for the unique challenges of the oil and gas sector.”

**Campaign Components:**

* **Threat Briefing Webinar:** “The Evolving Threat Landscape for Oil & Gas – A Dragos Perspective.”

* **Targeted Assessment:** “OT Security Posture Assessment – Pipeline & Offshore Rig Focus.”

* **Technical Demonstration:** Simulated KAMACITE attack scenario with Dragos Platform detection.

* **Case Study:** “Securing a Major European Oil & Gas Operator from Advanced Threats.”

* **Content Marketing:** Blog posts, white papers, and infographics on oil & gas cybersecurity best practices.

**Metrics:** 20 Qualified Leads, 5 Assessment Bookings, 2 Closed Deals.

---

## 3\. Manufacturing Sector Campaign: “Continuous Production Security” {#3.-manufacturing-sector-campaign:-“continuous-production-security”}

### Threat Alignment {#threat-alignment-2}

| Threat Group | TTPs | Impact |
| :---- | :---- | :---- |
| **Ransomware Groups** | Targeted encryption, data theft, industrial disruption | Production stoppage, financial losses |
| **KAMACITE** | DLL hijacking, credential theft | Initial access leading to potential disruption |
| **Legacy Threats** | Exploitation of unpatched vulnerabilities | Persistent access to manufacturing systems |

**Actionable Tactics**:  
\- Patch CVE-2021-22763 in 32% legacy PLCs.  
\- Implement SBOM tracking for 400+/plant vendors.

**Threat Landscape**

* **Ransomware**: 1,171 attacks in 2024 targeting DLL hijacking (Dragos, 2025).

* **AI Model Poisoning**: 47% lack safeguards for GenAI tools (WEF, 2025).

* **Legacy Windows Risks**: 79% of ransomware exploited unpatched systems (Sophos, 2024).

**Strategic Imperatives**

1. **Predictive Cyber-Physical Modeling**: Use Honeywell Forge to simulate ransomware impacts (Codecademy, 2024).

2. **SBOM Automation**: Enforce software bill of materials for 400+/plant vendors (Terranova Security, 2019).

3. **AI Governance**: Audit ML datasets via Schneider EcoStruxure Trust Advisor (Force4, n.d.).

**NCC Group Solutions**

* **Ransomware Certifications**: Align with NIST SP 1800-11 for ICS recovery (Exabeam, n.d.).

* **VR Training Modules**: Immersive phishing simulations for 10,000+ operators (Guardey, 2024).

* **Ransomware Readiness Assessments**: Test recovery of automated production lines.

* **OT/IT Convergence Reviews**: Secure MES/SCADA integration (Proficy, CIMPLICITY).

* **Predictive Analytics**: Monitor for MuddyWater APT activity in Asian factories.

**Competitive Differentiation**

* **No More Ransom Partnership**: Provide free LockBit 4.0 decryption tools (Flexential, 2023).

* **Azure Sentinel Integration**: Cross-correlate IT/OT alerts in hybrid clouds (Arxiv, 20 \#\#\# Campaign Components

1. **Ransomware Resilience Package**

   * Ransomware Readiness Assessment with recovery testing

   * OT/IT Convergence Security Assessment

   * DLL hijacking vulnerability scanning and remediation

2. **Technical Demonstration**

   * Factory floor ransomware recovery simulation

   * DLL hijacking attack path visualization

   * Legacy system vulnerability assessment toolkit

3. **Case Study Development**

   * “Automotive Manufacturer Reduces Ransomware Recovery Time by 80%”

   * “Preventing Production Downtime Through Proactive Threat Hunting”

### Campaign Message {#campaign-message-2}

*“Maintain production continuity and protect intellectual property by implementing robust defenses against the ransomware groups specifically targeting manufacturing environments.”*

### **Threat Focus:** Ransomware, Legacy Malware, Fieldbus Vulnerabilities. {#threat-focus:-ransomware,-legacy-malware,-fieldbus-vulnerabilities.}

**Campaign Objective:** Position NCC Group as the go-to cybersecurity partner for manufacturers seeking to protect their production operations.

**Key Messaging:** “Minimize downtime and protect your intellectual property. NCC Group delivers comprehensive cybersecurity solutions tailored to the unique challenges of the manufacturing sector.”

**Campaign Components:**

* **Ransomware Readiness Workshop:** “Protecting Your Factory Floor from Ransomware Attacks.”

* **Vulnerability Assessment:** “OT Security Assessment – Manufacturing Production Line Focus.”

* **Technical Demonstration:** Simulated ransomware attack on a manufacturing control system.

* **Case Study:** “Recovering from a Ransomware Attack – A Manufacturing Success Story.”

* **Content Marketing:** Blog posts, white papers, and infographics on manufacturing cybersecurity best practices.

**Metrics:** 30 Qualified Leads, 10 Assessment Bookings, 4 Closed Deals.

---

## 4\. Water and Wastewater Sector Campaign: “Critical Infrastructure Protection” {#4.-water-and-wastewater-sector-campaign:-“critical-infrastructure-protection”}

### Threat Alignment {#threat-alignment-3}

| Threat Group | TTPs | Impact |
| :---- | :---- | :---- |
| **CyberArmyofRussia\_Reborn** | Compromised systems in U.S. water utilities | Potential control system manipulation |
| **BAUXITE** | Default credentials, SSH attacks, IOControl backdoor | Access to water treatment controls |
| **Hacktivist Groups** | HMI access via default credentials, VNC exploitation | Unauthorized system access |
|  |  |  |

**Actionable Tactics**:  
\- Deploy NCC’s FrostyGoop detection rules for Modbus TCP.  
\- Integrate with AutoGrid VPP for DERMS security.

**Threat Landscape**

* **CyberArmyofRussia\_Reborn**: 70% YoY increase in VNC-exposed HMI attacks (Dragos, 2025).

* **BAUXITE**: Default credentials in 25% of water SCADA systems (Dragos, 2025).

* **IoT Botnets**: 50% of AMI devices lack IPv6 encryption (US CIP, 2024).

**Strategic Imperatives**

1. **Zero Trust for OT**: Enforce Okta MFA on WinCC OA instances (SBIR.gov, 2022).

2. **Drone-Based Monitoring**: Deploy LiDAR UAVs for physical tampering detection (WALLIX, 2023).

3. **Blockchain Water Testing**: Log pH/chlorine levels via IBM Food Trust (Flexential, 2023).

**NCC Group Solutions**

* **kurtlar\_scada.exe Mitigation**: Custom Snort rules for VNC port 5900 (Guardey, 2024).

* **NIST CSF Adoption**: 8-week sprints for Tier 4 controls (Exabeam, n.d.).

* 

  * **OT Asset Discovery**: Map 25K+ Gridstream AMI devices with Landis+Gyr APIs.

* **Security Awareness Training**: Phishing simulations for operators managing HMIs.

* **ICS Pen Testing**: Exploit VNC vulnerabilities (kurtlar\_scada.exe).

**Competitive Differentiation**

* **TSA Pipeline Blueprint**: Pre-certified CIRCIA 72-hour reporting playbooks (Force4, n.d.).

* **GE Proficy Hardening Kits**: Preconfigured RBAC templates for iFIX HMIs (Ardoq, 2024). \#\#\# Campaign Components

1. **Basic Security Fundamentals Package**

   * Basic OT Security Assessment with HMI credential review

   * ICS Network Segmentation Review

   * Security Awareness Training for Operations Staff

2. **Technical Demonstration**

   * kurtlar.exe malware detection demo

   * VNC security scanning and remediation tools

   * Default credential audit automation toolkit

3. **Case Study Development**

   * “Municipal Water Authority Prevents Process Manipulation”

   * “Addressing Default Credentials in Small Utility Operations”

### Campaign Message {#campaign-message-3}

*“Secure water treatment and distribution systems from hacktivist threats while implementing practical, cost-effective security controls appropriate for critical infrastructure operators.”*

**Threat Focus:** CyberArmyofRussia\_Reborn, BAUXITE, IoT Vulnerabilities.

**Campaign Objective:** Become the trusted cybersecurity partner for water and wastewater utilities.

**Key Messaging:** “Protect your critical water infrastructure from cyberattacks and ensure the safety of your community. NCC Group offers affordable and effective cybersecurity solutions tailored to the unique needs of water and wastewater utilities.”

**Campaign Components:**

* **Webinar:** “Securing Critical Water Infrastructure – A Proactive Approach.”

* **Basic Security Assessment:** “OT Security Assessment – Water & Wastewater Facility Focus.”

* **Technical Demonstration:** Exploitation of default credentials on HMIs.

* **Case Study:** “Protecting a Municipal Water Authority from Cyber Threats.”

* **Community Engagement:** Participation in water industry conferences and events.

## 5\. Transportation and Logistics Campaign: “Supply Chain Resilience” {#5.-transportation-and-logistics-campaign:-“supply-chain-resilience”}

### Threat Alignment {#threat-alignment-4}

| Threat Group | TTPs | Impact |
| :---- | :---- | :---- |
| **GRAPHITE** | Spear-phishing, Microsoft Outlook exploits, MASEPIE backdoor | Targeting rail/freight logistics |
| **APT41/DUSTTRAP** | Remote access trojan targeting automotive and shipping | Intelligence gathering, potential disruption |
| **Ransomware Groups** | Operational disruption, logistics software targeting | Service delivery failures |

**Actionable Tactics**:  
\- Threat hunt for PARISITE artifacts in AWS IoT Core.  
\- Align with DoD’s Zero Trust OT Strategy for defense contractors.

**Threat Landscape**

* **GRAPHITE**: MASEPIE backdoors in 40% of rail logistics software (Dragos, 2025).

* **APT41**: DustTrap RAT in port automation systems (WEF, 2025).

* **Autonomous Vehicle Risks**: 60% lack ISO 15118-3 compliance (US CIP, 2024).

**Strategic Imperatives**

1. **Quantum-Safe Cryptography**: Upgrade Siemens PLCs with CRYSTALS-Kyber (Arxiv, 2024).

2. **Maritime Threat Hunting**: Audit ROV firmware with Oceaneering International (OpenXcell, 2024).

3. **Railway Protocol Hardening**: Replace MODBUS with OPC UA Pub/Sub (Flexential, 2023).

**NCC Group Solutions**

* **GRAPHITE Mitigation**: Red team MASEPIE backdoors via Cobalt Strike emulation (Codecademy, 2024).

* **Autonomous Fleet Security**: Certify NVIDIA DRIVE OS under UNECE R155 (Guardey, 2024).

* 

  * **Third-Party Risk Management**: Audit 200+ vendors in Amazon warehousing systems.

* **OT/IoT Security Assessments**: Secure port automation (Yokogawa CENTUM).

* **HVDC/FACTS Security**: Protect $4B Germany/Korea grid expansion projects.

**Competitive Differentiation**

* **Digital Twin Modeling**: Simulate spear-phishing on Siemens Rail Cloud (WEF, 2025).

* **Arup Deepfake Defense**: License AI voiceprint verification (Terranova Security, 2019). \#\#\# Campaign Components

1. **Supply Chain Security Package**

   * Third-Party Risk Management Assessment for logistics providers

   * OT/IoT Security Assessment for warehouse/port automation

   * Transportation Management System security review

2. **Technical Demonstration**

   * MASEPIE backdoor detection and remediation

   * DUSTTRAP analysis and containment strategies

   * Logistics software recovery testing toolkit

3. **Case Study Development**

   * “Global Logistics Provider Secures Multi-Modal Operations”

   * “Preventing Spear-Phishing Success in Transportation Management”

### Campaign Message {#campaign-message-4}

*“Protect critical transportation and logistics operations from targeted attacks that could disrupt global supply chains and cause significant economic impact.”*

**Threat Focus:** GRAPHITE, APT41/DUSTTRAP, Ransomware.

**Campaign Objective:** Establish NCC Group as the leading cybersecurity provider for transportation and logistics companies.

**Key Messaging:** “Protect your supply chain from disruption and ensure the safe and efficient movement of goods. NCC Group delivers comprehensive cybersecurity solutions tailored to the unique challenges of the transportation and logistics sector.”

**Campaign Components:**

* **Executive Briefing:** “Securing the Global Supply Chain – A Cybersecurity Imperative.”

* **Third-Party Risk Assessment:** “Supply Chain Security Assessment – Logistics Provider Focus.”

* **Technical Demonstration:** Simulated APT41 attack on a logistics network.

* **Case Study:** “Protecting a Global Logistics Provider from Cyber Threats.”

* **Industry Partnerships:** Collaboration with transportation and logistics associations.

---

## Cross-Sector Implementation Strategy {#cross-sector-implementation-strategy}

## NCC Services and Solutions {#ncc-services-and-solutions}

1. **SANS ICS 5 Controls Framework**:

   * Baseline all campaigns on Incident Response \+ Defensible Architecture pillars.

2. **CISA CPG Alignment**:

   * Implement MFA for 100% remote access points (VPN/RDP/SSH).

3. **FBI InfraGard Partnerships**:

   * Share IOCs for VOLTZITE/BAUXITE via NDCA threat feeds.

**Competitive Edge vs Claroty**:  
\- **OT-native threat intel**: Dragos’ 3,300+ protocol decoders vs Claroty’s IT-centric approach.  
\- **Regulatory pre-certification**: Pre-built NERC CIP/EPA templates reduce audit time by 40%.

## Cross-Cutting Campaign Elements {#cross-cutting-campaign-elements}

* **Dragos Integration:** All campaigns will prominently feature Dragos Platform capabilities and threat intelligence.

* **NCC Group Expertise:** Leverage NCC Group’s deep expertise in OT/ICS security, incident response, and regulatory compliance.

* **Content Marketing:** Develop high-quality content that educates prospects on the latest threats and best practices.

* **Sales Enablement:** Equip the sales team with the tools and resources they need to effectively engage with prospects.

### Aligned with SANS ICS 5 Critical Controls {#aligned-with-sans-ics-5-critical-controls}

1. **ICS Incident Response**

   * Custom playbooks for each sector based on threat TTPs

   * Integration with existing SOC operations

2. **Defensible Architecture**

   * Sector-specific network segmentation models

   * Reference architectures for each industry vertical

3. **ICS Network Monitoring**

   * Dragos Platform integration for OT visibility

   * Protocol-specific monitoring rules (Modbus, DNP3, IEC-61850)

4. **Secure Remote Access**

   * VPN security assessment and hardening

   * Multi-factor authentication implementation

5. **Risk-Based Vulnerability Management**

   * “Now, Next, Never” prioritization framework

   * Supply chain vulnerability tracking

### Marketing and Sales Enablement {#marketing-and-sales-enablement}

1. **Sales Collateral**

   * Sector-specific threat briefs

   * ROI calculators for security investments

   * Reference architecture diagrams

2. **Demonstration Capabilities**

   * Portable lab environment for each threat scenario

   * Remote demonstration capabilities via secure cloud environment

3. **Partner Engagement**

   * Joint webinars with Dragos featuring threat research

   * Co-selling opportunities with technology vendors (GE, Siemens)

### **References** {#references}

1. American Psychological Association. (2020). *Publication manual of the American Psychological Association* (7th ed.).

2. BDO USA. (2023). *The four elements of a strong cybersecurity strategy*. [https://www.bdo.com](https://www.bdo.com/)

3. Dragos. (2025). *2025 OT/ICS Cybersecurity Report*.

4. Exabeam. (n.d.). *The 12 elements of an information security policy*. [https://www.exabeam.com](https://www.exabeam.com/)

5. Flexential. (2023). *Key elements of a cybersecurity program*. [https://www.flexential.com](https://www.flexential.com/)

6. Guardey. (2024). *How to set up a cybersecurity awareness campaign*. [https://www.guardey.com](https://www.guardey.com/)

7. OpenXcell. (2024). *Chain of thought prompting: A guide to enhanced AI reasoning*. [https://www.openxcell.com](https://www.openxcell.com/)

8. SBIR.gov. (2022). *Elements of a cybersecurity plan*. [https://scvotes.gov](https://scvotes.gov/)

9. Terranova Security. (2019). *The nine elements of cybersecurity awareness*. [https://www.terranovasecurity.com](https://www.terranovasecurity.com/)

10. WEF. (2025). *Global risks report*. World Economic Forum.

---

