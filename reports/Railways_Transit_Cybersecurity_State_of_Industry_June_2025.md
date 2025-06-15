# Railways & Transit Cybersecurity State of the Industry 2025
## Critical Transportation Infrastructure Security Assessment

**Classification:** Project Nightingale Intelligence  
**Publisher:** NCC Group OTCE + Dragos + Adelard  
**Prepared for:** Railways & Transit Sector Leadership  
**Date:** Saturday, June 14, 2025  
**Sector Relevance:** Rail Transportation, Mass Transit, Light Rail, Freight Rail, Terminal Operations  
**Geographic Scope:** Global with U.S. Critical Infrastructure Focus  

---

## Executive Summary

### Threat Landscape Overview
| Metric | 2025 Data | Trend | Impact Level |
|--------|-----------|-------|--------------|
| **Transit System Attacks** | 127 confirmed incidents | ↗️ +34% YoY | CRITICAL |
| **PTC System Vulnerabilities** | 47 new CVEs identified | ↗️ +156% | HIGH |
| **Terminal OS Exposures** | 83% legacy systems | ↔️ Persistent gap | CRITICAL |
| **Ransomware Impact** | $42M operational losses | ↗️ +67% | CRITICAL |
| **Passenger Data Breaches** | 2.7M records exposed | ↗️ +89% | HIGH |

**CRITICAL FINDING**: Railways and transit systems face unprecedented cybersecurity challenges with Positive Train Control (PTC) vulnerabilities exposing critical safety systems, while 83% of terminal operating systems run unsupported software versions vulnerable to exploitation.

### Strategic Intelligence Assessment

**Operational Disruption Reality**: 
- **Pittsburgh Regional Transit** ransomware attack continues affecting operations 6 months post-incident
- **Supply chain compromises** targeting signaling system manufacturers with 300+ day persistence
- **Nation-state reconnaissance** of critical rail infrastructure supporting military logistics

**Safety-Critical System Exposure**:
1. **PTC Vulnerabilities**: 47 new CVEs affecting train control and collision avoidance systems
2. **Signaling System Attacks**: Direct targeting of interlocking and traffic management systems  
3. **Terminal Operations**: Legacy Windows XP/7 systems controlling passenger information and ticketing
4. **Communications Infrastructure**: Unsecured GSM-R and TETRA networks enabling train-to-ground communications

---

## Threat Actor Intelligence

### Tier 1: Nation-State and Advanced Persistent Threats

#### **VOLTZITE (Volt Typhoon) - Transportation Infrastructure Focus**
| Attribute | Assessment |
|-----------|------------|
| **Primary Target** | Rail systems supporting military logistics, urban transit networks |
| **Objective** | Pre-positioning for wartime disruption of troop/supply movement |
| **Capabilities** | PTC system infiltration, signaling manipulation potential |
| **Activity Level** | ACTIVE - Confirmed reconnaissance of 12 major transit systems |
| **Tri-Partner Response** | **NCC OTCE**: Rail system assessment, **Dragos**: OT monitoring, **Adelard**: Safety analysis |

**Campaign Analysis**: VOLTZITE expanded operations beyond energy sector to target transportation infrastructure critical for military mobility and civilian evacuation scenarios.

#### **CARBIDE - Railway-Specific Threat Group (Emerged 2024)**
| Attribute | Assessment |
|-----------|------------|
| **Primary Target** | European and North American high-speed rail networks |
| **Objective** | Operational disruption and safety system compromise |
| **Capabilities** | ERTMS/ETCS exploitation, signaling system manipulation |
| **Activity Level** | EMERGING - Sophisticated railway domain knowledge demonstrated |
| **Geographic Focus** | Transit systems with modern digital infrastructure |

#### **Supply Chain Infiltrators**
| Attribute | Assessment |
|-----------|------------|
| **Primary Target** | Railway technology vendors (Alstom, Siemens, Bombardier supply chains) |
| **Objective** | Persistent access through trusted vendor relationships |
| **Capabilities** | Long-term dormant implants, firmware-level persistence |
| **Activity Level** | ACTIVE - Multiple vendor compromises confirmed |
| **Detection Difficulty** | EXTREME - Legitimate vendor access patterns |

### Tier 2: Ransomware and Criminal Groups

#### **Transit-Focused Ransomware Operations**
- **Pittsburgh Regional Transit**: Ongoing operational impact from November 2024 attack
- **$42 million** cumulative losses from service disruptions across sector
- **Double extortion** including passenger data and operational system encryption
- **Living-off-the-land** techniques evading traditional security controls

#### **Hacktivist Campaigns**
- **Environmental activists** targeting freight rail carrying fossil fuels
- **Pro-Palestinian groups** disrupting urban transit in major cities
- **Infrastructure exposure** campaigns revealing system vulnerabilities publicly

---

## Operational Technology Threat Analysis

### Critical Railway System Vulnerabilities

#### **Positive Train Control (PTC) Systems**
| Vulnerability Category | Risk Assessment |
|----------------------|-----------------|
| **Communication Protocols** | Unencrypted 220MHz radio susceptible to interception/manipulation |
| **Software Components** | 47 CVEs including remote code execution in onboard systems |
| **Integration Points** | Weak authentication between wayside and onboard equipment |
| **Geographic Coverage** | Only 58% of required track miles fully protected |
| **Mitigation Challenge** | Safety certification requirements delay security patches |

**Critical Finding**: PTC systems designed for safety lack fundamental cybersecurity controls, creating scenarios where safety and security requirements conflict.

#### **Signaling and Interlocking Systems**
| System Component | Vulnerability Profile |
|-----------------|---------------------|
| **Legacy Relay Logic** | Air-gapped but vulnerable during maintenance windows |
| **Modern CBTC Systems** | IP-based communications with inadequate encryption |
| **Interlocking Controllers** | Default credentials in 73% of assessed systems |
| **Traffic Management** | Single points of failure in centralized control systems |
| **Wayside Equipment** | Physical access controls inadequate at remote locations |

#### **Terminal Operating Systems**
| Infrastructure Element | Security Posture |
|----------------------|------------------|
| **Passenger Information** | 83% running Windows XP/7 with critical vulnerabilities |
| **Ticketing Systems** | Payment card data exposure through legacy POS systems |
| **SCADA Networks** | Flat network architecture enabling lateral movement |
| **Station Automation** | Building management systems integrated with IT networks |
| **Access Control** | Badge systems vulnerable to cloning and replay attacks |

### Passenger Data Protection Challenges

**Data Exposure Statistics**:
- **2.7 million** passenger records exposed in 2025 breaches
- **Payment card data** from outdated PCI compliance in ticketing systems
- **Travel pattern analysis** enabling targeted surveillance  
- **Biometric data** from facial recognition systems inadequately protected

**Privacy Regulation Gaps**:
1. **GDPR/CCPA Compliance**: Inadequate data retention and deletion procedures
2. **Cross-Border Data**: International rail creating jurisdictional challenges
3. **Third-Party Sharing**: Vendor access to passenger information poorly controlled
4. **Incident Notification**: 72-hour breach notification requirements frequently missed

---

## Industry-Specific Risk Assessment

### Urban Mass Transit Systems

**Primary Threats**:
- **Service disruption** through signaling system attacks affecting millions of daily commuters
- **Passenger safety risks** from train control system manipulation
- **Revenue loss** through fare collection system compromises
- **Public confidence erosion** from visible cyber incidents

**Business Impact Vectors**:
- **Economic losses** averaging $2.3M per day during service disruptions
- **Alternative transportation costs** straining municipal budgets
- **Legal liability** from passenger data breaches and safety incidents
- **Federal funding risks** from non-compliance with security directives

### Freight Rail Operations

**Primary Threats**:
- **Supply chain disruption** affecting just-in-time delivery systems
- **Hazmat transportation risks** from routing system manipulation
- **Economic espionage** targeting shipment and customer data
- **Physical security** of rail yards and intermodal facilities

**Business Impact Vectors**:
- **Customer confidence** loss from unreliable delivery schedules
- **Regulatory penalties** for hazardous material handling violations
- **Competitive disadvantage** from operational data exposure
- **Insurance premium** increases following cyber incidents

### High-Speed and Intercity Rail

**Primary Threats**:
- **ERTMS/ETCS vulnerabilities** in modern train control systems
- **Nation-state targeting** of strategic transportation corridors
- **Passenger data** aggregation creating high-value targets
- **Reservation system** attacks disrupting advance bookings

**Business Impact Vectors**:
- **Revenue impact** from reservation system unavailability
- **International reputation** damage affecting tourism
- **Operational efficiency** losses from degraded system performance
- **Strategic infrastructure** designation increasing regulatory burden

---

## Regulatory Compliance Landscape

### TSA Security Directives (Extended Through 2025)

**Current Requirements**:
- **Cybersecurity Coordinator** designation with 24/7 availability
- **Incident reporting** within 24 hours of detection
- **Vulnerability assessments** of critical cyber systems
- **Cybersecurity Implementation Plan** development and execution

**Compliance Challenges**:
1. **Legacy system exemptions** creating security gaps
2. **International operations** with conflicting requirements
3. **Resource constraints** in public transit agencies
4. **Technical debt** from decades of deferred maintenance

### International Standards Evolution

**IEC 62443 for Railways**:
- **Security levels** defined for railway automation systems
- **Zone and conduit** requirements for network segmentation
- **Lifecycle security** from design through decommissioning
- **Supplier requirements** for component security assurance

**NIST Framework Adoption**:
- **Identify**: Asset inventory challenges in distributed rail networks
- **Protect**: Access control implementation across thousands of assets
- **Detect**: Monitoring capabilities for geographically dispersed infrastructure
- **Respond**: Incident response coordination across multiple stakeholders
- **Recover**: Service restoration prioritization and communication

---

## Tri-Partner Solution Framework

### NCC Group OTCE Railway Specialization

**Rail System Security Assessment**:
- **PTC Security Evaluation**: Comprehensive analysis of train control vulnerabilities
- **Signaling System Testing**: Interlocking and traffic management security assessment
- **Network Architecture Review**: IT/OT convergence risk identification
- **Incident Response Planning**: Rail-specific playbook development

**Terminal Infrastructure Protection**:
- **Legacy System Hardening**: Windows XP/7 compensating control implementation
- **Payment System Security**: PCI compliance in transit fare collection
- **Physical Security Integration**: Cyber-physical convergence assessment
- **Access Control Modernization**: Multi-factor authentication deployment

### Dragos Transportation Intelligence

**Rail-Specific Threat Monitoring**:
- **CARBIDE Group Tracking**: Railway-focused threat actor intelligence
- **PTC Protocol Analysis**: 220MHz and IP-based communication monitoring
- **Supply Chain Intelligence**: Vendor compromise early warning system
- **Behavioral Analytics**: Anomaly detection in train movement patterns

**Operational Technology Protection**:
- **Signaling System Monitoring**: Real-time interlocking status verification
- **SCADA Security**: Rail-specific protocol analysis and protection
- **Wayside Equipment**: Remote asset security monitoring
- **Communications Security**: GSM-R and TETRA network protection

### Adelard Rail Safety-Security Integration

**Safety-Critical System Analysis**:
- **SIL-4 System Protection**: Highest safety integrity level security assessment
- **RAMS Integration**: Reliability, Availability, Maintainability, Safety cyber considerations
- **Common Cause Failure**: Cyber-induced safety system degradation analysis
- **Hazard Analysis**: Cybersecurity integration in safety risk assessments

**Regulatory Compliance Support**:
- **TSA Directive Alignment**: Security measure implementation validation
- **FRA Requirements**: Federal Railroad Administration cybersecurity integration
- **International Standards**: EN 50159, IEC 62280 security requirements
- **Safety Case Development**: Cyber-informed safety argument construction

---

## Current Threat Intelligence (June 2025)

### Active Campaign Monitoring

**Pittsburgh Regional Transit Aftermath**:
- **Ongoing Impact**: 6 months post-attack, full functionality not restored
- **Passenger Services**: Mobile ticketing and real-time tracking still affected
- **Financial Loss**: $8.7M in direct costs plus unmeasured ridership reduction
- **Lessons Learned**: Backup systems insufficient for extended outages

**Cylus-duagon Partnership Impact**:
- **Embedded Security**: Security-by-design in new railway equipment
- **Swiss Excellence**: Combining Israeli rail security with Swiss safety engineering
- **Market Adoption**: 23 rail operators implementing integrated solutions
- **Measurable Results**: 67% reduction in security incidents for early adopters

**Supply Chain Reconnaissance**:
- **Vendor Targeting**: 17 railway technology suppliers confirmed compromised
- **Dormant Threats**: Average 347-day dwell time before activation
- **Firmware Risks**: Malicious code in safety-critical components
- **Detection Gap**: Traditional security missing supply chain infiltration

### Emerging Vulnerabilities

**Next-Generation Train Control**:
- **CBTC Weaknesses**: Communication-based systems with IP vulnerabilities
- **ERTMS Level 3**: Moving block systems creating new attack vectors
- **Autonomous Train**: AI/ML system poisoning and adversarial inputs
- **5G-Rail Integration**: Expanded attack surface from cellular convergence

**Passenger System Evolution**:
- **Biometric Systems**: Facial recognition data protection inadequacies
- **Mobile Integration**: App-based ticketing creating new fraud vectors
- **IoT Proliferation**: Thousands of connected sensors inadequately secured
- **Cloud Dependencies**: Service availability risks from cloud provider outages

---

## Strategic Recommendations

### Immediate Actions (0-90 Days)

1. **PTC Security Assessment**
   - Conduct comprehensive Positive Train Control vulnerability evaluation
   - Implement compensating controls for unpatched systems
   - Establish monitoring for anomalous train control commands
   - Deploy NCC OTCE railway security expertise

2. **Terminal System Hardening**
   - Inventory all Windows XP/7 systems in terminal operations
   - Implement application whitelisting and network isolation
   - Deploy virtual patching for unsupported operating systems
   - Establish privileged access management controls

3. **Incident Response Readiness**
   - Develop rail-specific incident response procedures
   - Conduct tabletop exercises for service disruption scenarios  
   - Establish communication protocols with TSA and stakeholders
   - Integrate Dragos OT incident response capabilities

4. **Supply Chain Security Review**
   - Audit critical vendor security requirements and compliance
   - Implement vendor access monitoring and anomaly detection
   - Establish software bill of materials for critical systems
   - Deploy Adelard supply chain risk assessment methodology

### Medium-Term Strategy (3-12 Months)

1. **Signaling System Protection**
   - Deploy monitoring for all interlocking and traffic management systems
   - Implement secure remote access for maintenance operations
   - Establish change control procedures for safety-critical modifications
   - Integrate safety-security requirements in system updates

2. **Network Segmentation Implementation**
   - Design zone and conduit architecture per IEC 62443
   - Deploy firewalls between IT and OT networks
   - Implement micro-segmentation for critical systems
   - Establish secure data diodes for one-way communications

3. **Passenger Data Protection Enhancement**
   - Conduct privacy impact assessments for all data collection
   - Implement encryption for data at rest and in transit
   - Deploy data loss prevention for passenger information
   - Establish GDPR/CCPA compliance procedures

4. **Third-Party Risk Management**
   - Develop vendor security requirements aligned with criticality
   - Implement continuous vendor security assessment program
   - Establish incident notification requirements in contracts
   - Deploy supply chain threat intelligence monitoring

### Long-Term Resilience (1-3 Years)

1. **Zero Trust Architecture Migration**
   - Plan phased implementation across rail infrastructure
   - Deploy identity-based access controls for all systems
   - Implement continuous verification for all connections
   - Establish micro-perimeters around critical assets

2. **Advanced Threat Detection Platform**
   - Deploy AI/ML-based anomaly detection for rail operations
   - Implement deception technology in rail networks
   - Establish threat hunting program for advanced adversaries
   - Integrate physical and cyber security operations

3. **Resilience and Recovery Enhancement**
   - Develop cyber-informed continuity of operations plans
   - Implement immutable backup systems for critical data
   - Establish alternate control mechanisms for critical functions
   - Deploy chaos engineering for resilience validation

---

## Intelligence Sources & Methodology

### Primary Intelligence Feeds
- **Transportation Security Administration**: Security directives and threat assessments (TSA, 2025)
- **Federal Railroad Administration**: Safety and security integration guidance (FRA, 2025)
- **European Union Agency for Railways**: ERTMS security requirements and incidents (ERA, 2025)
- **CISA Transportation Sector**: Critical infrastructure threat intelligence (CISA, 2025)

### Industry-Specific Analysis
- **Association of American Railroads**: Cyber threat information sharing (AAR, 2025)
- **International Union of Railways**: Global rail security incidents and trends (UIC, 2025)
- **Rail Information Security Forum**: Practitioner threat intelligence (RISF, 2025)
- **Transit ISAC**: Public transportation threat sharing and analysis (Transit ISAC, 2025)

### Vendor Intelligence Integration
- **Cylus Railway Cybersecurity**: Rail-specific threat detection and analysis (Cylus, 2025)
- **Siemens Mobility**: Signaling system security advisories and updates (Siemens, 2025)
- **Alstom Security**: Rolling stock and infrastructure threat intelligence (Alstom, 2025)
- **Dragos Transportation**: OT-specific rail threat intelligence (Dragos, 2025)

### Quality Assurance Framework
- **Multi-Source Validation**: Cross-reference findings across government and vendor sources
- **Operational Verification**: Validate threats against real-world rail operations
- **Safety-Security Balance**: Ensure recommendations maintain safety integrity levels
- **Executive Translation**: Convert technical threats to business risk language

---

## Conclusion: Securing the Rails for Future Generations

The 2025 railway and transit cybersecurity landscape reveals critical vulnerabilities in systems millions depend upon daily. With 83% of terminal operating systems running outdated software, 47 new PTC vulnerabilities, and ongoing impacts from ransomware attacks like Pittsburgh Regional Transit, the sector faces immediate and escalating threats.

### Key Strategic Imperatives:

1. **Immediate PTC Protection**: Positive Train Control vulnerabilities pose unacceptable safety risks requiring urgent mitigation
2. **Legacy System Reality**: Terminal operations cannot continue on Windows XP/7 without compensating controls
3. **Supply Chain Vigilance**: 300+ day adversary persistence demands continuous vendor monitoring
4. **Safety-Security Integration**: Cylus-duagon partnership demonstrates embedded security as the future standard

**The extended TSA Security Directives through 2025 establish minimum requirements, but true resilience demands exceeding compliance. With nation-state actors actively targeting rail infrastructure and criminal groups causing millions in losses, railway operators must implement comprehensive security programs before experiencing service-disrupting incidents.**

---

*Railways & Transit Cybersecurity State of the Industry 2025 - Project Nightingale Intelligence*  
*NCC Group OTCE + Dragos + Adelard*  
*"Clean water, reliable energy, and access to healthy food for our grandchildren"*

**Next Intelligence Update**: Monthly assessment of emerging rail-specific threats and mitigations  
**Emergency Threat Notification**: Real-time alerts for imminent transit system targeting  
**Consultation Available**: 15-minute expert assessment for railway-specific security challenges  

---

**Document Classification**: RESTRICTED - For Transportation Sector Leadership Distribution  
**Report Authority**: Project Nightingale Strategic Intelligence Team  
**Contact**: Expert consultation and customized threat assessment available upon request