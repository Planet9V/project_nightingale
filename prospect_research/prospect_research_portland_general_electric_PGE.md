# Comprehensive Go-to-Market Analysis: NCC Group Targeting Portland General Electric Co (PGE)

## Executive Summary

Portland General Electric Company (NYSE: POR) represents a prime opportunity for NCC Group's cybersecurity and OT security services. As Oregon's largest utility serving 950,000 customers with 3,300+ MW of generation capacity, PGE operates extensive operational technology infrastructure requiring NERC CIP compliance while facing sophisticated nation-state threats. With $3.44B in 2024 revenue, aggressive decarbonization goals, and significant OT/IT convergence initiatives, PGE presents multiple entry points for NCC-Dragos capabilities across industrial cybersecurity, compliance, and incident response services.

---

# PART 1: ORGANIZATION PROFILE & LEADERSHIP

## Corporate Overview

**Legal Entity**: Portland General Electric Company  
**Founded**: 1889 (as Willamette Falls Electric Company)  
**Headquarters**: Portland, Oregon  
**Stock Symbol**: NYSE: POR  
**Market Capitalization**: $4.57 billion  
**Industry Classification**: Electric Services Utility (NAICS: Electric Power Generation, Transmission and Distribution)

### Financial Performance (3-Year Trend)
- **2024**: Revenue $3.44B (+18% YoY), Net Income $313M, EPS $3.01
- **2023**: Revenue $2.92B (+10.4% YoY), Net Income $228M, EPS $2.33  
- **2022**: Revenue $2.65B, Net Income $233M, EPS $2.60
- **2025 Guidance**: EPS $3.13-$3.33 (adjusted), targeting 5-7% annual growth

### Operational Footprint
- **Customers**: 950,000 retail customers across 51 cities in 7 Oregon counties
- **Service Territory**: 4,000+ square miles serving 1.9 million Oregonians
- **Employees**: ~2,870 total workforce
- **Infrastructure**: 1,269 circuit miles transmission, 29,398 circuit miles distribution
- **Generation Capacity**: 3,300+ MW (45% non-carbon emitting)

### Corporate Structure
Currently operating as direct utility company, planning 2025 reorganization to holding company structure with PGE as wholly-owned subsidiary and separate transmission subsidiary (pending regulatory approval).

## Executive Leadership Team

### C-Suite Leadership
**Maria Pope** - President, CEO & Director (Since 2018)
- **Tenure**: At PGE since 2009 (previously CFO)
- **Education**: MBA Stanford Graduate School of Business, BA Georgetown University
- **Industry Leadership**: Chair of Edison Electric Institute (2024-2025)
- **Other Boards**: Chair of Columbia Banking System Inc.
- **Compensation**: $7.37M total (2024)

**Joe Trpik** - Senior VP Finance & CFO (Since 2023)
- **Expertise**: Financial planning, capital allocation, risk management
- **Focus**: Leading accounting, finance, tax, investor relations

**Debbie Powell** - Senior VP Operations (Since 2024)
- **Experience**: 30 years energy/military, former Pacific Gas & Electric executive
- **Responsibilities**: Utility operations, safety, T&D, generation, emergency management

### IT and Security Leadership

**Campbell Henderson** - VP Information Technology & CIO (Since 2005)
- **Education**: MBA University of Texas, CPA certification
- **Previous**: CIO at Stockamp Associates, Willamette Industries

**John Kochavatr** - VP Information Technology & CIO (Since 2018)
- **Previous**: Senior VP/CIO at SUEZ Water Technologies, multiple GE divisions
- **Focus**: Information systems, operational effectiveness through technology

**Keegan Reichert** - Director of Cybersecurity (Since 2018)
- **Note**: CISO role not publicly identified, possibly integrated with cybersecurity director

### Board of Directors
- **Jim Torgerson** - Chairman (former AVANGRID CEO)
- **Jack Davis** - Independent Director (former Arizona Public Service CEO)
- **John O'Leary** - Director (CEO Daimler Truck North America)
- **Marie Oh Huber** - Independent Director (former eBay Chief Legal Officer)
- Additional experienced directors from finance, technology, and energy sectors

### Decision-Making Structure
- **Technology Purchases**: CIO authority for operational IT within approved budgets
- **Major Investments**: Board approval required for significant capital projects
- **Security Investments**: Executive-level approval with board oversight via Audit & Risk Committee
- **Procurement**: Distributed model with IT under CIO, general under operations

## Strategic Context

### Recent Organizational Changes (2023-2024)
- New CFO Joe Trpik (2023) bringing financial transformation expertise
- New COO Debbie Powell (2024) with PG&E wildfire mitigation experience  
- John O'Leary joined board (2024) - transportation electrification expertise
- Planning holding company reorganization (2025)

### Market Position & Competition
- **Market Share**: Serves 47% of Oregon's population, largest utility in state
- **Direct Competitors**: Pacific Power (Berkshire Hathaway), Eugene Water & Electric Board
- **Industry Recognition**: #1 Forrester Customer Experience Index (2024)
- **Renewable Leadership**: #1 U.S. voluntary renewable program (15 consecutive years)

### Corporate Culture & Priorities
- **Mission**: Leading the clean energy transformation
- **Decarbonization Goals**: 80% emissions reduction by 2030, 100% by 2040
- **DEI Recognition**: Bloomberg Gender-Equality Index (5 consecutive years)
- **Community Investment**: $5.5M donated in 2024, 23,000+ volunteer hours

---

# PART 2: TECHNICAL INFRASTRUCTURE & SECURITY POSTURE

## Technology Stack

### Cloud Infrastructure
- **Primary Provider**: Amazon Web Services (AWS) - completed migration 2019
- **Key Services**: DynamoDB, S3, SageMaker, EMR, Kinesis Data Streams
- **Architecture**: Hybrid cloud with modern data lake replacing legacy data warehouse
- **APIs**: 100+ microservices APIs deployed

### Enterprise Systems
- **ERP**: SAP S/4HANA (private/public cloud), SAP BTP, Build Process Automation
- **Analytics**: Snowflake data cloud platform
- **HR**: Workday
- **Customer Platforms**: My Account website, PGE mobile apps

### Operational Technology Environment

**SCADA/EMS Systems**:
- **Platform**: AVEVA System Platform with InTouch HMI
- **Integration**: Factory IQ as primary system integrator
- **Standards**: IEEE-61850-420-7 implementation
- **Capabilities**: Real-time monitoring, single-click dispatch, contingency analysis

**Generation Control**:
- **Distributed Generation**: GenOnSys controlling 32 generators at 21 sites (40 MW)
- **Virtual Power Plant**: Smart battery pilot (9.5 MWh capacity)
- **Renewables**: 311 MW Clearwater Wind, 162 MW Pachwaywit solar

**Smart Grid Infrastructure**:
- **AMI Deployment**: 825,000+ smart meters (near 100% coverage)
- **Test Bed**: 20,000+ customers across three neighborhoods
- **Battery Storage**: 475+ MW total capacity (Seaside, Troutdale facilities)
- **Microgrids**: Beaverton Public Safety Center, Portland Fire Station 1

## Security Program Status

### Regulatory Compliance
- **NERC CIP**: Mandatory compliance for Bulk Electric System operations
- **Standards**: CIP-002 through CIP-014 covering cyber/physical security
- **Audit History**: $5.6M total penalties since 2000 (no recent major violations)

### Current Security Infrastructure
- **SIEM**: QRadar deployment for security monitoring
- **Framework**: NERC CIP-aligned with CMMI maturity model
- **Team**: Dedicated cybersecurity director (Keegan Reichert)
- **Monitoring**: 24/7 security operations capabilities

### Security Incident History
- **Physical Attack (2022)**: Clackamas substation shooting, 6,400 customers affected
- **Cyber Incidents**: No major public breaches reported
- **Threat Landscape**: Tracking hacktivism, insider threats, nation-states, cybercrime

## Technical Challenges & Pain Points

### Infrastructure Challenges
- **Legacy Integration**: Complex OT/IT convergence requirements
- **Scale**: 825,000 smart meters increasing attack surface
- **Geographic Distribution**: 32 distributed generation sites requiring security
- **Vendor Diversity**: Multiple SCADA, control system vendors

### Security-Specific Challenges
- **Resource Constraints**: Skilled cybersecurity talent shortage
- **Compliance Complexity**: Evolving NERC CIP requirements
- **Nation-State Threats**: XENOTIME, KAMACITE, VOLTZITE targeting utilities
- **Smart Grid Immaturity**: Vendor security capabilities lag IT standards

### Vendor Ecosystem
**Current Technology Partners**:
- AWS (cloud infrastructure)
- SAP (enterprise systems)
- AVEVA (SCADA/EMS)
- Schneider Electric (DERMS)
- Microsoft (Azure for specific workloads)
- Snowflake (data analytics)

**No Public Bug Bounty Program** - Security handled through traditional channels

---

# PART 3: STRATEGIC SALES APPROACH & BATTLE CARD

## Business & Security Initiatives Analysis

### Active Business Initiatives
1. **Clean Energy Transformation** (Primary Driver)
   - 2,700-3,700 MW new renewable capacity needed by 2030
   - $1.46B annual capital investment in grid modernization
   - Federal grants totaling $470M for transmission/grid projects

2. **Grid Modernization & Resilience**
   - Smart Grid Test Bed expansion from 20,000 customers
   - 475+ MW battery storage integration
   - Wildfire mitigation: $135M annual investment

3. **Digital Transformation**
   - AWS cloud optimization and expansion
   - SAP S/4HANA modernization (active job postings)
   - AI implementation (12x engineering cycle reduction)

### Current Security/Compliance Projects
- **NERC CIP Evolution**: Meeting CIP-015 internal network monitoring requirements
- **OT/IT Convergence**: Securing integrated AVEVA/GenOnSys systems
- **Smart Grid Security**: Protecting 825,000 smart meters and communications
- **Supply Chain Security**: Post-SolarWinds enhanced vendor assessments

### Budget Cycles & Priorities
- **Fiscal Year**: January 1 - December 31
- **Capital Budget**: $1.3B planned for 2025
- **Rate Case**: 5.5% increase approved for 2025
- **Federal Funding**: $470M grants providing additional security investment capacity

## OT Environment Analysis

### Industrial Systems Landscape
**Generation Assets** (3,300+ MW):
- 7 hydroelectric facilities
- 4 wind farms (including 311 MW Clearwater)
- 6 thermal plants (5 natural gas)
- 162 MW solar (Pachwaywit Fields)
- 475+ MW battery storage

**Control Systems Architecture**:
- AVEVA System Platform (primary SCADA/EMS)
- GenOnSys distributed generation control
- Factory IQ system integration
- IEEE-61850 protocol implementation

### OT Security Maturity Assessment
**Current State**:
- Basic NERC CIP compliance achieved
- Physical/electronic security perimeters established
- 24/7 monitoring capabilities
- Limited OT-specific threat detection

**Gaps Identified**:
- No dedicated OT security platform
- Limited industrial protocol visibility
- Insufficient threat intelligence for ICS
- Reactive vs. proactive OT security posture

### OT Threat Exposure
**Critical Vulnerabilities**:
- **XENOTIME**: Proven capability against safety systems, conducting grid reconnaissance
- **KAMACITE**: Ukraine attack precedent, facilitates ELECTRUM access
- **VOLTZITE**: Active surveillance of global electric sector
- **Ransomware**: 13 electric sector incidents Q3 2024

## Value Proposition Alignment

### NCC-Dragos Capability Mapping

**Immediate Needs (NOW - 0-6 months)**:
1. **OT Asset Discovery & Visibility**
   - Dragos Platform deployment for AVEVA/GenOnSys environments
   - Map 32 distributed generation sites
   - **Value**: NERC CIP-002 compliance, reduce audit findings

2. **Threat Detection & Response**
   - Deploy Dragos threat detections for XENOTIME/KAMACITE
   - OT Watch managed service for 24/7 monitoring
   - **Value**: Proactive defense against proven utility threats

3. **Vulnerability Assessment**
   - Front Door Diagnostics (FDD) assessment
   - Focus on generation control systems
   - **Value**: Identify critical exposures before incidents

**Strategic Opportunities (NEXT - 6-18 months)**:
1. **OT Network Segmentation**
   - Design secure architectures for battery storage systems
   - Smart grid security architecture
   - **Value**: Protect $475M battery investments

2. **Incident Response Readiness**
   - IR Retainer with utility-specific runbooks
   - Tabletop exercises for grid attacks
   - **Value**: Minimize impact of inevitable attempts

3. **Supply Chain Security**
   - Vendor risk assessments for OT systems
   - Secure integration standards
   - **Value**: Prevent supply chain compromises

**Future Vision (NEVER compromises)**:
- Never sacrifice reliability for security
- Never impact NERC compliance status
- Never disrupt 24/7 operations

### Competitive Differentiation
**Vs. Current State**:
- PGE has IT security (QRadar) but lacks OT-specific capabilities
- Generic SIEM cannot detect industrial protocol attacks
- No utility-specific threat intelligence

**Vs. Competitors**:
- Only vendor with proven utility OT expertise
- Exclusive XENOTIME/KAMACITE detection capabilities  
- 24/7 OT-specific SOC (OT Watch)

## Engagement Strategy

### Target Stakeholders & Messaging

**Primary Targets**:
1. **Keegan Reichert** (Director of Cybersecurity)
   - Message: "Extend security visibility into OT environments"
   - Pain: Limited OT protocol visibility in current tools

2. **Campbell Henderson/John Kochavatr** (CIOs)
   - Message: "Protect digital transformation investments"
   - Pain: OT/IT convergence security gaps

3. **Debbie Powell** (COO)
   - Message: "Ensure operational resilience against targeted attacks"
   - Pain: 2022 physical attack, need comprehensive security

**Secondary Targets**:
- Larry Bekkedahl (Advanced Energy Delivery) - Smart grid security
- Joe Trpik (CFO) - ROI and risk reduction metrics
- Board Audit & Risk Committee - Compliance assurance

### Discovery Process Questions
1. How are you currently monitoring AVEVA System Platform for cyber threats?
2. What visibility do you have into your 32 distributed generation sites?
3. How do you assess OT vulnerabilities during NERC CIP audits?
4. What's your incident response plan for an ICS-specific attack?
5. How are you securing the 475 MW of battery storage systems?

### Sales Process Flow
**Phase 1 (Weeks 1-2)**: Initial Contact
- LinkedIn outreach to Reichert/Henderson
- Reference 2022 attack and XENOTIME threats
- Offer FDD assessment

**Phase 2 (Weeks 3-4)**: Discovery
- Technical deep dive on AVEVA environment
- Review NERC compliance gaps
- Demonstrate Dragos Platform capabilities

**Phase 3 (Weeks 5-8)**: Proof of Value
- Deploy Dragos in test environment
- Show threat detection capabilities
- Quantify risk reduction

**Phase 4 (Weeks 9-12)**: Contract Negotiation
- Start with single site deployment
- Include OT Watch and IR Retainer
- Plan enterprise rollout

### Objection Handling Matrix

| Objection | Response |
|-----------|----------|
| "We have QRadar for security monitoring" | "QRadar excels at IT but cannot decode Modbus, DNP3, or IEC-61850 protocols in your AVEVA systems" |
| "NERC CIP is sufficient" | "CIP is minimum baseline - XENOTIME and KAMACITE exceed CIP threat models" |
| "Too expensive" | "2022 attack cost 6,400 customers power - what's the cost of a generation facility compromise?" |
| "Our vendors handle security" | "Vendor security varies - need unified visibility across AVEVA, GenOnSys, battery systems" |

## Implementation & Success Planning

### Phased Deployment Approach

**Phase 1 - Foundation** (Months 1-3):
- Deploy Dragos Platform at primary control center
- Integrate with AVEVA System Platform
- Baseline normal OT behavior

**Phase 2 - Expansion** (Months 4-6):
- Extend to distributed generation sites
- Add battery storage systems
- Enable OT Watch service

**Phase 3 - Maturity** (Months 7-12):
- Full threat intelligence integration
- Automated response playbooks
- Predictive vulnerability management

### Success Metrics Framework
**Technical KPIs**:
- Time to detect OT anomalies: <5 minutes
- NERC CIP audit findings: 50% reduction
- OT asset visibility: 100% coverage
- Mean time to respond: <30 minutes

**Business KPIs**:
- Avoided outage minutes
- Compliance penalty reduction
- Insurance premium optimization
- Board risk score improvement

### Strategic Expansion Roadmap
1. **Initial Win**: Generation control systems
2. **Expand**: Smart grid and battery storage
3. **Integrate**: Unified IT/OT security operations
4. **Mature**: Predictive OT risk management
5. **Lead**: Industry best practices sharing

## Executive Summary Battle Card

**The Opportunity**: PGE operates 3,300+ MW of critical generation infrastructure with ambitious modernization goals, facing sophisticated nation-state threats while managing complex NERC compliance requirements.

**The Challenge**: Current security tools lack OT visibility, cannot detect industrial protocol attacks, and leave critical infrastructure exposed to proven threat actors.

**The Solution**: NCC-Dragos provides purpose-built OT security platform with utility-specific threat intelligence, 24/7 monitoring, and proven incident response capabilities.

**The Outcome**: Comprehensive OT visibility, proactive threat detection, NERC compliance assurance, and operational resilience against targeted attacks.

**Next Step**: Schedule Front Door Diagnostics assessment to identify current OT security gaps and demonstrate immediate value through asset discovery and vulnerability identification.