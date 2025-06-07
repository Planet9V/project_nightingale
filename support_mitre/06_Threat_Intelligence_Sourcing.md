# Sourcing Threat Intelligence: Reports and Feeds with MITRE ATT&CK Mappings

## Government and Public Sector Intelligence Sources

Government agencies and public sector organizations provide authoritative, high-quality threat intelligence with increasing ATT&CK integration, offering credible and actionable insights for defensive operations.

### U.S. Government Sources

**Cybersecurity and Infrastructure Security Agency (CISA)**
- **Authority**: U.S. Department of Homeland Security
- **Publications**: Cybersecurity Advisories (CSAs), Alerts, Joint Advisories
- **ATT&CK Integration**: Explicit TTP mappings in threat analysis
- **Coverage**: Critical infrastructure targeting, nation-state campaigns, cybercriminal activity
- **Example**: LummaC2 malware advisory with T1566.001, T1566.002, T1036, T1027 mappings
- **Strategic Value**: Sets industry standards for ATT&CK-based threat communication

**CISA Cascade (Prototype Platform)**
- **Purpose**: Server for authentication, analytics, and investigations
- **Foundation**: Built upon MITRE ATT&CK framework
- **Capabilities**: Analytics against Splunk/Elasticsearch data, alert generation
- **Significance**: Demonstrates governmental operationalization of ATT&CK
- **Future Impact**: Large-scale analytics and investigation capabilities

**Joint Cybersecurity Advisories**
- **Participants**: CISA, FBI, NSA collaboration
- **Coverage**: Nation-state campaigns, critical infrastructure threats
- **Format**: Comprehensive TTP analysis with ATT&CK mappings
- **Example**: Iranian CYBERAV3NGERS energy infrastructure targeting
- **Intelligence Value**: Multi-agency validation and assessment

### International Government Sources

**National CERTs and Cybersecurity Centers**
- **Coverage**: Country-specific threat landscapes
- **ATT&CK Adoption**: Varying levels of framework integration
- **Languages**: Multiple languages requiring translation
- **Regional Focus**: Geographic-specific threat actor activity
- **Coordination**: Information sharing with U.S. agencies

**Examples of International Sources:**
- UK NCSC threat reports and advisories
- Canadian Centre for Cyber Security intelligence
- Australian Cyber Security Centre threat assessments
- European Union cybersecurity agency reports

## Leading Cybersecurity Vendor Intelligence

Commercial cybersecurity vendors provide in-depth threat intelligence derived from product telemetry, incident response engagements, and dedicated research teams, with increasing ATT&CK standardization.

### Premier Vendor Sources

**Mandiant (Google Cloud)**
- **Expertise**: Incident response and threat actor tracking
- **Specialization**: Advanced Persistent Threats (APTs) and financially motivated actors
- **ATT&CK Integration**: Comprehensive TTP mappings with detailed procedures
- **Report Quality**: In-depth technical analysis with attribution assessment
- **Example Coverage**: FIN7 group analysis with complete technique documentation
- **Strategic Value**: Real-world incident intelligence and actor profiling

**CrowdStrike**
- **Platform**: Falcon threat intelligence integration
- **Publications**: Annual Global Threat Report, actor profiles
- **ATT&CK Participation**: MITRE Engenuity evaluations, CTID research projects
- **Capabilities**: Real-time TTP detection and mapping
- **Community Engagement**: Top ATT&CK Techniques research, TRAM II participation
- **Innovation**: AI-enhanced threat detection with ATT&CK correlation

**Palo Alto Networks Unit 42**
- **Research Scope**: Ransomware trends, malware families, campaign analysis
- **ATT&CK Application**: Behavioral mapping and product mitigation guidance
- **Coverage**: Cross-sector threat analysis with technique documentation
- **Defensive Focus**: Product capability mapping to ATT&CK framework
- **Strategic Intelligence**: Threat landscape evolution and defensive recommendations

**Red Canary**
- **Specialization**: Annual Threat Detection Report with ATT&CK focus
- **Methodology**: Customer base TTP prevalence analysis
- **Detection Analytics**: Intrinsic ATT&CK mapping for all analytics
- **Practical Value**: Real-world technique manifestation patterns
- **Community Contribution**: Detection logic sharing and TTP frequency analysis

**Trend Micro**
- **Research Areas**: Container security, IoT threats, APT campaigns
- **ATT&CK Mapping**: Product capability alignment and threat analysis
- **Contribution**: Real-world attack data to MITRE framework
- **Coverage**: Multi-platform threat intelligence and defensive guidance
- **Innovation**: Cross-platform technique detection and correlation

**Kaspersky**
- **Publication**: Securelist blog and research reports
- **Expertise**: APT campaigns, malware analysis, emerging threats
- **ATT&CK Engagement**: Framework evaluations and MDR service integration
- **Geographic Coverage**: Global threat landscape with regional expertise
- **Technical Depth**: Detailed technical analysis and tool documentation

**Sophos**
- **Integration**: Intercept X with XDR ATT&CK mapping
- **Evaluations**: MITRE Engenuity participation (Wizard Spider, Sandworm)
- **Research**: Lab articles and threat landscape analysis
- **Detection**: Product capabilities mapped to ATT&CK techniques
- **Validation**: Public evaluation of detection and prevention capabilities

### Vendor Intelligence Assessment Criteria

**Quality Indicators:**
- Explicit ATT&CK technique mappings
- Detailed procedure documentation
- Technical validation and evidence
- Attribution confidence levels
- Defensive recommendations

**Evaluation Factors:**
- TTP mapping accuracy and completeness
- Technical detail depth and precision
- Evidence quality and verification
- Timeliness and relevance
- Actionable defensive guidance

## Open-Source Intelligence Feeds

Open-source CTI feeds provide access to large volumes of threat data, requiring additional analytical processing for effective ATT&CK correlation and operational application.

### Major Open-Source Platforms

**AlienVault OTX (Open Threat Exchange)**
- **Model**: Community-powered threat intelligence sharing
- **Content**: Real-time threat indicators and "pulses"
- **ATT&CK Integration**: Variable—some pulses include ATT&CK tags
- **Volume**: Large-scale indicator collection
- **Challenge**: Requires additional analysis for behavioral context
- **Use Cases**: IOC enrichment, threat landscape monitoring

**MISP (Malware Information Sharing Platform)**
- **Architecture**: Open-source threat intelligence platform
- **Capability**: Event creation with ATT&CK tagging
- **Integration**: Compatible with OpenCTI and other platforms
- **Standardization**: Support for multiple classification schemes
- **Community**: Global information sharing community
- **Quality Variance**: Contributor-dependent intelligence quality

### Open-Source Intelligence Processing

**Analytical Requirements:**
- **Context Enrichment**: IOCs require behavioral analysis for TTP mapping
- **Quality Assessment**: Variable contributor expertise and validation
- **Correlation Needs**: Cross-reference with authoritative sources
- **Validation Process**: Independent technical verification required

**Example Processing Workflow:**
1. IOC Collection: Gather indicators from open-source feeds
2. Context Analysis: Research associated malware behavior and campaigns
3. TTP Mapping: Correlate behaviors with ATT&CK techniques
4. Quality Validation: Cross-reference with commercial intelligence
5. Operational Integration: Deploy in detection and hunting capabilities

**ATT&CK Correlation Challenges:**
- IOCs alone don't directly indicate techniques
- Requires understanding of tool behavior and campaign context
- Need additional research for accurate technique mapping
- Quality validation essential for operational deployment

### Intelligence Feed Comparison

| **Source Type** | **ATT&CK Integration** | **Quality Level** | **Volume** | **Technical Depth** | **Cost Model** |
|-----------------|------------------------|-------------------|------------|-------------------|----------------|
| **Government** | Explicit, authoritative | High | Medium | High | Free |
| **Commercial Vendors** | Detailed, validated | High | Medium | Very High | Subscription |
| **Open Source Feeds** | Variable, requires processing | Variable | Very High | Low-Medium | Free |

## Strategic Intelligence Application

### Multi-Source Intelligence Fusion

**Comprehensive Approach:**
1. **Government Intelligence**: Authoritative threat landscape assessment
2. **Commercial Intelligence**: Technical depth and attribution analysis
3. **Open Source Feeds**: Broad indicator coverage and community insights
4. **Internal Intelligence**: Organizational-specific threat analysis

**Quality Assurance Process:**
- Cross-source validation for critical intelligence
- Confidence level assessment for all mappings
- Regular review and update of intelligence sources
- Documentation of analytical methodology and assumptions

### Operational Intelligence Requirements

**Real-Time Needs:**
- Current campaign activity and TTP evolution
- Emerging threat actor capabilities
- New technique variations and procedures
- Defensive bypass methods and adaptations

**Strategic Planning:**
- Long-term threat landscape trends
- Adversary capability development patterns
- Geographic and sector-specific targeting shifts
- Defensive technology effectiveness assessment

### Intelligence-Driven Operations

**Detection Development:**
- TTP-based detection rule creation
- Behavioral analytics development
- Threat hunting hypothesis generation
- False positive reduction through context

**Defensive Planning:**
- Control effectiveness assessment
- Gap analysis and improvement prioritization
- Investment decision support
- Training and awareness program development

**Incident Response:**
- Attribution assessment support
- TTP comparison and correlation
- Adversary behavior prediction
- Recovery and remediation guidance

## Best Practices for Intelligence Consumption

### Source Diversification Strategy

**Multi-Vendor Approach:**
- Avoid single-source dependency
- Cross-validate critical intelligence
- Maintain awareness of source biases
- Regular source performance evaluation

**Quality Over Quantity:**
- Focus on high-quality, validated intelligence
- Prioritize actionable TTP information
- Emphasize technical depth over volume
- Maintain analytical objectivity

### Operational Integration

**Workflow Development:**
- Standardized intelligence processing procedures
- ATT&CK mapping validation requirements
- Quality assurance checkpoints
- Operational deployment protocols

**Technology Integration:**
- Automated intelligence feeds where appropriate
- Manual validation for critical decisions
- Tool integration for efficiency
- Human oversight for complex analysis

---

*This document provides comprehensive guidance for threat intelligence sourcing with MITRE ATT&CK integration. For reporting best practices, see related documents in this series.*