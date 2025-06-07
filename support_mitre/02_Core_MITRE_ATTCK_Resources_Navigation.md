# Core MITRE ATT&CK Resources Navigation

## Essential ATT&CK Website Navigation

The official MITRE ATT&CK website (attack.mitre.org) serves as the definitive source for all ATT&CK-related knowledge and provides the foundation for professional threat intelligence work.

### Primary Website Components

**Matrices Structure:**
- **Enterprise Matrix**: Most extensive coverage including Windows, macOS, Linux, cloud infrastructure (IaaS, SaaS), networking infrastructure, and containers
- **Mobile Matrix**: Android and iOS platform-specific TTPs
- **ICS Matrix**: Industrial Control Systems and operational technology environments

**Core Data Elements:**

**Tactics**: Represent adversary tactical objectives—the "why" behind actions
- Example: "Credential Access" (TA0006) for stealing account credentials
- Enterprise Matrix contains 14 tactics total

**Techniques and Sub-techniques**: Describe "how" adversaries achieve tactical goals
- Main techniques (e.g., T1548 "Abuse Elevation Control Mechanism")
- Sub-techniques for specificity (e.g., T1548.002 "Bypass User Account Control")
- Each page includes: description, platforms, data sources, mitigations, procedure examples, references

**Groups Database**: Adversary activity clusters tracked by security community
- Examples: FIN7, APT29
- Includes: aliases, origins, targets, TTPs, known software, relevant reports

**Software Database**: Malware and legitimate tools used by adversaries
- Examples: PlugX (malware), Cobalt Strike (tool), PsExec (tool)
- Details: type, capabilities, associated groups, ATT&CK techniques enabled

### Relational Data Structure Benefits

The interconnected nature enables powerful analytical pivoting:
- Tool → actors who use it → other techniques they favor → relevant defenses
- Actor → typical software → techniques enabled → appropriate mitigations
- Technique → mitigation advice → procedure examples → software/groups that use it

This facilitates holistic investigations beyond isolated intelligence sources.

### Critical Website Features for Analysts

**Procedure Examples**: Concrete illustrations of abstract techniques in real-world scenarios
- Help analysts recognize specific observed actions as manifestations of broader techniques
- Essential for accurate mapping and deeper understanding
- Link theoretical framework to practical implementation

**Cross-Referencing Capabilities**: 
- Group pages list associated software and techniques
- Software pages link to groups and enabled techniques  
- Technique pages provide mitigations and procedure examples
- Enables comprehensive threat actor profiling and defense planning

## Data Access Methods

### STIX Format Access
**Purpose**: Machine-readable format for automated integration
**Repository**: mitre-attack/attack-stix-data GitHub repository
**Use Cases**: 
- Threat Intelligence Platforms (TIPs) ingestion
- SIEM/SOAR platform integration
- Automated security tool consumption
- Programmatic analysis and processing

### Excel Spreadsheet Access
**Purpose**: Manual review and ad-hoc analysis
**Format**: Downloadable Excel files with matrices and data
**Use Cases**:
- Manual analysis workflows
- Custom reporting development
- Offline analysis requirements
- Training and education materials

### Python Library Integration
**Tool**: mitreattack-python library
**Purpose**: Programmatic access and manipulation
**Benefits**:
- Lowers barrier for custom solution development
- Enables bespoke analytical tools
- Supports automated reporting
- Facilitates advanced analytics without deep STIX expertise

## Navigation Best Practices

**For Incident Analysis**:
1. Start with Technique pages for observed behaviors
2. Review Procedure Examples for context validation
3. Check associated Groups for attribution clues
4. Examine Software entries for tool-specific intelligence
5. Review Mitigations for defensive guidance

**For Threat Hunting**:
1. Begin with Group profiles for target actor TTPs
2. Map to relevant Techniques and Sub-techniques
3. Identify associated Software and tools
4. Develop hunting hypotheses based on procedure examples
5. Create detection logic using Data Sources guidance

**For Defense Planning**:
1. Assess organization's threat landscape via Group analysis
2. Prioritize Techniques based on relevant threat actors
3. Review Mitigations for each prioritized technique
4. Map to organizational security controls
5. Identify gaps and improvement opportunities

---

*This document provides essential navigation guidance for the official MITRE ATT&CK website. For specific threat actor analysis, see related documents in this series.*