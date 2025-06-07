# MITRE ATT&CK® Overview and Foundation

## The Central Role of MITRE ATT&CK® in Modern Threat Intelligence

The MITRE ATT&CK® framework has emerged as a cornerstone in the field of cybersecurity, fundamentally reshaping how organizations approach threat intelligence and cyber defense. It is a globally accessible, curated knowledge base detailing adversary tactics, techniques, and procedures (TTPs) derived from real-world observations. This comprehensive repository serves as a common lexicon, enabling defenders worldwide to articulate, discuss, and strategize against cyber threats with unprecedented clarity and consistency.

### Framework Core Strengths

The framework's core strength lies in its shift away from traditional, reactive Indicator of Compromise (IOC)-based defense towards a more proactive, behavior-centric approach to threat detection, analysis, and response.

**Global Recognition and Adoption:**
- Recognized as the "global gold standard for turning cyber threat data into a strategic advantage"
- Often referred to as the "'motherbrain' of cybersecurity planning and intelligence"
- Adoption spans over 190 countries
- Over 80% of North American organizations surveyed in 2022 regard it as "critical" or "very important" to their security operations strategy

### Living Encyclopedia Approach

ATT&CK is not a static document but a "living encyclopedia," continually updated and refined through contributions from a global community of cybersecurity practitioners and real-world incident data. This dynamic nature means that the framework evolves in tandem with the threat landscape.

**Implications for Practitioners:**
- Continuous learning commitment required to stay current
- Need to understand evolving adversary methodologies
- Must effectively leverage the latest insights offered by the framework

### Framework Matrices

ATT&CK is organized into several key matrices:

1. **Enterprise Matrix**: The most extensive matrix, covering tactics and techniques observed in enterprise network environments, including:
   - Windows, macOS, Linux operating systems
   - Cloud infrastructure and services (IaaS, SaaS)
   - Networking infrastructure
   - Containers

2. **Mobile Matrix**: Focuses on TTPs relevant to mobile devices, specifically Android and iOS platforms

3. **ICS (Industrial Control Systems)**: Addresses unique TTPs employed by adversaries targeting industrial control systems and operational technology environments

### Core Components

**Tactics**: Represent the adversary's tactical objective—the "why" behind their actions
- Example: "Credential Access" (TA0006) represents stealing account names and passwords
- Enterprise ATT&CK Matrix currently comprises 14 tactics

**Techniques and Sub-techniques**: Describe "how" an adversary achieves a tactical goal
- Example: T1548 "Abuse Elevation Control Mechanism" under "Privilege Escalation" tactic
- Sub-techniques provide more specific descriptions (e.g., T1548.002 "Bypass User Account Control")

**Groups**: Clusters of adversary activity tracked by a common name in the security community
- Examples: FIN7, APT29
- Include information on origins, targets, TTPs, and known software

**Software**: Catalogs malware and legitimate tools leveraged by adversaries
- Examples: PlugX (malware), Cobalt Strike or PsExec (tools)
- Details type, capabilities, associated groups, and ATT&CK techniques facilitated

### Interconnected Data Structure

The relational structure of ATT&CK allows analysts to pivot between different data types:
- From observed tool → actors who use it
- From actors → other techniques they favor
- From techniques → relevant defensive measures

This facilitates more holistic and context-rich investigations than isolated information sources.

---

*This document serves as the foundation for understanding MITRE ATT&CK. For specific implementation guidance, see related documents in this series.*