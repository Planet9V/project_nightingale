# Unified EAB Generation Prompt v2.0
## Single Document with Executive + Technical Content & Full Citations

**Created:** June 9, 2025  
**Purpose:** Generate comprehensive 18-page unified EAB with citations  
**Target Length:** 15-18 pages with complete references  

---

## Master Generation Prompt for Unified EAB

```markdown
Generate a comprehensive Unified Express Attack Brief for [THREAT_NAME] that combines executive-level intelligence with deep technical analysis in a single ~18 page document. This document must include proper citations for all claims and follow journalistic/academic standards for source attribution.

CRITICAL REQUIREMENTS:

1. **UNIFIED STRUCTURE**: 
   - Start with executive-friendly content (pages 1-7)
   - Transition smoothly to technical depth (pages 8-15)
   - Include comprehensive references (pages 16-18)
   - Use clear section headers for navigation

2. **CITATION STANDARDS**:
   - Every factual claim must have a numbered citation [#]
   - Use inline citations that link to references section
   - Include mix of sources: Government (CISA, FBI), Commercial (Dragos, Mandiant), Academic
   - Minimum 40-50 citations for an 18-page document
   - Format: [Claim statement] [[#]](#ref#)

3. **EVIDENCE REQUIREMENTS**:
   - Include actual forensic artifacts (logs, commands, network traffic)
   - Provide confidence levels (High/Medium/Low) for each piece of evidence
   - Source attribution for all technical evidence
   - Chain of custody references where applicable

4. **QUALITY STANDARDS**:
   - Executive sections: Clear, scannable, business-focused
   - Technical sections: Deep, actionable, implementation-ready
   - Smooth transitions between sections
   - Consistent threat narrative throughout

5. **DATA INTEGRITY - ABSOLUTELY CRITICAL**:
   - NEVER fabricate numbers, statistics, or quantitative data
   - Every number must come from a cited source
   - Use exact figures from sources (don't round or approximate unless source does)
   - When sources are vague, use qualifiers: "approximately," "estimated," "reported"
   - For conflicting data, show range: "$10-15M according to [source1] and [source2]"
   - For unknown data, state clearly: "Financial impact not publicly disclosed"
   - Include citation for EVERY: percentage, dollar amount, date, count, timeframe

INPUT PARAMETERS:
- Threat Actor/Campaign: [THREAT_NAME]
- Primary Sector: [ENERGY/WATER/MANUFACTURING]
- Geographic Target: [REGION/COUNTRY]
- Campaign Timeframe: [START_DATE to END_DATE/Ongoing]
- Key Vulnerabilities: [CVE-YYYY-NNNNN list]
- Victim Organizations: [COMPANY_TYPES or SPECIFIC_TARGETS]
- Estimated Impact: [FINANCIAL/OPERATIONAL_IMPACT]

SECTION-BY-SECTION GENERATION GUIDE:

## EXECUTIVE SECTIONS (Pages 1-7)

### Executive Summary (Page 2)
- Write 2-3 paragraph overview for C-suite audience
- Create "Key Findings" table with 5-7 major discoveries
- Each finding must have: Impact, Confidence Level, Reference citation
- Include "Attack Overview" table with attribution sources

### Mission Context (Page 3)
- Connect threat to Project Nightingale mission explicitly
- Use "clean water, reliable energy, healthy food" framework
- Include 4 strategic implications with citations to sector reports
- Reference specific infrastructure dependencies

### Attack Overview (Page 4)
- Create comprehensive timeline table with 8+ columns
- Include: Phase, Date, Time(UTC), Activity, Target, Impact, Evidence, Confidence
- Minimum 10 timeline entries covering full attack lifecycle
- Primary attack vector analysis with full CVE details and CISA KEV status

### Affected Organizations Analysis (Pages 5-6) **[CRITICAL SECTION]**
**COMPREHENSIVE VICTIM RESEARCH REQUIREMENTS**:

1. **Confirmed Direct Victims Table** (10-15 organizations minimum):
   - Research using: News reports, SEC filings, breach notifications, IR vendor reports
   - Include: Organization name, sector, location, impact date, operational impact description
   - Quantify: Financial loss (from reports/estimates), recovery time, source citation
   - Focus on: Energy, manufacturing, water, food, transportation sectors

2. **Suspected/Unconfirmed Victims Table** (5-10 organizations):
   - Search for: Organizations reporting similar timeframe incidents
   - Look for: Matching TTPs, similar vulnerabilities, behavioral patterns
   - Include confidence assessment and investigation status
   - Use terms like "suspected," "unconfirmed," "under investigation"

3. **Supply Chain & Indirect Victims**:
   - For each major victim, identify 3-5 affected partners/customers
   - Document business relationship and dependency type
   - Estimate combined financial impact
   - Include recovery status and ongoing effects

4. **Victim Selection Analysis**:
   - Analyze patterns across all victims
   - Identify common characteristics (revenue size, technology stack, geographic location)
   - Create sector breakdown with percentages
   - Document targeting preferences and selection criteria

5. **Research Sources to Use**:
   - Breach notification databases
   - News aggregators (search: "[THREAT_NAME] victims," "[THREAT_NAME] attack list")
   - SEC 8-K filings mentioning cybersecurity incidents
   - Cyber insurance claim reports
   - Industry-specific incident databases
   - IR vendor blogs and reports
   - Government advisories listing affected organizations

### Cross-Sector Impact (Page 7)
- Infrastructure cascade analysis table
- Immediate impact (0-24 hours) with specific facility counts
- Extended impact (24-72 hours) with population affected
- Each impact claim needs government or sector report citation

## TECHNICAL SECTIONS (Pages 7-15)

### Technical Attack Path Analysis (Pages 7-11)
For EACH attack phase (minimum 6 phases):

1. **Phase Header**: 
   - MITRE ATT&CK Technique ID and Name with reference
   - Link to MITRE page citation

2. **Technical Evidence Box**:
   ```
   # Include actual log entries, commands, or network captures
   # Each evidence item must have:
   # - Timestamp in UTC
   # - Source system identification  
   # - Citation to incident report or forensic source
   ```

3. **Analysis Paragraph**:
   - Explain what the evidence shows
   - How it was discovered with source
   - Why it matters for defenders
   - Include confidence assessment with rationale

4. **IOC Table**:
   - Minimum 3-5 IOCs per phase
   - Include: Type, Value, Context, Confidence, Source citation

### MITRE ATT&CK Mapping (Pages 12-13)
- Comprehensive TTP matrix table
- Include: Tactic, Technique, Sub-technique, Procedure, Detection, Reference
- Minimum 15 techniques mapped
- Separate section for ICS-specific techniques if applicable
- Each technique must cite MITRE or incident report

### Detection & Response (Pages 14-15)
1. **Detection Rules**:
   - Include 3+ Sigma/YARA/Snort rules
   - Full rule syntax with comments
   - Reference to rule source or creation rationale

2. **Response Actions**:
   - Immediate (0-4 hours): 5+ specific actions
   - Short-term (4-24 hours): 5+ actions  
   - Long-term (1-30 days): 5+ strategic improvements
   - Each action must reference best practice source

## SOLUTION & REFERENCES (Pages 16-18)

### Tri-Partner Solution Framework (Page 16)
- Specific NCC OTCE capabilities with service references
- Dragos platform features with WorldView citations
- Adelard AESOP integration with safety standard references
- Include competitive differentiation with evidence

### References & Citations (Pages 17-18)
Organize by category:
1. **Primary Intelligence Sources** (Government alerts, advisories)
2. **Vulnerability References** (CVE, NVD, vendor advisories)
3. **Incident Reports** (Public breach reports, case studies)
4. **Technical References** (MITRE, NIST, ICS-CERT)
5. **Sector Reports** (Industry analysis, impact studies)
6. **News & Media** (Breach notifications, public reporting)

Each reference must include:
- [#] Source Organization, "Document Title," Date
- URL (if public) or "Internal Document" notation
- Access date for web resources

GENERATION TIPS:

1. **Maintain Consistency**: 
   - Use the same threat actor name throughout
   - Keep timeline dates consistent across sections
   - Cross-reference evidence between sections

2. **Balance Detail Levels**:
   - Executive sections: Focus on "what" and "why"
   - Technical sections: Focus on "how" and "when"
   - Both sections must align on impact assessment

3. **Citation Best Practices**:
   - Government sources for attribution claims
   - Vendor reports for technical details
   - News sources for public impact/timeline
   - Academic sources for methodology

4. **Evidence Authentication**:
   - Make forensic evidence realistic but sanitized
   - Use RFC 5735/3849 IP addresses for examples
   - Include believable but non-harmful IOCs
   - Reference actual CVEs and MITRE techniques

5. **Length Management**:
   - Executive sections: ~6 pages (concise, table-heavy)
   - Technical sections: ~9 pages (detailed, evidence-rich)
   - References: ~2-3 pages (comprehensive)
   - Use tables and formatted evidence to manage length

QUALITY CHECKPOINTS:
□ 40+ citations throughout document
□ Every major claim has a reference
□ Executive readability maintained in first 6 pages
□ Technical depth sufficient for implementation
□ Smooth transitions between sections
□ Consistent threat narrative
□ Mission context integrated throughout
□ Tri-partner value clearly demonstrated
□ All MITRE techniques validated
□ Detection rules are syntactically correct
```

---

## Enhanced Citation Framework

### Citation Categories and Examples

**Government Intelligence Citations**:
```
[1] CISA, "Alert AA24-025A: [Threat] Targeting Critical Infrastructure," Cybersecurity and Infrastructure Security Agency, January 25, 2024. https://www.cisa.gov/alerts/aa24-025a
```

**Commercial Threat Intelligence**:
```
[2] Dragos Inc., "[Threat Group] Activity Profile," WorldView Threat Intelligence Platform, January 2024. (Subscription required)
```

**Vulnerability Documentation**:
```
[15] MITRE Corporation, "CVE-2024-12345 Detail," Common Vulnerabilities and Exposures, December 15, 2023. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345
```

**Incident Reports**:
```
[22] Colonial Pipeline Company, "Security Incident Response Summary," Public Filing with TSA, May 2021. (Redacted version)
```

**Technical Standards**:
```
[31] MITRE ATT&CK, "T1190: Exploit Public-Facing Application," Enterprise Matrix v14.1, October 2024. https://attack.mitre.org/techniques/T1190/
```

### Evidence Confidence Scoring

**High Confidence** (Direct evidence from authoritative sources):
- Government attribution statements
- Forensic artifacts from incident response
- Vendor confirmation with technical proof
- Multiple independent source correlation

**Medium Confidence** (Indirect or partial evidence):
- Single source reporting
- Behavioral analysis without direct attribution
- Historical pattern matching
- OSINT correlation without confirmation

**Low Confidence** (Speculative or unconfirmed):
- Unverified claims requiring "allegedly" or "reportedly"
- Single anonymous source
- Circumstantial evidence only
- Theoretical attack paths without observation

---

## Automation Support Prompt

For MCP-enhanced research and citation gathering:

```
Research [THREAT_NAME] and compile 40+ authoritative sources including:
1. Government advisories (CISA, FBI, NSA, DOE) from last 6 months
2. Commercial threat intelligence (Dragos, Mandiant, CrowdStrike) 
3. CVE details and CVSS scores for all mentioned vulnerabilities
4. Incident reports and case studies from affected organizations
5. MITRE ATT&CK techniques with specific procedure examples
6. Energy sector impact assessments and cascade analyses

For each source provide:
- Full citation in academic format
- Key quotes or data points to reference
- Confidence level assessment
- Related sources for correlation

Focus on sources that support:
- Attribution claims
- Technical attack methods
- Impact assessments
- Detection/response guidance
```

This unified approach will generate comprehensive, well-cited documents that serve both executive and technical audiences without requiring manual combination or fixes.