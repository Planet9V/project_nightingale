# State of the Industry Report Generation Master Prompt
## High-Quality Monthly Cybersecurity Briefing System

**Version**: 1.0  
**Date**: June 14, 2025  
**Purpose**: Reproducible generation of executive-level cybersecurity industry reports  
**Author**: Project Nightingale Intelligence Team  

YOU MUST ALWAYS USE APA CITATION STYLE!!!! ALWAYS

## 🎯 Mission Statement

Generate five (5) high-quality "State of the Industry" cybersecurity briefings for critical infrastructure sectors, maintaining executive-level quality, data-driven insights, and subtle promotion of the NCC Group tri-partner solution. 

You must maximize the claude code capabilities by running parallel tasks when appropriate and writing key research into "notecards" for future reference during reserch by the different subagents

All files and content are to be placed in  /home/jim/gtm-campaign-project/reports
## 📋 Execution Checklist

### Phase 1: Research & Intelligence Gathering
- [ ] Initialize extended thinking mode for deep analysis
- [ ] Deploy Research Agent #1: Current advisories analysis
- [ ] Deploy Research Agent #2: Sector-specific threat intelligence
- [ ] Deploy Research Agent #3: Recent cyber incidents and trends
- [ ] Deploy Research Agent #4: Regulatory and compliance updates
- [ ] Create consolidated research scratchpad
- [ ] Timestamp: [YYYY-MM-DD HH:MM:SS TZ]

### Phase 2: Report Generation
- [ ] Generate Energy Sector report
- [ ] Generate Renewables/Natural Gas report
- [ ] Generate Manufacturing report
- [ ] Generate Railways/Transit report
- [ ] Generate DER/Smart Grid/VPP report
- [ ] Apply consistent formatting to all reports
- [ ] Timestamp: [YYYY-MM-DD HH:MM:SS TZ]

### Phase 3: Quality Enhancement
- [ ] Deploy Editor Agent for prose refinement
- [ ] Verify all citations and sources
- [ ] Ensure tri-partner solution integration
- [ ] Check formatting consistency
- [ ] Timestamp: [YYYY-MM-DD HH:MM:SS TZ]

### Phase 4: Cross-Sector Analysis
- [ ] Create cross-sector analysis scratchpad
- [ ] Identify common trends and patterns
- [ ] Generate Cross-Sector Intelligence Report
- [ ] Cross-reference all six reports
- [ ] Timestamp: [YYYY-MM-DD HH:MM:SS TZ]

### Phase 5: Final Enhancement
- [ ] Review individual reports for improvements
- [ ] Apply insights from cross-sector analysis
- [ ] Final formatting consistency check
- [ ] Verify tri-partner language standards
- [ ] Update blotter.md with completion
- [ ] Timestamp: [YYYY-MM-DD HH:MM:SS TZ]

---

## 🔧 Detailed Implementation Instructions

### 1. Research Phase Instructions

**Activate Extended Thinking Mode:**
```
<thinking>
I need to perform deep research across multiple sources to gather comprehensive intelligence for these sector reports. Let me deploy multiple research agents in parallel to maximize efficiency and coverage.
</thinking>
```

# Please note that there is an extensive mount of threat intelligence already gathereed and local. You are directed to catalogue key relevant topics and data and place into a temprorary "research_note" and be sure each Research Agent also examines the folder as well as external searches from this folder and subfolders; intelligence 

**Research Agent Deployment:**

```markdown
## Research Agent #1: Advisory Analysis
- Source: /Current_advisories_2025_7_1/*
- Focus: CISA advisories, ICS alerts, vulnerability disclosures
- Extract: CVEs, affected systems, threat actors, TTPs

## Research Agent #2: Sector Intelligence  
- Use: mcp__tavily__tavily-search
- Queries: "[Sector] cybersecurity incidents 2025", "[Sector] ransomware attacks", "[Sector] OT vulnerabilities"
- Time range: Last 30 days

## Research Agent #3: Threat Trends
- Use: mcp__brave__brave_web_search
- Focus: Emerging threat actors, new malware variants, attack campaigns
- Priority: Sector-specific threats

## Research Agent #4: Regulatory Updates
- Search: New regulations, compliance requirements, industry standards
- Sectors: Energy (NERC CIP), Manufacturing (NIST), Rail (TSA directives)
```

### 2. Report Structure Template

```markdown
# [Sector] Cybersecurity State of the Industry
## [Month] 2025 Intelligence Briefing

**Classification**: UNCLASSIFIED // FOR PUBLIC DISTRIBUTION  
**Date**: [Current Date]  
**Version**: 1.0  
**Author**: Jim McKenney, Director OTCE Americas, NCC Group  
**Distribution**: Industry Executives and Security Leaders  

## Executive Summary

[3-4 sentences capturing the month's most critical developments, quantified impacts, and strategic implications for the sector]

## Threat Landscape Overview

### Active Threat Actors
- **[Threat Actor Name]**: [Brief description, TTPs, recent activity]
  - Target Profile: [Specific subsector targets]
  - Recent Campaign: [Specific incident with date]
  - Impact: [Quantified business impact]

### Critical Vulnerabilities
| CVE ID | Affected Systems | CVSS Score | Exploitation Status |
|--------|------------------|------------|-------------------|
| CVE-2025-XXXXX | [System] | [Score] | [Active/PoC/None] |

## Sector-Specific Analysis

### [Subsector 1] Challenges
[Data-driven analysis with specific examples, percentages, and business impacts]

### [Subsector 2] Trends
[Emerging patterns, statistical trends, predictive insights]

## Attack Vector Analysis

### Primary TTPs Observed
1. **[Technique]**: [Description with specific examples]
   - Frequency: [X incidents in past 30 days]
   - Success Rate: [Percentage]
   - Mitigation Effectiveness: [Data]

## Business Impact Assessment

- **Operational Disruptions**: [Quantified downtime, production losses]
- **Financial Exposure**: [$X million in ransoms, $Y million in recovery]
- **Regulatory Implications**: [Specific compliance impacts]

## Strategic Recommendations

### Immediate Actions (0-30 days)
1. [Specific, actionable recommendation]
2. [Specific, actionable recommendation]

### Strategic Initiatives (30-90 days)
[Forward-looking recommendations aligned with sector needs]

*For organizations seeking comprehensive OT security assessments and multi-state coordination capabilities, the NCC Group tri-partner solution with Dragos and Adelard provides specialized expertise in [sector-specific value proposition].*

## Intelligence Sources
[1] [Source with date]  
[2] [Source with date]  
[3] [Source with date]
```

### 3. Sector-Specific Focus Areas

**Energy Sector:**
- Grid reliability threats
- SCADA/ICS vulnerabilities
- Nation-state targeting
- NERC CIP compliance

**Renewables/Natural Gas:**
- Remote monitoring risks
- Supply chain attacks
- Environmental activism hacktivism
- Pipeline security

**Manufacturing:**
- Ransomware impacts on production
- IP theft campaigns
- IoT/OT convergence risks
- Supply chain disruptions

**Railways/Transit:**
- Signaling system vulnerabilities
- Passenger data protection
- Critical infrastructure designation
- TSA Security Directives

**DER/Smart Grid/VPP:**
- Distributed attack surfaces
- Grid edge security
- Virtual power plant risks
- Advanced metering infrastructure

### 4. Tri-Partner Solution Integration Guidelines

**Tasteful Integration Points:**
- Within strategic recommendations
- As part of risk mitigation options
- In context of multi-state coordination needs
- When discussing OT security expertise

**Key Messages:**
- NCC Group: Grid-integrated security operations
- Dragos: OT-native platform and threat intelligence
- Adelard: Quantitative risk assessment and ROI modeling

**Positioning Statement Template:**
"Organizations managing [specific challenge] benefit from specialized OT security expertise. The tri-partner solution from NCC Group, Dragos, and Adelard has demonstrated [specific metric] improvements in similar deployments."

### 5. Quality Standards

**Executive Prose Style:**
- Spartan, fact-driven sentences
- Active voice throughout
- Quantified impacts (percentages, dollars, time)
- No jargon without explanation
- 2-3 sentence paragraphs maximum

**Citation Requirements:**
- All statistics must have sources
- Recent incidents need dates
- Vulnerability data requires CVE references
- Regulatory items need official sources

**Formatting Standards:**
- Headers: ## for main sections, ### for subsections
- Tables for structured data
- Bullet points for lists
- Bold for emphasis on key terms
- Italics for subtle call-outs only

### 6. Cross-Sector Analysis Instructions

After generating all five reports, create a meta-analysis:

```markdown
# Critical Infrastructure Cybersecurity Trends
## Cross-Sector Intelligence Analysis [Month] 2025

### Common Attack Patterns
[Identify trends appearing across multiple sectors]

### Emerging Threat Convergence
[Analyze how threats are evolving across sectors]

### Sector Interdependencies
[Map cascading risks between sectors]

### Predictive Intelligence
[Forward-looking analysis based on observed patterns]

### Comparative Risk Matrix
| Sector | Primary Threat | Risk Level | Trend |
|--------|---------------|------------|-------|
```

### 7. Blotter.md Update Format

```markdown
## [Current Date Time] - State of Industry Report Generation

### Tasks Completed:
- [14:46:05 CDT] Research Phase initiated with 4 parallel agents
- [15:10:22 CDT] Energy Sector report completed (2,847 words)
- [15:25:43 CDT] Renewables/Natural Gas report completed (2,563 words)
- [15:41:18 CDT] Manufacturing report completed (2,791 words)
- [15:58:02 CDT] Railways/Transit report completed (2,654 words)
- [16:15:44 CDT] DER/Smart Grid report completed (2,892 words)
- [16:32:19 CDT] Cross-sector analysis completed
- [16:45:33 CDT] Final enhancements applied to all reports
- [16:52:21 CDT] Quality assurance and formatting check complete

### Key Insights Generated:
- [Insight 1]
- [Insight 2]
- [Insight 3]

### Metrics:
- Total research sources consulted: [X]
- Unique threat actors identified: [Y]
- Critical vulnerabilities analyzed: [Z]
- Cross-sector patterns identified: [N]
```

---

## 🚀 Execution Command Sequence

1. **Initialize**: `date` → Record timestamp → Open blotter.md
2. **Research**: Deploy parallel research agents → Compile findings
3. **Generate**: Create 5 sector reports using template → Apply formatting
4. **Enhance**: Editor agent review → Citation verification
5. **Analyze**: Cross-sector analysis → Pattern identification
6. **Refine**: Apply cross-sector insights → Final formatting
7. **Complete**: Update blotter.md → Save all reports

---

## 📊 Success Metrics

- Each report 2,500-3,000 words
- Minimum 10 citations per report
- 3+ threat actors per sector
- 5+ specific vulnerabilities analyzed
- 1 tri-partner mention per report (subtle)
- Zero formatting inconsistencies
- 100% source verification

---

*This prompt system ensures consistent, high-quality generation of executive-level cybersecurity intelligence reports that provide genuine value while tastefully promoting the NCC Group tri-partner solution.*