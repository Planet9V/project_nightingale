# Affected Organizations Research Prompt
## Comprehensive Victim Identification for EABs

**Created:** June 9, 2025  
**Purpose:** Systematic research methodology for identifying all organizations affected by threats  
**Quality Standard:** Exhaustive victim analysis with full attribution  

---

## Master Research Prompt for Affected Organizations

```markdown
OBJECTIVE: Conduct exhaustive research to identify ALL organizations directly and indirectly affected by [THREAT_NAME]. This research is CRITICAL for understanding the true scope and impact of the threat.

RESEARCH METHODOLOGY:

## Phase 1: Direct Victim Identification

### 1.1 Primary Search Queries (Use MCP Tavily/Web Search):
- "[THREAT_NAME] victims list complete"
- "[THREAT_NAME] affected companies organizations"  
- "[THREAT_NAME] ransomware attack victims"
- "[THREAT_NAME] breach notification [YEAR]"
- "[THREAT_NAME] incident response [Company Names]"
- "[THREAT_NAME] data breach settlement"
- "[THREAT_NAME] cyber insurance claim"

### 1.2 Sector-Specific Searches:
- "[THREAT_NAME] energy sector victims"
- "[THREAT_NAME] manufacturing attacks"
- "[THREAT_NAME] water utility breach"
- "[THREAT_NAME] food processing ransomware"
- "[THREAT_NAME] critical infrastructure"

### 1.3 Financial Disclosure Searches:
- "SEC 8-K cybersecurity incident [DATE_RANGE]"
- "material breach disclosure [SECTOR] [DATE_RANGE]"
- "[THREAT_NAME] financial impact millions"
- "cyber incident operational disruption [SECTOR]"

### 1.4 Technical Indicator Searches:
- "[CVE-NUMBER] exploitation victims"
- "[SPECIFIC_IOC] compromised organizations"
- "[THREAT_NAME] IOC sightings companies"

## Phase 2: Victim Data Collection

For EACH identified victim, collect:

### 2.1 Basic Information:
- Full organization name and any subsidiaries affected
- Primary business sector and sub-sector
- Headquarters location and affected facilities
- Company size (revenue, employees)
- Date of initial compromise
- Date of discovery/disclosure
- Current status (recovered, recovering, ongoing)

### 2.2 Impact Metrics:
- Operational impact description (specific systems, duration)
- Financial impact (ransom paid, recovery costs, lost revenue)
- Data impact (records stolen, systems encrypted)
- Recovery timeline (days/weeks to restore operations)
- Long-term effects (credit monitoring, lawsuits, regulatory)

### 2.3 Evidence Sources:
- Primary source (news article, press release, SEC filing)
- Secondary sources for corroboration
- Technical reports confirming attribution
- Government advisories mentioning the victim

## Phase 3: Indirect Victim Identification

### 3.1 Supply Chain Research:
For each major direct victim, search:
- "[VICTIM_NAME] supply chain disruption cyber"
- "[VICTIM_NAME] customer impact ransomware"
- "[VICTIM_NAME] partner notification breach"
- "[VICTIM_NAME] vendor relationships"

### 3.2 Business Impact Searches:
- "[VICTIM_NAME] production halt customers affected"
- "[VICTIM_NAME] service outage impact"
- "companies affected by [VICTIM_NAME] breach"

### 3.3 Industry Analysis:
- Review industry reports for cascade effects
- Search trade publications for partner impacts
- Check regulatory filings for disclosed dependencies

## Phase 4: Validation and Verification

### 4.1 Attribution Confidence:
Rate each victim identification as:
- **Confirmed**: Multiple sources, official confirmation
- **High Confidence**: Technical evidence, single authoritative source
- **Medium Confidence**: Behavioral correlation, timing match
- **Low Confidence**: Circumstantial evidence only

### 4.2 Cross-Reference Validation:
- Compare victim lists across multiple sources
- Verify dates align with campaign timeline
- Confirm technical indicators match
- Validate sector targeting patterns

## Phase 5: Pattern Analysis

### 5.1 Victim Commonalities:
Analyze all victims for:
- Geographic clustering
- Sector concentrations  
- Technology stack similarities
- Revenue/size thresholds
- Security maturity indicators
- Business relationship networks

### 5.2 Targeting Intelligence:
Document:
- Clear selection criteria used by threat actor
- Preferential targeting patterns
- Avoidance patterns (who wasn't targeted and why)
- Evolution of targeting over time

## OUTPUT REQUIREMENTS:

### Table 1: Confirmed Direct Victims (10-15 minimum)
Must include ALL columns:
- Organization Name
- Sector & Sub-sector  
- Geographic Location
- Impact Date
- Operational Impact (specific)
- Financial Loss (with source)
- Recovery Time  
- Evidence Source [Citation]

### Table 2: Suspected Victims (5-10)
Must include:
- Organization Name
- Sector
- Matching Indicators
- Confidence Level
- Investigation Status
- Source [Citation]

### Table 3: Supply Chain Victims
For each primary victim show:
- Primary Victim Name
- 3-5 Affected Partners (named)
- Impact Type
- Business Disruption Description
- Combined Financial Impact
- Recovery Status

### Analysis Section:
- Comprehensive targeting pattern analysis
- Sector breakdown with percentages
- Common vulnerability/technology analysis
- Geographic distribution map (description)
- Lessons learned from victim analysis

CRITICAL REMINDERS:
- Aim for COMPLETENESS - find every possible victim
- Include organizations even if impact details are limited
- Use date ranges that encompass the full campaign
- Search in multiple languages if threat is global
- Check regional/local news sources, not just major outlets
- Review IR vendor blogs for customer case studies
- Search cybersecurity conference presentations for victim stories

QUALITY CHECK:
- Minimum 15 total organizations identified
- At least 10 with quantified impact data
- Multiple sectors represented
- Supply chain impacts documented
- All claims properly cited
```

---

## Automated Research Enhancement

### For MCP Tool Users:
```
Use Tavily/Brave search with these parameters:
- Time range: Last [X] months
- Include news, blogs, reports, SEC filings
- Search each query variant
- Compile comprehensive victim list
- Extract all quantitative impact data
- Gather multiple sources per victim
```

### Victim Research Checklist:
- [ ] 10+ confirmed direct victims identified
- [ ] 5+ suspected victims with indicators
- [ ] Supply chain impacts documented
- [ ] Financial impact data for majority
- [ ] Recovery timelines included
- [ ] All sectors analyzed
- [ ] Pattern analysis completed
- [ ] 40+ citations for victim data
- [ ] Confidence levels assigned
- [ ] Validation completed

---

**Remember**: The Affected Organizations Analysis is often the MOST VALUABLE section of an EAB for readers who want to understand real-world impact and assess their own risk. Make it comprehensive, well-researched, and data-rich.