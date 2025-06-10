# Express Attack Brief (EAB) System Documentation
## Unified Format with Full Citations - Version 2.0

**Last Updated:** June 9, 2025  
**System Status:** Enhanced Unified Format Ready  
**Document Length:** 15-18 pages per EAB  

---

## Overview

The Express Attack Brief (EAB) system generates comprehensive threat intelligence documents that serve both executive and technical audiences in a single, well-cited format. This unified approach eliminates the need for manual combination of separate documents while maintaining professional citation standards.

## Key Improvements in v2.0

### 1. **Unified Document Structure**
- Single 18-page document instead of two separate files
- Smooth transition from executive (pages 1-7) to technical content (pages 8-15)
- Comprehensive references section (pages 16-18)

### 2. **Enhanced Citation Framework**
- 40-50 citations per document minimum
- Every claim properly referenced
- Mix of authoritative sources (government, commercial, academic)
- Inline citations linked to references section

### 3. **Evidence-Based Approach**
- Forensic evidence with confidence scoring (High/Medium/Low)
- Source attribution for all technical artifacts
- Chain of custody documentation where applicable

### 4. **Comprehensive Affected Organizations Analysis** (NEW)
- Exhaustive research into 15+ directly affected organizations
- Supply chain and indirect victim identification
- Quantified operational and financial impacts per victim
- Targeting pattern analysis based on victim commonalities
- Separate tables for confirmed vs suspected victims

---

## Quick Start Guide

### To Generate a Unified EAB:

1. **Use the new unified template**:
   ```
   /express_attack_briefs/templates/UNIFIED_EAB_TEMPLATE_WITH_CITATIONS.md
   ```

2. **Apply the enhanced generation prompt**:
   ```
   /express_attack_briefs/templates/UNIFIED_EAB_GENERATION_PROMPT_V2.md
   ```

3. **Provide these inputs**:
   - Threat Actor/Campaign Name
   - Target Sector (Energy/Water/Manufacturing)
   - Geographic Scope
   - Timeline (specific dates)
   - Key CVEs exploited
   - Victim organization types
   - Estimated impact

### Example Generation Command:
```
"Generate a Unified Express Attack Brief for LOCKBIT ransomware targeting manufacturing sector 
in North America from January-March 2025, exploiting CVE-2024-1234, affecting automotive 
manufacturers with $50M+ average impact, using the UNIFIED_EAB_TEMPLATE_WITH_CITATIONS.md"
```

---

## Document Structure

### Executive Sections (Pages 1-7)
1. **Cover & Navigation** - Classification, contents
2. **Executive Summary** - Key findings with citations
3. **Mission Context** - Project Nightingale alignment
4. **Attack Overview** - Timeline and primary vectors
5. **Affected Organizations Analysis** - Comprehensive victim identification (NEW)
6. **Cross-Sector Impact** - Infrastructure cascade analysis

### Technical Sections (Pages 7-15)
6. **Attack Path Analysis** - Phase-by-phase breakdown
7. **Forensic Evidence** - Logs, commands, artifacts
8. **MITRE ATT&CK Mapping** - Complete TTP matrix
9. **Detection Rules** - Sigma, YARA, Snort
10. **Response Procedures** - Immediate to long-term

### Solution & References (Pages 16-18)
11. **Tri-Partner Framework** - NCC + Dragos + Adelard
12. **References** - 40-50 categorized citations
13. **Appendices** - Extended technical details

---

## Citation Standards

### Required Citation Categories:
- **Government Intelligence**: CISA, FBI, NSA alerts
- **Commercial Intelligence**: Dragos, Mandiant reports  
- **Vulnerability Data**: CVE, NVD, vendor advisories
- **Incident Reports**: Breach notifications, IR summaries
- **Technical Standards**: MITRE ATT&CK, NIST frameworks

### Citation Format:
```
[#] Organization, "Document Title," Publication, Date. URL/Source
```

### Confidence Levels:
- **High**: Multiple sources, direct evidence, government confirmation
- **Medium**: Single authoritative source, behavioral correlation
- **Low**: Unconfirmed reports, circumstantial evidence

### CRITICAL DATA INTEGRITY RULES:
1. **NEVER fabricate statistics or numbers** - All quantitative data must come from cited sources
2. **Use exact figures from sources** - If a source says "approximately 50," don't write "48" or "52"
3. **Qualify uncertain data** - Use "approximately," "estimated," "reported" when sources are unclear
4. **Range when uncertain** - If sources conflict, provide range: "$10-15M reported losses [[source1], [source2]]"
5. **Acknowledge gaps** - Write "Financial impact: Not publicly disclosed" rather than guessing
6. **Source every number** - Every percentage, dollar amount, timeframe, and count needs a citation

---

## Quality Checklist

Before finalizing any Unified EAB, verify:

- [ ] 40+ citations throughout document
- [ ] Executive summary accessible to C-suite
- [ ] Technical sections actionable for SOC teams
- [ ] All MITRE techniques properly referenced
- [ ] Forensic evidence includes source attribution
- [ ] Detection rules syntactically correct
- [ ] Mission context woven throughout
- [ ] Tri-partner value clearly demonstrated
- [ ] Cross-sector impacts analyzed
- [ ] Timeline consistency maintained

---

## Benefits of Unified Format

1. **No Manual Combination Needed** - Single generation produces complete document
2. **Consistent Narrative** - One story from executive to technical
3. **Better Flow** - Natural progression of detail levels
4. **Reduced Errors** - No copy/paste mistakes
5. **Professional Output** - Academic-quality citations
6. **Time Savings** - ~2 hours saved per EAB

---

## Migration from Dual Format

If you have existing dual-format EABs:
1. Use executive brief for pages 1-6 content
2. Use technical analysis for pages 7-15 content  
3. Add citation references throughout
4. Merge into unified template
5. Validate with quality checklist

---

## Support Resources

- **Template**: `/templates/UNIFIED_EAB_TEMPLATE_WITH_CITATIONS.md`
- **Prompt**: `/templates/UNIFIED_EAB_GENERATION_PROMPT_V2.md`
- **Examples**: See `/final_products/` for completed unified EABs
- **Research**: Use MCP Tavily for citation gathering
- **Validation**: Enhanced methodology comparative analysis

---

## Future Enhancements

### Planned for v3.0:
- Automated citation gathering via MCP
- Dynamic length adjustment (12-20 pages)
- Sector-specific template variants
- Multi-language support
- Interactive web version

### Under Consideration:
- AI-assisted evidence correlation
- Real-time threat feed integration
- Automated quality scoring
- Client branding options

---

**For questions or improvements, contact the Project Nightingale Intelligence Team**

*"Clean water, reliable energy, and access to healthy food for our grandchildren"*