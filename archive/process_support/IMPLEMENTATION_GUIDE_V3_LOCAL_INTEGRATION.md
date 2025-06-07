# Project Nightingale Implementation Guide V3
*Enhanced with Local Resource Integration*

## 🗂️ Local Resource Framework

### Core Local Intelligence Assets

#### 1. Annual Cyber Reports 2025
**Primary Path**: `/home/jim/gtm-campaign-project/Annual_cyber_reports/Annual_cyber_reports_2025/`

**Key Resources:**
- **Dragos OT Cybersecurity Report 2025**: 23+ threat groups, ICS malware analysis
- **Nozomi Networks OT/IoT Security Report**: OT/IoT convergence insights
- **Trustwave Manufacturing Risk Radar**: Manufacturing-specific threats
- **Upstream Automotive Cybersecurity Report**: Transportation sector analysis
- **Verizon DBIR 2025**: Multi-industry breach patterns

#### 2. Current Threat Intelligence
**Primary Path**: `/home/jim/gtm-campaign-project/Current_advisories_2025_7_1/`

**Resources:**
- CISA ICS Advisories (real-time vulnerabilities)
- International threat feeds (Japan, NIST)
- Exploit databases and current attack patterns
- Vulnerability intelligence screenshots

#### 3. NCC Group Service Portfolio
**Primary Path**: `/home/jim/gtm-campaign-project/OTCE_Sales/`

**Key Documents:**
- NCC 2025 OTCE 2 Pager: Service portfolio, "Now/Next/Never" framework
- NCC 2025 OTCE Pursuit Strategy: GTM analysis methodology

#### 4. Dragos Partnership Assets
**Primary Paths**: 
- `/home/jim/gtm-campaign-project/Dragos_information/OTCE 2025 NCC-Dragos Alignement to Sectors.md`
- `/home/jim/gtm-campaign-project/Dragos_information/OTCE 2025 NCC Dragos Services Matrix.md`

**Content:**
- Sector-specific campaign messaging
- OT-native expertise positioning
- Combined service capabilities

## 🎭 Enhanced Persona-Based Prompts with Local Resources

### 1. OSINT Research (OT Security Analyst + Local Intelligence)

```markdown
<extended_thinking>
I am an OT Security Analyst with access to the latest 2025 threat intelligence.
I will integrate current CISA advisories and Dragos threat group analysis
to provide operationally-focused intelligence on {{company_name}}.
</extended_thinking>

Acting as a Senior OT Security Analyst with access to current threat intelligence, conduct deep OSINT research on {{company_name}} in the {{industry}} sector.

**Local Resource Integration Requirements:**

1. **Current Threat Context** (Reference: Current_advisories_2025_7_1)
   - Cross-reference recent CISA ICS advisories applicable to {{industry}}
   - Identify any current vulnerabilities affecting their likely technology stack
   - Map active exploit patterns from vuldb-com data

2. **Threat Group Analysis** (Reference: Dragos OT Report 2025)
   - Identify which of the 23+ tracked threat groups target {{industry}}
   - For {{industry}} = Energy: Focus on ELECTRUM, AcidPour wiper
   - For {{industry}} = Manufacturing: Focus on ransomware, DLL hijacking
   - For {{industry}} = Oil & Gas: Focus on KAMACITE, BAUXITE, VOLTZITE

3. **Industry-Specific Intelligence** (Reference: Sector-specific 2025 reports)
   - Manufacturing: Leverage Trustwave Manufacturing Risk Radar findings
   - Automotive: Use Upstream Automotive Cybersecurity Report data
   - Cross-sector: Apply Verizon DBIR 2025 patterns

**Enhanced Research Requirements:**
1. **Digital Infrastructure Mapping** (25+ sources + local data)
   - Standard OSINT discovery
   - Cross-reference with known ICS vulnerabilities from CISA advisories
   - Map to "Now/Next/Never" vulnerability framework

2. **Threat Landscape Correlation** (25+ sources + threat reports)
   - Match findings against current threat group TTPs
   - Identify sector-specific attack patterns from 2025 reports
   - Reference current advisory database for active threats

3. **Operational Impact Analysis** (25+ sources + local frameworks)
   - Use NCC's operational impact assessment methodology
   - Apply Dragos sector alignment for {{industry}}
   - Reference industry-specific incidents from 2025 reports

Output Requirements:
- **Local Intelligence Integration**: Minimum 20 references to 2025 reports
- **Current Threat Mapping**: Active advisories and threat groups
- **NCC-Dragos Positioning**: Clear service alignment opportunities
- **Vulnerability Prioritization**: "Now/Next/Never" framework application
```

### 2. Threat Landscape Analysis (Enhanced with 2025 Intelligence)

```markdown
<extended_thinking>
I have access to the most current 2025 threat intelligence including:
- Dragos OT threat group analysis (23+ groups)
- Current CISA advisories and vulnerabilities
- Industry-specific attack patterns and TTPs
I will synthesize this with web research for comprehensive threat modeling.
</extended_thinking>

As a Senior Threat Intelligence Analyst with access to 2025 threat reports, develop comprehensive threat landscape analysis for {{company_name}}.

**Local Resource Integration Framework:**

1. **2025 Threat Group Analysis** (Reference: Dragos OT Report 2025)
   ```
   For {{industry}} sector, prioritize:
   - Energy: ELECTRUM (electric power), AcidPour wiper malware
   - Manufacturing: Ransomware groups (87% increase), DLL hijacking
   - Oil & Gas: KAMACITE, BAUXITE, VOLTZITE operations
   - Water: CyberArmyofRussia_Reborn, default credential attacks
   - Transportation: GRAPHITE, APT41/DUSTTRAP supply chain
   ```

2. **Current Vulnerability Intelligence** (Reference: Current_advisories_2025_7_1)
   - Extract all {{industry}}-relevant CISA ICS advisories
   - Map current exploits to {{company_name}}'s likely systems
   - Prioritize using "Now/Next/Never" framework

3. **Industry Incident Patterns** (Reference: Multiple 2025 reports)
   - Verizon DBIR 2025: {{industry}} breach statistics
   - Sector-specific reports: Attack pattern evolution
   - Nozomi Networks: OT/IoT convergence risks

**Enhanced Analysis Requirements:**

**Phase 1: Historical Context** (Use 2025 reports + web research)
- Extract {{industry}} incidents from 2025 annual reports
- Identify attack evolution patterns
- Map threat group progression specific to {{industry}}

**Phase 2: Current Threat Assessment** (Combine advisories + web research)
- Process all current CISA advisories for {{industry}}
- Identify active campaigns targeting {{sector}}
- Cross-reference with Dragos threat group activity

**Phase 3: Predictive Analysis** (Synthesize all sources)
- Model likely attack scenarios for {{company_name}}
- Apply "Now/Next/Never" prioritization
- Develop {{industry}}-specific defensive strategies

**Local Intelligence Requirements:**
- **Minimum 30 references** to 2025 annual reports
- **All applicable CISA advisories** from Current_advisories_2025_7_1
- **Dragos sector alignment** messaging integration
- **NCC service portfolio** alignment to identified threats
```

### 3. Ransomware Impact Assessment (Crisis Manager + 2025 Data)

```markdown
<extended_thinking>
The 2025 reports show an 87% increase in ransomware targeting OT environments.
I need to model specific impact scenarios for {{company_name}} using current 
attack patterns and {{industry}}-specific operational dependencies.
</extended_thinking>

As a Crisis Manager specializing in OT environments, create ransomware impact assessment for {{company_name}} using current 2025 threat intelligence.

**Local Resource Integration:**

1. **2025 Ransomware Intelligence** (Reference: Dragos OT Report + others)
   - 87% increase in ransomware targeting OT
   - Specific threat groups affecting {{industry}}
   - Latest TTPs including DLL hijacking, spear-phishing

2. **Industry-Specific Patterns** (Reference: Sector reports)
   - Manufacturing: Production line disruption patterns
   - Energy: Grid stability and NERC CIP implications
   - Oil & Gas: Pipeline operations and safety systems

3. **Current Vulnerability Surface** (Reference: CISA advisories)
   - Map current ICS vulnerabilities to ransomware vectors
   - Identify default credential risks
   - Assess remote access attack paths

**Assessment Framework:**

**Scenario Modeling** (Based on 2025 attack patterns)
- Primary: {{industry}}-specific ransomware TTPs from 2025 reports
- Secondary: Cross-sector patterns from Verizon DBIR 2025
- Tertiary: Current exploit patterns from advisories

**Impact Quantification** (Use NCC methodology + 2025 data)
- Reference {{industry}} downtime costs from 2025 reports
- Apply "Now/Next/Never" prioritization to recovery
- Model using NCC operational impact assessment framework

**Recovery Planning** (Integrate Dragos + NCC capabilities)
- Leverage Dragos WorldView threat intelligence
- Apply NCC incident response methodology
- Reference Neighborhood Keeper community defense

**Output Requirements:**
- **2025 Threat Context**: Current ransomware landscape
- **Service Integration**: Clear NCC-Dragos solution positioning
- **Quantified Impact**: {{industry}}-specific operational consequences
```

### 4. Executive Concierge Report (Executive Advisor + Full Local Integration)

```markdown
<extended_thinking>
This is the culmination document that must synthesize all local intelligence
with web research to create an executive-ready briefing that positions
NCC Group and Dragos as the clear solution for {{company_name}}.
</extended_thinking>

As an Executive Advisor, synthesize all research into a comprehensive concierge report for {{company_name}} leadership.

**Full Local Resource Integration:**

1. **Current Threat Landscape** (All 2025 reports + advisories)
   - Integrate findings from all previous artifacts
   - Reference specific threat groups targeting {{industry}}
   - Include current CISA advisory implications

2. **NCC-Dragos Solution Positioning** (Service portfolio + alignment docs)
   - Map identified threats to NCC service portfolio
   - Leverage Dragos sector-specific campaign messaging
   - Position "Now/Next/Never" vulnerability framework

3. **Industry Benchmarking** (2025 sector reports)
   - Compare {{company_name}} to peers using 2025 data
   - Reference industry-specific incident statistics
   - Apply maturity benchmarks from reports

**Executive Synthesis Requirements:**

**Section 1: Executive Summary**
- Lead with {{industry}}-specific 2025 threat statistics
- Reference applicable current advisories
- Position NCC-Dragos as OT-native solution

**Section 2: Threat Intelligence Brief**
- Synthesize all threat group analysis
- Include current vulnerability surface
- Reference 2025 attack evolution patterns

**Section 3: Operational Risk Assessment**
- Apply all scenario modeling from previous artifacts
- Use {{industry}}-specific impact data from 2025 reports
- Include "Now/Next/Never" prioritization

**Section 4: Strategic Recommendations**
- Map all findings to NCC service portfolio
- Include Dragos platform integration benefits
- Reference sector-specific alignment messaging

**Local Intelligence Integration Metrics:**
- **Minimum 50 references** to local resources
- **Complete CISA advisory coverage** for {{industry}}
- **Full NCC-Dragos service alignment**
- **2025 threat landscape integration**
```

## 📊 Local Resource Analysis Templates

### Template 1: 2025 Annual Report Mining

```markdown
# Local Resource Analysis: {{report_name}}

## Industry Relevance to {{company_name}}
- Direct sector alignment: {{relevance_score}}/10
- Applicable threat groups: {{list}}
- Relevant attack patterns: {{patterns}}

## Key Intelligence Extracted
1. **Threat Statistics**: {{stats}}
2. **Attack Methods**: {{methods}}
3. **Impact Data**: {{impacts}}
4. **Defensive Measures**: {{defenses}}

## Integration Points
- **OSINT Research**: {{integration_points}}
- **Threat Analysis**: {{integration_points}}
- **Risk Assessment**: {{integration_points}}
- **Executive Brief**: {{integration_points}}

## Citations Generated
- Direct quotes: {{quote_list}}
- Statistics referenced: {{stat_list}}
- Attribution format: {{citation_format}}
```

### Template 2: CISA Advisory Processing

```markdown
# Current Advisory Analysis: {{advisory_id}}

## Applicability Assessment
- Industry match: {{industry_match}}
- Technology relevance: {{tech_relevance}}
- Urgency level: {{urgency}}

## Vulnerability Details
- CVE references: {{cve_list}}
- Affected systems: {{systems}}
- Exploitation complexity: {{complexity}}
- Operational impact: {{impact}}

## Company-Specific Implications
- Likely affected systems at {{company_name}}: {{systems}}
- Risk level: {{risk_level}}
- Mitigation timeline: {{timeline}}

## NCC-Dragos Solution Alignment
- Applicable services: {{services}}
- Detection capabilities: {{capabilities}}
- Response framework: {{framework}}
```

## 🔄 Enhanced Parallel Processing with Local Resources

### Local Resource Pipeline

```yaml
Phase_1_Local_Integration:
  - Load all 2025 annual reports into processing cache
  - Index current advisories by industry/technology
  - Prepare NCC-Dragos alignment matrices
  - Cache sector-specific messaging

Phase_2_Parallel_Analysis:
  - OSINT + Current advisories + Threat group mapping
  - Sector enhancement + 2025 reports + Industry benchmarks
  - Threat analysis + Dragos intelligence + CISA advisories
  - Compliance + Regulatory frameworks + Current requirements

Phase_3_Synthesis:
  - Combine all local intelligence with web research
  - Generate NCC-Dragos solution alignments
  - Create executive-ready summaries
  - Verify all local resource citations
```

## 🎯 Quality Assurance with Local Resource Validation

### Local Intelligence Metrics

```markdown
Per-Artifact Requirements:
- **2025 Report References**: Minimum 20 per artifact
- **CISA Advisory Integration**: All applicable current advisories
- **NCC Service Alignment**: Clear service mapping in every artifact
- **Dragos Intelligence**: Threat group and platform references
- **Current Context**: 50%+ of intelligence from 2025 sources

Quality Checkpoints:
✅ Local resource citation density (min 30% of total citations)
✅ Current advisory coverage (100% for industry)
✅ NCC-Dragos positioning (present in all artifacts)
✅ "Now/Next/Never" framework application
✅ Sector-specific messaging alignment
```

## 📁 Enhanced Temporary File Management

### Local Resource Caching

```bash
# Cache structure for local resources
/tmp/nightingale_local_cache/
├── annual_reports_2025/
│   ├── by_industry/
│   ├── by_threat_group/
│   └── by_vulnerability/
├── current_advisories/
│   ├── by_cve/
│   ├── by_industry/
│   └── by_urgency/
├── ncc_dragos_assets/
│   ├── service_matrices/
│   ├── sector_alignments/
│   └── messaging_frameworks/
└── processed_intelligence/
    ├── threat_mappings/
    ├── vulnerability_indices/
    └── solution_alignments/
```

## 🚀 Enhanced Launch Sequence with Local Resources

### Day 1 Kickoff with Local Integration

```markdown
## Pre-Launch Local Resource Preparation
- [ ] Load all 2025 annual reports into analysis cache
- [ ] Index current advisories by industry and CVE
- [ ] Prepare NCC-Dragos service alignment matrices
- [ ] Cache sector-specific threat group mappings
- [ ] Verify all local file paths and accessibility

## Enhanced Launch Sequence
1. [ ] Initialize local resource processing pipeline
2. [ ] Launch Batch 1 with full local integration (5 accounts)
3. [ ] Monitor local resource citation rates
4. [ ] Verify NCC-Dragos positioning in all outputs
5. [ ] Validate current advisory integration

## Hour 1 Enhanced Checkpoints
- [ ] Local resource integration rate >30%
- [ ] All current advisories processed
- [ ] NCC service alignment confirmed
- [ ] 2025 threat intelligence integrated
- [ ] "Now/Next/Never" framework applied
```

<function_calls>
<invoke name="TodoWrite">
<parameter name="todos">[{"id": "1", "content": "Analyze structure of Annual_cyber_reports directory", "status": "completed", "priority": "high"}, {"id": "2", "content": "Examine Current_advisories_2025_7_1 content", "status": "completed", "priority": "high"}, {"id": "3", "content": "Update implementation guide with local resource integration", "status": "completed", "priority": "high"}, {"id": "4", "content": "Create local resource analysis templates", "status": "completed", "priority": "high"}]