# FILE ORGANIZATION STANDARDS
## Project Nightingale - Systematic Directory Structure & Naming Conventions

**Document Status**: Core Process Documentation  
**Created**: January 7, 2025  
**Purpose**: Comprehensive file organization standards for consistent placement and naming  
**Target User**: Claude Code AI for systematic file management  
**Reference**: Based on existing 49/49 completed prospects and established patterns  

---

## 🎯 **ORGANIZATION OVERVIEW**

Project Nightingale maintains systematic file organization to ensure consistency, accessibility, and quality across all prospects. These standards are derived from the proven structure of 49/49 completed prospects and enhanced with systematic process documentation.

### **Core Principles**
- ✅ **Consistent Naming**: Standardized conventions across all files and directories
- ✅ **Logical Hierarchy**: Clear directory structure for easy navigation
- ✅ **Predictable Placement**: Files placed in documented, expected locations
- ✅ **Quality Maintenance**: Organization supports systematic quality verification
- ✅ **Enhancement Integration**: Structure accommodates local knowledge integration

---

## 📁 **DIRECTORY STRUCTURE STANDARDS**

### **Root Project Structure**
```
/home/jim/gtm-campaign-project/
├── prospects/                           🎯 [PROSPECT ARTIFACTS - PRIMARY DELIVERABLES]
├── process/                            📋 [PROCESS DOCUMENTATION - WORKFLOWS & STANDARDS]
├── templates/                          📄 [TEMPLATES & FRAMEWORKS]
├── prospect_research/                  🔍 [RESEARCH COLLECTION FILES]
├── intelligence/                       🧠 [THREAT INTELLIGENCE & ACTOR PROFILES]
├── Annual_cyber_reports/              📊 [ANNUAL THREAT REPORTS 2021-2024]
├── sector_intelligence_reports/       🏭 [FLAGSHIP INDUSTRY REPORTS]
├── Dragos_information/                🛡️ [OT-SPECIFIC INTELLIGENCE & SECTOR ALIGNMENT]
├── OTCE_Sales/                        💼 [NCC GROUP OTCE SERVICE PORTFOLIO]
├── support_threat_analysis/           ⚠️ [THREAT MODELING & ANALYSIS SUPPORT]
├── support_mitre/                     🎯 [MITRE ATT&CK RESOURCES & EAB METHODOLOGY]
├── express_attack_briefs/             📡 [ENHANCED EAB SYSTEM & PRODUCTION BRIEFS]
├── consultation_frameworks_2025/      🗣️ [15-MINUTE EXPERT CONSULTATION FRAMEWORK]
├── landing_pages_2025/                🌐 [CAMPAIGN LANDING PAGES]
├── reference_materials/               📚 [BEST PRACTICES & CLAUDE CODE OPTIMIZATION]
└── Project_nightingale_process_start_here/ 🚀 [ORIGINAL PLAYBOOKS & PROSPECT LISTS]
```

---

## 📂 **PROSPECT DIRECTORY STANDARDS**

### **Directory Naming Convention**
**Format**: `A-[ACCOUNT_ID]_[Company_Name_No_Spaces]/`

**Examples**:
```
A-008302_US_Sugar/
A-018814_Boeing_Corporation/
A-037323_PGE_Pacific_Gas_Electric/
A-110670_San_Francisco_International_Airport_Corp/
```

**Naming Rules**:
- ✅ **Account ID**: Always starts with `A-` followed by 6-digit number
- ✅ **Company Name**: Remove spaces, replace with underscores
- ✅ **Legal Accuracy**: Use exact legal entity name where possible
- ✅ **Length Management**: Truncate if extremely long but maintain clarity
- ✅ **Special Characters**: Remove parentheses, commas, periods, ampersands (replace & with _and_)

### **Prospect Directory Contents**
**Standard Structure** (10 Required Artifacts + Optional Files):
```
A-[ACCOUNT_ID]_[Company_Name]/
├── [Company_Name]_GTM_Part_1_Organization_Profile_Project_Nightingale.md
├── [Company_Name]_GTM_Part_2_Operational_Analysis_Strategic_Sales_Intelligence_Project_Nightingale.md
├── [Company_Name]_GTM_Part_3_Decision_Maker_Profiles_Engagement_Strategy_Project_Nightingale.md
├── [Company_Name]_Local_Intelligence_Integration_Project_Nightingale.md
├── [Company_Name]_Threat_Landscape_Analysis_Project_Nightingale.md
├── [Company_Name]_Sector_Enhancement_Analysis_Project_Nightingale.md
├── [Company_Name]_Regulatory_Compliance_Research_Project_Nightingale.md
├── [Company_Name]_Ransomware_Impact_Assessment_Project_Nightingale.md
├── [Company_Name]_M&A_Due_Diligence_Analysis_Project_Nightingale.md (Note: M&A or MA variations accepted)
├── [Company_Name]_Executive_Concierge_Report_Project_Nightingale.md
├── 
├── [OPTIONAL PROCESS FILES]
├── PROSPECT_INFO.md                    🆕 [PROSPECT TRACKING & STATUS]
├── PROSPECT_THEME_CLASSIFICATION.md    🆕 [9-THEME SERVICE SPECIALIZATION]
├── [Company_Name]_Research_Collection_[Date].md 🆕 [ENHANCED RESEARCH DOCUMENTATION]
└── [Enhanced EAB files if applicable] 🆕 [CURRENT THREAT INTELLIGENCE BRIEFS]
```

---

## 📝 **FILE NAMING CONVENTIONS**

### **Standard Artifact Naming Pattern**
**Format**: `[Company_Name]_[Artifact_Type]_Project_Nightingale.md`

**Component Breakdown**:
- **Company_Name**: Consistent with directory name (no spaces, underscores)
- **Artifact_Type**: Standardized descriptor for each of 10 artifacts
- **Project_Nightingale**: Universal identifier for all campaign artifacts
- **Extension**: Always `.md` for markdown format

### **Artifact Type Standards**
| **Artifact** | **Standard Naming** | **Variations Allowed** |
|--------------|-------------------|----------------------|
| **GTM Part 1** | `GTM_Part_1_Organization_Profile` | `GTM_Part1_Organization_Profile` |
| **GTM Part 2** | `GTM_Part_2_Operational_Analysis_Strategic_Sales_Intelligence` | `GTM_Part2_Operational_Analysis` |
| **GTM Part 3** | `GTM_Part_3_Decision_Maker_Profiles_Engagement_Strategy` | `GTM_Part3_Decision_Maker_Profiles` |
| **Local Intelligence** | `Local_Intelligence_Integration` | `Local_Intelligence` |
| **Threat Landscape** | `Threat_Landscape_Analysis` | `Threat_Analysis` |
| **Sector Enhancement** | `Sector_Enhancement_Analysis` | `Sector_Analysis` |
| **Regulatory Compliance** | `Regulatory_Compliance_Research` | `Compliance_Research` |
| **Ransomware Impact** | `Ransomware_Impact_Assessment` | `Ransomware_Assessment` |
| **M&A Due Diligence** | `M&A_Due_Diligence_Analysis` | `MA_Due_Diligence_Analysis` |
| **Executive Concierge** | `Executive_Concierge_Report` | `Concierge_Report` |

### **Enhanced Process File Naming**
**New Standards for Enhanced Workflow**:
```
PROSPECT_INFO.md                        # Prospect tracking and status
PROSPECT_THEME_CLASSIFICATION.md        # 9-theme service specialization
[Company_Name]_Research_Collection_[YYYYMMDD].md  # Enhanced research documentation
[Company_Name]_EAB_[Threat_Name]_Executive_Brief_Project_Nightingale.md     # Optional EAB executive
[Company_Name]_EAB_[Threat_Name]_Technical_Analysis_Project_Nightingale.md  # Optional EAB technical
```

---

## 🔍 **RESEARCH COLLECTION STANDARDS**

### **Prospect Research Directory**
**Location**: `/prospect_research/`  
**Purpose**: Comprehensive OSINT research files for prospects  
**Naming**: `prospect_research_[company_name_lowercase].md`

**Examples**:
```
prospect_research_boeing.md
prospect_research_us_sugar.md
prospect_research_pacific_gas_and_electric.md
prospect_research_san_francisco_international_airport.md
```

**Content Standards**:
- ✅ **Quality Target**: 400-600 lines of comprehensive intelligence
- ✅ **MCP Integration**: Research collected using Tavily + Brave + Fetch tools
- ✅ **Local Knowledge**: 30%+ content from local intelligence resources
- ✅ **Current Intelligence**: 2025 threat data and regulatory information
- ✅ **Enhancement Ready**: Prepared for artifact generation integration

---

## 📋 **PROCESS DOCUMENTATION STANDARDS**

### **Process Directory Organization**
**Location**: `/process/`  
**Structure**:
```
/process/
├── MASTER_PROSPECT_GENERATION_WORKFLOW.md     🎯 [PRIMARY WORKFLOW GUIDE]
├── NEW_PROSPECT_CHECKLIST.md                  ✅ [66-CHECKPOINT VERIFICATION]
├── FILE_ORGANIZATION_STANDARDS.md             📁 [THIS DOCUMENT]
├── ARTIFACT_GENERATION_REFERENCE.md           📄 [PROMPT-TO-ARTIFACT MAPPING] (Future)
├── 
├── [ENHANCED EXISTING DOCUMENTS]
├── IMPLEMENTATION_GUIDE_V3_LOCAL_INTEGRATION.md  ✅ [LOCAL RESOURCE FRAMEWORK]
├── STREAMLINED_ARTIFACT_CREATION_GUIDE.md       ✅ [EFFICIENCY OPTIMIZATION]
├── SESSION_HANDOFF_GUIDE.md                     ✅ [SESSION CONTINUITY]
├── 
└── [ORGANIZED SUBDIRECTORIES]
    ├── documentation/                          📋 [PROJECT OVERVIEWS]
    ├── reports/                               📊 [COMPLETION REPORTS]
    ├── startup/                               🚀 [ORIGINAL PLAYBOOKS]
    └── support_materials/                     📚 [REFERENCE MATERIALS]
```

---

## 📄 **TEMPLATE ORGANIZATION STANDARDS**

### **Template Directory Structure**
**Location**: `/templates/`  
**Organization**:
```
/templates/
├── PROJECT_NIGHTINGALE_ENHANCED_TEMPLATES.md   🎯 [PRIMARY TEMPLATE FRAMEWORK]
├── MASTER_TEMPLATE_INDEX.md                    📋 [COMPREHENSIVE TEMPLATE CATALOG]
├── 
├── [SERVICE THEME TEMPLATES] (Future Enhancement)
├── service_themes/                             🏭 [9-THEME SPECIALIZATION TEMPLATES]
│   ├── SCV_supply_chain_vulnerability.md       
│   ├── IEC_62443_compliance.md                 
│   └── [Additional theme templates...]         
├── 
├── [EXPRESS ATTACK BRIEF TEMPLATES]
├── EXPRESS_ATTACK_BRIEF_GENERATION_PROMPT.md   📡 [EAB GENERATION FRAMEWORK]
├── EXPRESS_ATTACK_BRIEF_TEMPLATE_FRAMEWORK.md  📡 [EAB TEMPLATE STRUCTURE]
├── EXPRESS_ATTACK_BRIEF_DUAL_GENERATION_SYSTEM.md 📡 [DUAL SYSTEM FRAMEWORK]
├── 
└── [SPECIALIZED FRAMEWORKS]
    ├── PROSPECT_THEME_CLASSIFICATION.md        🎯 [THEME SELECTION FRAMEWORK]
    ├── SERVICE_THEME_ANALYSIS.md               🏭 [THEME ANALYSIS FRAMEWORK]
    └── THEME_INTELLIGENCE_FRAMEWORK.md         🧠 [INTELLIGENCE INTEGRATION]
```

---

## 🧠 **INTELLIGENCE RESOURCE ORGANIZATION**

### **Enhanced Intelligence Pipeline Structure**
Based on existing directory organization with systematic access patterns:

#### **Primary Intelligence Sources**
```
/Annual_cyber_reports/Annual_cyber_reports_2024/    📊 [377+ ANNUAL REPORTS]
├── Industry-specific threat intelligence by year
├── Naming: [Vendor]-[Report-Title]-[Year].md
└── Usage: Industry context and current threat landscape

/intelligence/                                      🧠 [THREAT INTELLIGENCE PIPELINE]  
├── threat-actor-profiles.md                       🎯 [CONSOLIDATED THREAT ACTORS]
├── README_INTELLIGENCE_PIPELINE.md                📋 [PIPELINE DOCUMENTATION]
└── Usage: Current threat actor mapping and TTPs

/sector_intelligence_reports/                       🏭 [FLAGSHIP INDUSTRY REPORTS]
├── Energy_Utilities_Intelligence_Report_2025.md   ⚡ [ENERGY SECTOR FLAGSHIP]
└── Usage: Industry-specific positioning and insights
```

#### **Partner Intelligence Sources**
```
/Dragos_information/                               🛡️ [OT-SPECIFIC INTELLIGENCE]
├── OTCE 2025 NCC-Dragos Alignement to Sectors.md  🎯 [SECTOR ALIGNMENT]
├── OTCE 2025 NCC Dragos Services Matrix.md        📋 [SERVICE INTEGRATION]
├── 2024 GTM Dragos Analysis.md                    📊 [GTM ANALYSIS]
└── Usage: OT-first positioning and threat intelligence

/OTCE_Sales/                                       💼 [NCC GROUP OTCE PORTFOLIO]
├── NCC 2025 OTCE 2 Pager.v1.md                   📄 [SERVICE OVERVIEW]
├── NCC 2025 OTCE Pursuit Straegy 2025.md         🎯 [PURSUIT STRATEGY]
├── NCC 2025 OTCE-Adelard Battlecard.v1.md        ⚔️ [COMPETITIVE POSITIONING]
└── Usage: Service positioning and sales strategy
```

#### **Technical Support Resources**
```
/support_mitre/                                    🎯 [MITRE ATT&CK RESOURCES]
├── PROJECT_NIGHTINGALE_MITRE_ATTCK_CHEAT_SHEET.md 📋 [QUICK REFERENCE]
├── PROJECT_NIGHTINGALE_ENHANCED_EAB_METHODOLOGY_MASTER.md 🚀 [ENHANCED METHODOLOGY]
├── [01-07]_MITRE_ATTCK_[Topic].md                 📚 [COMPREHENSIVE GUIDES]
└── Usage: Technical accuracy and Enhanced EAB methodology

/support_threat_analysis/                          ⚠️ [THREAT MODELING SUPPORT]
├── Industry-specific threat analysis reports      🏭 [SECTOR-SPECIFIC MODELING]
├── OT Security expert essays and market research  📊 [EXPERT ANALYSIS]
└── Usage: Industry-specific threat modeling and positioning

/reference_materials/                              📚 [BEST PRACTICES]
└── Claude Code optimization and best practices    🤖 [AI OPTIMIZATION]
```

---

## ✅ **QUALITY ASSURANCE STANDARDS**

### **File Verification Requirements**
**For Each New Prospect Directory**:
- [ ] **Directory Naming**: Follows A-[ID]_[Company_Name] convention
- [ ] **Artifact Count**: Contains exactly 10 primary artifacts
- [ ] **Naming Consistency**: All files follow naming standards
- [ ] **Process Files**: Contains PROSPECT_INFO.md and PROSPECT_THEME_CLASSIFICATION.md
- [ ] **Research Integration**: Enhanced research collection documented
- [ ] **Quality Standards**: All files meet executive-level presentation requirements

### **Verification Commands**
```bash
# Directory structure verification
cd /home/jim/gtm-campaign-project/prospects/[ACCOUNT_ID]_[Company_Name]/
pwd  # Confirm correct directory

# File count verification  
ls -1 *.md | wc -l  # Should show 12+ files (10 artifacts + process files)

# Naming convention verification
ls -1 *Project_Nightingale.md | wc -l  # Should show 10 artifacts

# Process file verification
ls -1 PROSPECT_*.md  # Should show PROSPECT_INFO.md and PROSPECT_THEME_CLASSIFICATION.md

# Research file verification (if applicable)
ls -1 *Research_Collection*.md  # Should show enhanced research documentation
```

---

## 🚀 **ENHANCEMENT INTEGRATION STANDARDS**

### **New File Types for Enhanced Workflow**
Based on enhanced process documentation:

#### **Prospect Tracking Files**
```
PROSPECT_INFO.md                               🏷️ [PROSPECT METADATA & STATUS]
├── Contains: Account info, status, completion tracking
├── Format: Key-value pairs with timestamps
└── Usage: Progress tracking and handoff information

PROSPECT_THEME_CLASSIFICATION.md               🎯 [SERVICE THEME SPECIALIZATION]
├── Contains: Primary theme, rationale, integration strategy
├── Format: Structured analysis with theme mapping
└── Usage: Theme specialization and artifact enhancement
```

#### **Enhanced Research Documentation**
```
[Company_Name]_Research_Collection_[YYYYMMDD].md  🔍 [COMPREHENSIVE RESEARCH]
├── Contains: MCP research + local knowledge integration
├── Format: 400-600 lines with source attribution
├── Quality: 30%+ local knowledge integration
└── Usage: Foundation for all artifact generation
```

#### **Optional Enhanced EAB Files**
```
[Company_Name]_EAB_[Threat_Name]_Executive_Brief_Project_Nightingale.md     📡 [EXECUTIVE EAB]
[Company_Name]_EAB_[Threat_Name]_Technical_Analysis_Project_Nightingale.md  🔧 [TECHNICAL EAB]
├── Contains: Current threat intelligence with Enhanced EAB methodology
├── Format: Dual-audience approach (Executive + Technical)
├── Quality: 67% quality improvement standard
└── Usage: Current threat positioning and technical credibility
```

---

## 📊 **COMPLIANCE WITH EXISTING PATTERNS**

### **Validated Against 49/49 Completed Prospects**
These standards are derived from analysis of existing completed prospects:

**Observed Patterns** (Maintained in Standards):
- ✅ **Directory Naming**: A-[ID]_[Company] pattern 100% consistent
- ✅ **Artifact Naming**: [Company]_[Type]_Project_Nightingale.md pattern
- ✅ **File Count**: 10 primary artifacts per prospect (some with 11+ including extras)
- ✅ **Naming Variations**: Some acceptable variations in artifact type naming
- ✅ **Quality Consistency**: Executive-level presentation standards maintained

**Enhancements Added** (New to Standards):
- 🆕 **Process Files**: PROSPECT_INFO.md and PROSPECT_THEME_CLASSIFICATION.md
- 🆕 **Research Documentation**: Enhanced research collection files
- 🆕 **Local Knowledge Integration**: Systematic use of intelligence resources
- 🆕 **Quality Gates**: 66-checkpoint verification system
- 🆕 **Theme Specialization**: 9-theme service specialization framework

---

## 🎯 **IMPLEMENTATION GUIDANCE**

### **For New Prospect Addition**
1. **Follow Master Workflow**: Use `/process/MASTER_PROSPECT_GENERATION_WORKFLOW.md`
2. **Use Verification Checklist**: Follow `/process/NEW_PROSPECT_CHECKLIST.md` (66 checkpoints)
3. **Apply File Standards**: Use this document for naming and placement guidance
4. **Verify Organization**: Run verification commands to confirm compliance
5. **Document Quality**: Ensure all files meet executive-level presentation standards

### **For Existing Prospect Enhancement**
1. **Assess Current Structure**: Compare against these standards
2. **Add Missing Process Files**: Create PROSPECT_INFO.md and PROSPECT_THEME_CLASSIFICATION.md
3. **Enhance with Local Knowledge**: Integrate intelligence resources where beneficial
4. **Verify Compliance**: Ensure naming and organization meets standards
5. **Maintain Quality**: Preserve executive-level presentation standards

---

## 📚 **REFERENCE AND MAINTENANCE**

### **Related Documentation**
- **Master Workflow**: `/process/MASTER_PROSPECT_GENERATION_WORKFLOW.md`
- **Verification Checklist**: `/process/NEW_PROSPECT_CHECKLIST.md`
- **Template Framework**: `/templates/PROJECT_NIGHTINGALE_ENHANCED_TEMPLATES.md`
- **Template Index**: `/templates/MASTER_TEMPLATE_INDEX.md`
- **Implementation Guide**: `/process/IMPLEMENTATION_GUIDE_V3_LOCAL_INTEGRATION.md`

### **Maintenance Protocol**
- **Regular Review**: Assess standards against new prospect completions
- **Pattern Updates**: Update standards based on successful implementations
- **Quality Evolution**: Enhance standards as quality frameworks improve
- **Documentation Sync**: Keep all process documents aligned with current standards

---

**ORGANIZATION SUCCESS**: These comprehensive standards ensure consistent, high-quality file organization while supporting the enhanced workflow capabilities and local knowledge integration that distinguish Project Nightingale's systematic approach to prospect development.