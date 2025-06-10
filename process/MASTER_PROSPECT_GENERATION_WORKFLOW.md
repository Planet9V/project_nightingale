# MASTER PROSPECT GENERATION WORKFLOW
## Project Nightingale - Systematic Process for New Prospect Addition

**Document Status**: Core Process Documentation  
**Created**: January 7, 2025  
**Purpose**: Complete workflow for adding new prospects with systematic artifact generation  
**Target User**: Claude Code AI for automated prospect processing  
**Quality Standard**: 100% completion rate with executive-level quality  

---

## 🎯 **WORKFLOW OVERVIEW**

This workflow enables systematic addition of new prospects to Project Nightingale with complete artifact generation, proper file placement, and quality assurance. Each new prospect follows this exact process to ensure consistency and completeness.

### **Success Criteria**
- ✅ 10 standardized artifacts generated per prospect
- ✅ All files properly named and placed
- ✅ Quality standards met for executive presentation
- ✅ Enhanced intelligence integration completed
- ✅ OT-First positioning integrated throughout

---

## 📋 **PHASE 1: PROSPECT INITIALIZATION**

### **Step 1.1: Gather Prospect Information**
**Required Information**:
- Company Name (exact legal name)
- Account ID (format: A-######)
- Industry/Sector classification
- Primary Account Manager assignment
- Geographic location/headquarters

**Input Format**:
```
PROSPECT: [Company Name]
ACCOUNT_ID: A-######
INDUSTRY: [Energy/Manufacturing/Transportation/etc.]
ACCOUNT_MANAGER: [AM Name]
LOCATION: [City, State/Country]
```

### **Step 1.2: Create Directory Structure**
**Command Sequence**:
```bash
# Create prospect directory
mkdir -p "/home/jim/gtm-campaign-project/prospects/[ACCOUNT_ID]_[Company_Name_No_Spaces]/"

# Navigate to directory
cd "/home/jim/gtm-campaign-project/prospects/[ACCOUNT_ID]_[Company_Name_No_Spaces]/"

# Create tracking file
echo "PROSPECT: [Company Name]" > PROSPECT_INFO.md
echo "ACCOUNT_ID: [Account ID]" >> PROSPECT_INFO.md
echo "STATUS: INITIATED - $(date)" >> PROSPECT_INFO.md
echo "INDUSTRY: [Industry]" >> PROSPECT_INFO.md
echo "ACCOUNT_MANAGER: [AM Name]" >> PROSPECT_INFO.md
```

**Example**:
```bash
mkdir -p "/home/jim/gtm-campaign-project/prospects/A-999999_Example_Corporation/"
cd "/home/jim/gtm-campaign-project/prospects/A-999999_Example_Corporation/"
```

---

## 🔍 **PHASE 2: MANDATORY TIER 1 MCP RESEARCH COLLECTION**

⚠️ **CRITICAL**: MCP research is MANDATORY and cannot be skipped. This is the default framework for ALL prospect artifact generation.

### **Step 2.1: Execute Mandatory MCP-Powered Research (TIER 1 DEFAULT)**
**Research Collection Sequence** (MANDATORY - Not Optional):

#### **2.1a: Primary OSINT Research (MANDATORY TIER 1)**
```bash
# MANDATORY MCP RESEARCH EXECUTION - NEVER SKIP
echo "🔍 TIER 1: Executing mandatory MCP research..."
mcp__tavily__tavily-search query="[Company Name] cybersecurity operational technology infrastructure energy sector"
mcp__brave__brave_web_search query="[Company Name] industrial technology security threats SCADA control systems"
mcp__fetch__fetch_markdown url="[Company Official Website]"
echo "✅ TIER 1: Primary research completed"
```

#### **2.1b: Enhanced Intelligence Integration (MANDATORY TIER 1)**
```bash
# Current threat intelligence - MANDATORY
echo "🔍 TIER 1: Collecting current threat intelligence..."
mcp__tavily__tavily-search query="[Company Name] [Industry] cyber threats 2025 CISA advisories"
mcp__brave__brave_web_search query="[Company Name] recent cybersecurity incidents vulnerabilities"

# Industry-specific intelligence - MANDATORY
mcp__tavily__tavily-search query="[Industry] sector cybersecurity threats 2025 NERC CIP FERC"
echo "✅ TIER 1: Intelligence integration completed"
```

#### **2.1c: Regulatory and Compliance Research (MANDATORY TIER 1)**
```bash
# Regulatory environment - MANDATORY
echo "🔍 TIER 1: Collecting regulatory compliance intelligence..."
mcp__tavily__tavily-search query="[Company Name] regulatory compliance NERC CIP nuclear safety"
mcp__brave__brave_web_search query="[Company Name] regulatory violations fines compliance challenges"
echo "✅ TIER 1: Regulatory research completed"
echo "🎯 TIER 1: All mandatory MCP research phases complete - ready for artifact generation"
```

**TIER 1 Research Quality Target**: 400-600 lines of comprehensive intelligence per research file (Enhanced with MCP data)

### **Step 2.2: Create Research Documentation**
**File Creation**:
```bash
# Create research file
touch "[Company_Name]_Research_Collection_$(date +%Y%m%d).md"

# Add research header
cat > "[Company_Name]_Research_Collection_$(date +%Y%m%d).md" << 'EOF'
# [Company Name] - Comprehensive Research Collection
## Project Nightingale Enhanced Intelligence Integration

**Research Date**: $(date)
**Research Quality**: [Target 400-600 lines]
**Intelligence Sources**: MCP Tavily + Brave + Direct Fetch
**Enhancement Integration**: Enhanced EAB Methodology + 9-Theme Specialization

---

[PASTE RESEARCH RESULTS HERE]
EOF
```

---

## 🎯 **PHASE 3: 9-THEME SERVICE SPECIALIZATION**

### **Step 3.1: Theme Classification**
**Theme Analysis Framework**:
Based on research findings, classify prospect into primary service theme:

| **Theme Code** | **Service Theme** | **Industry Alignment** |
|----------------|-------------------|------------------------|
| **SCV** | Supply Chain Vulnerability | Manufacturing, Technology |
| **IEC** | IEC 62443 Compliance | Process Industries, Chemical |
| **ITC** | IT/OT Convergence Security | Energy, Utilities, Smart Grid |
| **LCR** | Legacy Codebase Risk | Transportation, Defense |
| **PLM** | Product Lifecycle Monitoring | Manufacturing, Automotive |
| **SCA** | Safety Case Analysis | Nuclear, Chemical, Critical Infrastructure |
| **NVC** | Network Visibility & Compliance | All sectors with OT networks |
| **RIA** | Ransomware Impact Assessment | Universal (all prospects) |
| **MDA** | M&A Due Diligence | All sectors with M&A activity |

### **Step 3.2: Document Theme Selection**
```bash
# Create theme classification file
cat > "PROSPECT_THEME_CLASSIFICATION.md" << 'EOF'
# [Company Name] - Service Theme Classification
## Project Nightingale 9-Theme Specialization

**Primary Theme**: [THEME_CODE] - [Theme Name]
**Secondary Theme**: [THEME_CODE] - [Theme Name] (if applicable)
**Rationale**: [Why this theme fits based on research]
**Theme Integration Points**: [How to integrate throughout artifacts]

**Universal Themes Applied**:
- ✅ RIA (Ransomware Impact Assessment) - Universal baseline
- ✅ MDA (M&A Due Diligence) - Universal baseline

---

**Theme-Specific Enhancement Strategy**:
[Details on how theme will enhance standard artifacts]
EOF
```

---

## 📄 **PHASE 4: SYSTEMATIC ARTIFACT GENERATION**

### **Step 4.1: Use Enhanced Templates with Theme Integration**
**Template Source**: `/templates/PROJECT_NIGHTINGALE_ENHANCED_TEMPLATES.md`  
**Enhancement**: Layer theme-specific positioning throughout each artifact

### **Step 4.2: Artifact Generation Sequence**
**Generate in this exact order for quality dependencies**:

#### **4.2a: Foundational Artifacts (Research-Based)**
1. **GTM Part 1: Organization Profile**
   - **Prompt Source**: Enhanced Template Section 1
   - **Enhancement**: Theme-specific operational focus
   - **File Name**: `[Company_Name]_GTM_Part_1_Organization_Profile_Project_Nightingale.md`

2. **GTM Part 2: Operational Analysis**
   - **Prompt Source**: Enhanced Template Section 2
   - **Enhancement**: Theme-aligned operational challenges
   - **File Name**: `[Company_Name]_GTM_Part_2_Operational_Analysis_Strategic_Sales_Intelligence_Project_Nightingale.md`

3. **GTM Part 3: Decision-Maker Profiles**
   - **Prompt Source**: Enhanced Template Section 3
   - **Enhancement**: Theme-specific stakeholder focus
   - **File Name**: `[Company_Name]_GTM_Part_3_Decision_Maker_Profiles_Engagement_Strategy_Project_Nightingale.md`

#### **4.2b: Intelligence-Enhanced Artifacts**
4. **Local Intelligence Integration**
   - **Prompt Source**: Enhanced Template Section 4 + Current Advisory Integration
   - **Enhancement**: CISA KEV database + 2025 threat intelligence
   - **File Name**: `[Company_Name]_Local_Intelligence_Integration_Project_Nightingale.md`

5. **Threat Landscape Analysis**
   - **Prompt Source**: Enhanced Template Section 6 + Enhanced EAB Methodology
   - **Enhancement**: 67% quality improvement framework integration
   - **File Name**: `[Company_Name]_Threat_Landscape_Analysis_Project_Nightingale.md`

6. **Sector Enhancement Analysis**
   - **Prompt Source**: Enhanced Template Section 5 + Theme Specialization
   - **Enhancement**: Primary theme positioning and value proposition
   - **File Name**: `[Company_Name]_Sector_Enhancement_Analysis_Project_Nightingale.md`

#### **4.2c: Compliance and Risk Artifacts**
7. **Regulatory Compliance Research**
   - **Prompt Source**: Enhanced Template Section 10 + Theme-Specific Regulations
   - **Enhancement**: Theme-aligned compliance requirements
   - **File Name**: `[Company_Name]_Regulatory_Compliance_Research_Project_Nightingale.md`

8. **Ransomware Impact Assessment**
   - **Prompt Source**: Enhanced Template Section 8 + Universal RIA Framework
   - **Enhancement**: Operational impact with theme considerations
   - **File Name**: `[Company_Name]_Ransomware_Impact_Assessment_Project_Nightingale.md`

9. **M&A Due Diligence Analysis**
   - **Prompt Source**: Enhanced Template Section 9 + Universal MDA Framework
   - **Enhancement**: Theme-specific due diligence considerations
   - **File Name**: `[Company_Name]_M&A_Due_Diligence_Analysis_Project_Nightingale.md`

#### **4.2d: Executive Synthesis**
10. **Executive Concierge Report**
    - **Prompt Source**: Enhanced Template Section 4 + All Previous Artifacts
    - **Enhancement**: C-suite positioning with theme value proposition
    - **File Name**: `[Company_Name]_Executive_Concierge_Report_Project_Nightingale.md`

---

## 🔍 **PHASE 5: ENHANCED EAB INTEGRATION (OPTIONAL)**

### **Step 5.1: Generate Express Attack Brief (If Current Threat Available)**
**When to Generate**: If current, relevant threat activity identified in research

**EAB Generation Process**:
1. **Identify Current Threat**: From research or current intelligence
2. **Generate Dual EAB**: Using Enhanced EAB Methodology (67% quality improvement)
   - **Executive Optimized Brief**: For C-suite audience
   - **Technical Analysis**: For SOC/technical teams
3. **Place in Prospect Directory**: Add to artifact set as bonus intelligence

**File Names**:
- `[Company_Name]_EAB_[Threat_Name]_Executive_Brief_Project_Nightingale.md`
- `[Company_Name]_EAB_[Threat_Name]_Technical_Analysis_Project_Nightingale.md`

---

## ✅ **PHASE 6: QUALITY ASSURANCE & VERIFICATION**

### **Step 6.1: Artifact Completion Verification**
**Checklist Verification**:
```bash
# Run completion check
echo "=== ARTIFACT COMPLETION VERIFICATION ==="
echo "Prospect: [Company Name]"
echo "Directory: $(pwd)"
echo ""
echo "Required Artifacts (10):"
ls -1 *GTM_Part_1* && echo "✅ GTM Part 1" || echo "❌ GTM Part 1 MISSING"
ls -1 *GTM_Part_2* && echo "✅ GTM Part 2" || echo "❌ GTM Part 2 MISSING"
ls -1 *GTM_Part_3* && echo "✅ GTM Part 3" || echo "❌ GTM Part 3 MISSING"
ls -1 *Local_Intelligence* && echo "✅ Local Intelligence" || echo "❌ Local Intelligence MISSING"
ls -1 *Threat_Landscape* && echo "✅ Threat Landscape" || echo "❌ Threat Landscape MISSING"
ls -1 *Sector_Enhancement* && echo "✅ Sector Enhancement" || echo "❌ Sector Enhancement MISSING"
ls -1 *Regulatory_Compliance* && echo "✅ Regulatory Compliance" || echo "❌ Regulatory Compliance MISSING"
ls -1 *Ransomware_Impact* && echo "✅ Ransomware Impact" || echo "❌ Ransomware Impact MISSING"
ls -1 *M*A_Due_Diligence* && echo "✅ M&A Due Diligence" || echo "❌ M&A Due Diligence MISSING"
ls -1 *Executive_Concierge* && echo "✅ Executive Concierge" || echo "❌ Executive Concierge MISSING"
echo ""
echo "Total Files: $(ls -1 *.md | wc -l)"
```

### **Step 6.2: Quality Standards Verification**
**Quality Checklist**:
- [ ] **OT-First Positioning**: All artifacts emphasize operational excellence over traditional cybersecurity
- [ ] **Project Nightingale Mission**: "Clean water, reliable energy, healthy food for our grandchildren" integrated
- [ ] **Tri-Partner Solution**: NCC OTCE + Dragos + Adelard positioning throughout
- [ ] **Theme Integration**: Primary service theme consistently applied
- [ ] **Current Intelligence**: 2025 threat intelligence and CISA KEV integration
- [ ] **Executive Quality**: C-level presentation standards maintained
- [ ] **Operational Context**: Company-specific operational challenges addressed

### **Step 6.3: Final Status Update**
```bash
# Update prospect status
echo "STATUS: COMPLETED - $(date)" >> PROSPECT_INFO.md
echo "ARTIFACTS: 10/10 COMPLETE" >> PROSPECT_INFO.md
echo "QUALITY: VERIFIED" >> PROSPECT_INFO.md
echo "THEME: [PRIMARY_THEME]" >> PROSPECT_INFO.md
echo "ENHANCEMENT: Enhanced EAB + 9-Theme + Intelligence Integration" >> PROSPECT_INFO.md
```

---

## 📊 **WORKFLOW SUCCESS METRICS**

### **Completion Standards**
- ✅ **10/10 artifacts generated** for each prospect
- ✅ **Consistent file naming** according to established conventions
- ✅ **Proper directory placement** in `/prospects/[Account_ID]_[Company_Name]/`
- ✅ **Quality verification** completed with checklist
- ✅ **Theme classification** documented and applied
- ✅ **Enhanced intelligence integration** throughout all artifacts

### **Expected Timeline**
- **Research Collection**: 30-45 minutes
- **Theme Classification**: 10-15 minutes  
- **Artifact Generation**: 60-90 minutes
- **Quality Verification**: 15-20 minutes
- **Total Time**: 2-3 hours per prospect

### **Quality Benchmarks**
- **Research Quality**: 400-600 lines of comprehensive intelligence
- **Artifact Quality**: Executive-level presentation standards
- **Consistency**: Matches existing 49/49 completed prospects
- **Enhancement Integration**: 100% theme and intelligence integration

---

## 🚀 **NEXT STEPS AFTER COMPLETION**

### **Account Manager Handoff**
1. **Notify Assigned AM**: Send completion notification
2. **Provide Artifact Summary**: Brief overview of key findings and positioning
3. **Theme Strategy Brief**: Primary theme application strategy
4. **OT-First Positioning**: Key operational excellence messaging

### **Campaign Integration**
1. **Landing Page Assignment**: Match to appropriate campaign theme
2. **Consultation Preparation**: 15-minute expert consultation materials ready
3. **Nurture Sequence**: Three-part progression content available
4. **EAB Integration**: Enhanced Express Attack Brief if generated

---

## 📚 **REFERENCE DOCUMENTS**

### **Supporting Process Documents**
- **Artifact Generation Reference**: `/process/ARTIFACT_GENERATION_REFERENCE.md`
- **New Prospect Checklist**: `/process/NEW_PROSPECT_CHECKLIST.md`
- **File Organization Standards**: `/process/FILE_ORGANIZATION_STANDARDS.md`
- **Enhanced Templates**: `/templates/PROJECT_NIGHTINGALE_ENHANCED_TEMPLATES.md`

### **Quality and Framework References**
- **Enhanced EAB Methodology**: `/express_attack_briefs/EXPRESS_ATTACK_BRIEF_SYSTEM_DOCUMENTATION.md`
- **15-Minute Consultation Framework**: `/consultation_frameworks_2025/15_Minute_Expert_Consultation_Master_Framework.md`
- **Theme Specialization**: `/templates/SERVICE_THEME_FRAMEWORK.md`
- **Intelligence Integration**: `/process/IMPLEMENTATION_GUIDE_V3_LOCAL_INTEGRATION.md`

---

**WORKFLOW SUCCESS**: This systematic process ensures 100% completion rate with consistent quality standards, matching the proven success of the existing 49/49 completed prospects while enhancing with new intelligence capabilities and theme specialization.

**NEXT ENHANCEMENT**: OT-First Engagement Process Flow artifact integration for complete campaign readiness.