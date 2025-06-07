# Intelligence Pipeline - Local Data Management

## 🚨 CRITICAL: .gitignore Configuration

The following directories are **EXCLUDED** from git commits and contain local-only data:

```
intelligence/external_sources/    # Large GitHub repositories (100MB+ datasets)
intelligence/current/            # Real-time threat intelligence (refreshed automatically)
```

**These directories are automatically generated and should NOT be committed to version control.**

## 📋 Intelligence Directory Structure

```
intelligence/
├── README_INTELLIGENCE_PIPELINE.md     # This file
├── current/                            # ❌ GITIGNORED - Auto-generated current intel
│   ├── advisories/                     # CISA KEV and security advisories
│   ├── threats/                        # Current OT/ICS threats
│   ├── vulnerabilities/                # Real-time vulnerability data
│   ├── incidents/                      # Recent industrial incidents
│   └── regulatory/                     # Compliance updates
├── external_sources/                   # ❌ GITIGNORED - GitHub repositories
│   ├── awesome_annual_reports/         # 377+ annual security reports
│   ├── cisa_vulnrichment/             # 98,681 CISA vulnerability files
│   ├── cybersecurity_papers/          # Academic research papers
│   └── [other repositories]/          # Additional external sources
├── foundation/                         # ✅ COMMITTED - Theme intelligence indexes
│   ├── SCV_supply_chain_vulnerability/ # Supply chain theme data
│   ├── ITC_itot_convergence/          # IT/OT convergence theme data
│   └── [8 other themes]/              # Service specialization themes
├── partnerships/                       # ✅ COMMITTED - Partner summaries only
│   ├── dragos/current/                # Dragos intelligence summaries
│   ├── adelard/current/               # Adelard safety methodologies
│   └── ncc_otce/current/              # NCC OTCE capabilities
└── scripts/                           # ✅ COMMITTED - Automation scripts
    ├── enhanced_intelligence_pipeline.sh
    ├── generate_themed_prospect.sh
    └── collect_prospect_vulnerability_intel.sh
```

## 🔄 Intelligence Refresh Process

### **Quick Refresh** (5 minutes - Weekly recommended)
```bash
cd /home/jim/gtm-campaign-project
./intelligence/scripts/enhanced_intelligence_pipeline.sh --quick
```

**What it does:**
- Updates CISA KEV database from official feeds
- Collects current OT/ICS threats via MCP Tavily
- Refreshes industrial incident reports  
- Updates compliance and regulatory advisories

### **Full Pipeline Refresh** (15-20 minutes - Monthly recommended)
```bash
cd /home/jim/gtm-campaign-project
./intelligence/scripts/enhanced_intelligence_pipeline.sh --full
```

**What it does:**
- **Phase 1**: GitHub repository updates (external_sources/)
  - awesome-annual-security-reports
  - CISA vulnrichment (98,681 files)
  - cybersecurity-papers collection
  - ICS/OT security resources
- **Phase 2**: Partner intelligence collection (partnerships/)
  - Dragos threat intelligence updates
  - Adelard safety methodologies
  - NCC OTCE capabilities
- **Phase 3**: Current advisories refresh (current/)
  - Same as quick refresh but more comprehensive
- **Phase 4**: Theme curation (foundation/)
  - Processes all sources for 9 service themes
  - Updates vulnerability counts and relevance

### **On-Demand Prospect Intelligence** (2-3 minutes per prospect)
```bash
./intelligence/scripts/collect_prospect_vulnerability_intel.sh [COMPANY_NAME] [THEME]
```

**What it does:**
- Company-specific vulnerability analysis
- Theme-aligned threat intelligence
- Industry-focused current events
- Tri-partner opportunity assessment

## 🎯 Data Sources Summary

### **Layer 1: Foundation Intelligence** (Pre-curated)
- **377 Annual Reports** (2021-2025) categorized by theme
- **98,681 CISA vulnerability files** from vulnrichment repository
- **Academic papers** and cybersecurity datasets
- **Partner intelligence** (Dragos, Adelard, NCC OTCE)

### **Layer 2: Current Intelligence** (Auto-updated)
- **CISA KEV database** (14 data files, updated weekly)
- **Current threat feeds** via MCP Tavily
- **Industry-specific vulnerability tracking**
- **Partner capability updates**

### **Layer 3: Prospect-Specific Intelligence** (On-demand)
- **Company-specific vulnerability analysis**
- **Theme-aligned threat intelligence** 
- **Industry-focused current events**
- **Tri-partner opportunity assessment**

## 🔧 Technical Implementation

### **MCP Tools Used:**
- `mcp__tavily__tavily-search` - AI-powered threat intelligence
- `mcp__fetch__fetch_json` - CISA data feeds
- `mcp__brave__brave_web_search` - Supplementary research

### **Automation Scripts:**
- **enhanced_intelligence_pipeline.sh** - Master collection script
- **generate_themed_prospect.sh** - Single-command prospect generation
- **collect_prospect_vulnerability_intel.sh** - Company-specific analysis

### **Theme Specialization:**
- **SCV** - Supply Chain Vulnerability (98,342 vulnerabilities)
- **ITC** - IT/OT Convergence Security (46,033 vulnerabilities)  
- **IEC** - IEC 62443 Compliance (10 vulnerabilities)
- **LCR** - Legacy Codebase Risk (223 vulnerabilities)
- **PLM** - Product Lifecycle Monitoring (4,304 vulnerabilities)
- **SCA** - Safety Case Analysis (27 vulnerabilities)
- **NVC** - Network Visibility & Compliance (169 vulnerabilities)
- **RIA** - Ransomware Impact Assessment (240 vulnerabilities)
- **MDA** - M&A Due Diligence (98,676 vulnerabilities)

## 📊 Data Freshness Requirements

### **Critical (Update Weekly):**
- CISA KEV database
- Current OT/ICS threats
- Industrial incident reports

### **Important (Update Monthly):**
- GitHub repositories
- Partner intelligence
- Academic papers

### **Stable (Update Quarterly):**
- Annual security reports
- Foundation theme curation
- Academic datasets

## ⚠️ Important Notes

1. **Never commit intelligence/current/** - Contains 100MB+ of real-time data
2. **Never commit intelligence/external_sources/** - Contains full GitHub repositories
3. **Foundation and partnerships directories** contain summaries only and are committed
4. **All scripts are version controlled** for reproducible intelligence gathering
5. **Run quick refresh weekly** to maintain current threat intelligence
6. **Run full refresh monthly** to update all sources comprehensively

## 🚀 Quick Start

```bash
# Initial setup (one-time)
cd /home/jim/gtm-campaign-project
./intelligence/scripts/enhanced_intelligence_pipeline.sh --full

# Weekly maintenance 
./intelligence/scripts/enhanced_intelligence_pipeline.sh --quick

# Generate new prospect with theme specialization
./intelligence/scripts/generate_themed_prospect.sh A-999999 "Example Company" SCV Manufacturing
```

## 📈 Intelligence Statistics

**Total Sources**: 100,406+ automated intelligence sources operational
- Foundation intelligence: 377 annual reports + 98,681 CISA files
- Current intelligence: Real-time feeds via MCP
- Theme specialization: 9 service themes with vulnerability mapping
- Partner integration: Dragos + Adelard + NCC OTCE

**Generated fresh intelligence every 7 days to support Project Nightingale's mission of ensuring "clean water, reliable energy, and access to healthy food for our grandchildren."**