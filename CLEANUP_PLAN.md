# Project Nightingale Cleanup Plan

## 🗑️ Files/Folders to Remove (Deprecated/Scattered)

### Scattered Exelon Files (Move to organized structure)
```bash
# Root level scattered files - MOVE to proper location
/home/jim/gtm-campaign-project/exelon-strategic-sales-approach.md
/home/jim/gtm-campaign-project/exelon-executive-summary.md
/home/jim/gtm-campaign-project/exelon-battle-card.md
/home/jim/gtm-campaign-project/exelon-executive-concierge-report.md
/home/jim/gtm-campaign-project/exelon-sector-analysis.md
/home/jim/gtm-campaign-project/exelon-executive-briefing.md
/home/jim/gtm-campaign-project/exelon-technical-infrastructure-analysis.md

# Scattered analysis folders - CONSOLIDATE
/home/jim/gtm-campaign-project/exelon-compliance-research/
/home/jim/gtm-campaign-project/assessments/exelon-energy/
/home/jim/gtm-campaign-project/analysis/
/home/jim/gtm-campaign-project/m-and-a-analysis/exelon-energy/
/home/jim/gtm-campaign-project/exelon-analysis/
```

### Incomplete/Failed OSINT Reports (Remove)
```bash
# These were the shallow versions before proper GTM framework
/home/jim/gtm-campaign-project/prospects/A-020265_Exelon_Energy/phase1_intelligence/osint_research.md
/home/jim/gtm-campaign-project/prospects/A-019227_Duke_Energy_Corporation/phase1_intelligence/osint_research.md
/home/jim/gtm-campaign-project/prospects/A-075450_Southern_California_Edison/phase1_intelligence/osint_research.md
/home/jim/gtm-campaign-project/prospects/A-037323_PGE_Pacific_Gas_Electric/phase1_intelligence/osint_research.md
/home/jim/gtm-campaign-project/prospects/A-018829_Puget_Sound_Energy/phase1_intelligence/osint_research.md
```

### Temporary/Working Files (Remove)
```bash
/home/jim/gtm-campaign-project/Exelon_Energy_GTM_Part1_Organization_Leadership_Profile.md
/home/jim/gtm-campaign-project/evergy-sector-analysis.md
/home/jim/gtm-campaign-project/evergy-nightingale-strategic-brief.md
/home/jim/gtm-campaign-project/evergy-analysis-appendix.md
```

## 📁 Proposed Organized Folder Structure

```
/home/jim/gtm-campaign-project/
├── 📋 project_management/
│   ├── FINAL_ENHANCED_IMPLEMENTATION_PLAN.md
│   ├── ENHANCED_OSINT_RESEARCH_PLAN.md
│   ├── SESSION_1_EXECUTION_TRACKER.md
│   ├── PROJECT_CLEANUP_AND_OPTIMIZATION.md
│   └── OSINT_EXECUTION_DOCUMENTATION.md
│
├── 📚 reference_materials/
│   ├── gtm_strategy/
│   │   └── Project_Nightingalle_GTM_Exec_Brief_Update.md
│   ├── best_practices/
│   │   ├── Claude_4_Best_Practices-2025-5-30.md
│   │   └── Deep_Research_Process_used_by_Gemini_Deep_Research.md
│   ├── ncc_services/
│   │   └── OTCE_Sales/ (existing folder)
│   ├── partner_assets/
│   │   └── Dragos_information/ (existing folder)
│   └── intelligence_sources/
│       ├── Annual_cyber_reports/ (existing folder)
│       └── Current_advisories_2025_7_1/ (existing folder)
│
├── 🎯 prospects/
│   └── A-020265_Exelon_Energy/ ⭐ EXEMPLAR COMPLETE
│       ├── 📊 gtm_analysis/
│       │   ├── gtm_part1_organization_profile.md
│       │   ├── gtm_part2_technical_infrastructure.md
│       │   └── gtm_part3_strategic_sales_approach.md
│       ├── 🔍 intelligence_analysis/
│       │   ├── local_intelligence_integration.md
│       │   ├── sector_enhancement.md
│       │   ├── threat_landscape_analysis.md
│       │   └── regulatory_compliance_research.md
│       ├── 📋 campaign_themes/
│       │   ├── ransomware_impact_assessment.md
│       │   └── ma_due_diligence_analysis.md
│       ├── 📄 executive_deliverable/
│       │   └── executive_concierge_report.md
│       └── 🔗 quick_reference/
│           ├── battle_card.md
│           ├── key_contacts.md
│           └── engagement_timeline.md
│
├── 📝 templates/ (Generated from Exelon exemplar)
│   ├── gtm_templates/
│   ├── intelligence_templates/
│   ├── campaign_templates/
│   └── executive_templates/
│
└── 🚀 execution_logs/
    ├── SESSION_1_PROGRESS_TRACKER.md
    └── session_archives/
```

## 📋 Cleanup Actions Required

### 1. Remove Deprecated Files
```bash
# Remove shallow OSINT reports
rm /home/jim/gtm-campaign-project/prospects/*/phase1_intelligence/osint_research.md

# Remove temporary working files
rm /home/jim/gtm-campaign-project/*exelon*.md
rm /home/jim/gtm-campaign-project/*evergy*.md

# Remove scattered directories
rm -rf /home/jim/gtm-campaign-project/analysis/
rm -rf /home/jim/gtm-campaign-project/assessments/
rm -rf /home/jim/gtm-campaign-project/exelon-*/
rm -rf /home/jim/gtm-campaign-project/m-and-a-analysis/
```

### 2. Create New Structure
```bash
# Create organized folders
mkdir -p project_management reference_materials templates execution_logs
mkdir -p reference_materials/{gtm_strategy,best_practices,ncc_services,partner_assets,intelligence_sources}
mkdir -p templates/{gtm_templates,intelligence_templates,campaign_templates,executive_templates}
```

### 3. Organize Exelon Exemplar
```bash
# Reorganize Exelon folder structure
mkdir -p prospects/A-020265_Exelon_Energy/{gtm_analysis,intelligence_analysis,campaign_themes,executive_deliverable,quick_reference}
```

### 4. Move Reference Materials
```bash
# Move core reference docs to proper locations
mv "Project Nightingalle GTM Exec Brief Update.md" reference_materials/gtm_strategy/
mv "Claude 4 Best Practices-2025-5-30.md" reference_materials/best_practices/
```

## ✅ Benefits of New Structure

1. **Clear Separation**: Project management vs. execution vs. reference
2. **Scalable**: Easy to replicate for 54 remaining accounts
3. **Organized**: Each account follows same structure
4. **Accessible**: Quick reference materials separate from detailed analysis
5. **Professional**: Client-ready organization for deliverables
6. **Maintainable**: Easy to update and manage artifacts

**Ready to execute cleanup and create organized structure?**