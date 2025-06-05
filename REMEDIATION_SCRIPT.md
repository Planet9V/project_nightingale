# GTM Campaign Project - Remediation Script

## File Organization and Naming Corrections

### 1. EXELON ENERGY (A-020265) - File Renaming

Files to rename for consistency:

```bash
# Navigate to Exelon directory
cd /home/jim/gtm-campaign-project/prospects/A-020265_Exelon_Energy/

# Rename inconsistent files to match standard convention
mv exelon-battle-card.md Exelon_Battle_Card_Project_Nightingale.md
mv exelon-compliance-analysis-2025.md Exelon_Compliance_Analysis_Project_Nightingale.md
mv exelon-ransomware-impact-assessment.md Exelon_Ransomware_Impact_Assessment_Project_Nightingale.md
mv exelon-strategic-sales-approach.md Exelon_Strategic_Sales_Approach_Project_Nightingale.md
```

### 2. CONSOLIDATE DUPLICATE EXELON ACCOUNTS

```bash
# Check if A-034695 has any unique content
ls -la /home/jim/gtm-campaign-project/prospects/A-034695_Exelon_Corporation/

# If empty or minimal, remove the duplicate directory
# rm -rf /home/jim/gtm-campaign-project/prospects/A-034695_Exelon_Corporation/
```

### 3. MISSING ARTIFACTS FOR EXELON ENERGY

Create the following missing files:
1. `Exelon_GTM_Part1_Organization_Profile_Project_Nightingale.md`
2. `Exelon_GTM_Part3_Decision_Maker_Profiles_Engagement_Strategy_Project_Nightingale.md`
3. `Exelon_Threat_Landscape_Analysis_Project_Nightingale.md`
4. `Exelon_Sector_Enhancement_Analysis_Project_Nightingale.md`
5. `Exelon_MA_Due_Diligence_Analysis_Project_Nightingale.md`
6. `Exelon_Regulatory_Compliance_Research_Project_Nightingale.md`

### 4. VERIFY DUKE ENERGY COMPLETION

```bash
# List all Duke Energy artifacts
ls -la /home/jim/gtm-campaign-project/prospects/A-019227_Duke_Energy_Corporation/*.md | wc -l
# Should return 10
```

### 5. CREATE TRACKING FILE

```bash
# Create prospect completion tracker
touch /home/jim/gtm-campaign-project/PROSPECT_COMPLETION_TRACKER.md
```

### 6. DIRECTORY STRUCTURE VERIFICATION

For each prospect, ensure these subdirectories exist:
- campaign_themes/
- executive_deliverable/
- gtm_analysis/
- intelligence_analysis/
- phase1_intelligence/
- phase2_enhanced/
- quick_reference/

### 7. CLEAN UP EMPTY DIRECTORIES

```bash
# Remove empty duke-energy-analysis directory
rmdir /home/jim/gtm-campaign-project/duke-energy-analysis/

# Remove empty exelon-analysis directory if exists
rmdir /home/jim/gtm-campaign-project/exelon-analysis/
```

### 8. MOVE MISPLACED ANALYSIS FILES

```bash
# Create directories for prospects with research files
mkdir -p /home/jim/gtm-campaign-project/prospects/A-129751_McDonalds_Corporation
mkdir -p /home/jim/gtm-campaign-project/prospects/A-135830_National_Fuel_Gas_Distribution_Corporation  
mkdir -p /home/jim/gtm-campaign-project/prospects/A-153223_GE_Vernova
mkdir -p /home/jim/gtm-campaign-project/prospects/A-138100_Halliburton_Manufacturing_Services

# Move and rename research files
cd /home/jim/gtm-campaign-project/prospect_research/

# McDonald's
mv prospect_research_mcdonalds.md ../prospects/A-129751_McDonalds_Corporation/McDonalds_Initial_Research_Project_Nightingale.md

# National Fuel Gas
mv prospect_research_nationalfuelgasdistribution.md ../prospects/A-135830_National_Fuel_Gas_Distribution_Corporation/National_Fuel_Gas_Initial_Research_Project_Nightingale.md

# GE Vernova (fix typo)
mv prospect_research_ge_verona.md ../prospects/A-153223_GE_Vernova/GE_Vernova_Initial_Research_Project_Nightingale.md

# Halliburton
mv prospect_research_halliburton.md ../prospects/A-138100_Halliburton_Manufacturing_Services/Halliburton_Initial_Research_Project_Nightingale.md

# Fix Constellation Energy typos and keep in research for now (no prospect directory)
mv prospect_reseaech_constellation_energy.md prospect_research_constellation_energy_v1.md
mv prospect_research_contellation_energy.md prospect_research_constellation_energy_v2.md
```

### 9. STANDARDIZE GTM ANALYSIS SUBDIRECTORY

```bash
# Ensure gtm_part1_organization_profile.md is renamed properly
cd /home/jim/gtm-campaign-project/prospects/A-020265_Exelon_Energy/gtm_analysis/
mv gtm_part1_organization_profile.md Exelon_GTM_Part1_Organization_Profile_Project_Nightingale.md
mv Exelon_GTM_Part1_Organization_Profile_Project_Nightingale.md ../
```

### 10. FIX TYPOS IN FILENAMES

```bash
cd /home/jim/gtm-campaign-project/prospect_research/

# Fix ExxonMobil typo
mv prospect_research_exxonmobile.md prospect_research_exxonmobil.md
```

### 11. CREATE PROSPECT DIRECTORIES WITH STANDARD STRUCTURE

```bash
# Function to create standard prospect structure
create_prospect_structure() {
    local prospect_dir=$1
    mkdir -p "$prospect_dir"/{campaign_themes,executive_deliverable,gtm_analysis,intelligence_analysis,phase1_intelligence,phase2_enhanced,quick_reference}
}

# Create for new prospects
create_prospect_structure "/home/jim/gtm-campaign-project/prospects/A-129751_McDonalds_Corporation"
create_prospect_structure "/home/jim/gtm-campaign-project/prospects/A-135830_National_Fuel_Gas_Distribution_Corporation"
create_prospect_structure "/home/jim/gtm-campaign-project/prospects/A-153223_GE_Vernova"
create_prospect_structure "/home/jim/gtm-campaign-project/prospects/A-138100_Halliburton_Manufacturing_Services"
```

### 12. CREATE COMPLETION CHECKLIST TEMPLATE

```markdown
# Prospect Completion Checklist

- [ ] GTM Part 1 - Organization Profile & Technical Infrastructure
- [ ] GTM Part 2 - Operational Analysis & Strategic Sales Intelligence  
- [ ] GTM Part 3 - Decision-Maker Profiles & Engagement Strategy
- [ ] Executive Concierge Report
- [ ] Local Intelligence Integration (2025 threat reports)
- [ ] Threat Landscape Analysis
- [ ] Sector Enhancement Analysis
- [ ] Ransomware Impact Assessment
- [ ] M&A Due Diligence Analysis
- [ ] Regulatory Compliance Research
```

---

## Execution Order:

1. **Immediate**: Execute file renamings (Section 1)
2. **Immediate**: Clean up empty directories (Section 7)
3. **Next**: Create missing Exelon artifacts (Section 3)
4. **Then**: Begin systematic completion of other prospects
5. **Ongoing**: Use tracking system to prevent duplicate work

---

*Script created on January 3, 2025*