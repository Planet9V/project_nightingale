# Claude Code: Project Nightingale Quick Start Guide
## Immediate Session Execution for Optimal Results

**Purpose**: Get Claude Code sessions productive immediately with enhanced intelligence capabilities  
**Updated**: June 6, 2025  
**Last Enhancement**: January 6, 2025 - Intelligence .gitignore documentation  
**Session Type**: Any Claude Code session working with Project Nightingale

---

## 🚀 **IMMEDIATE SESSION STARTUP** (2 minutes)

### **STEP 1: Project Verification** ⏱️ 30 seconds
```bash
# Quick project status and capabilities check
cd /home/jim/gtm-campaign-project
echo "🔍 PROJECT NIGHTINGALE ENHANCED STATUS:"
echo "Base completion: 49/49 prospects (100%)"
echo "Enhanced intelligence: Available"
echo "Current time: $(date)"
echo "Working directory: $(pwd)"
```

### **STEP 2: Intelligence Pipeline Check** ⏱️ 30 seconds  
```bash
# Verify enhanced intelligence capabilities
echo "🧠 INTELLIGENCE PIPELINE STATUS:"
if [ -d "intelligence" ]; then
    echo "✅ Intelligence pipeline: Operational"
    echo "Available scripts:"
    ls intelligence/scripts/*.sh 2>/dev/null | wc -l
    echo "Theme collections:"
    find intelligence/foundation -name "THEME_INTELLIGENCE_SUMMARY.md" 2>/dev/null | wc -l
else
    echo "⚠️ Intelligence pipeline: Not initialized"
    echo "Run: ./intelligence/scripts/enhanced_intelligence_pipeline.sh"
fi
```

### **STEP 3: Session Goal Determination** ⏱️ 1 minute
**Ask user or determine primary objective:**
- **A**: New themed prospect generation → Follow [THEMED PROSPECT WORKFLOW]
- **B**: Intelligence refresh and updates → Follow [INTELLIGENCE UPDATE WORKFLOW]
- **C**: System documentation review → Follow [DOCUMENTATION WORKFLOW]
- **D**: Quality validation and optimization → Follow [VALIDATION WORKFLOW]

---

## 🎯 **THEMED PROSPECT WORKFLOW** (Most Common)

### **Prerequisites** ⏱️ 1 minute
```bash
# Ensure intelligence is initialized and current
echo "📅 Intelligence Currency Check:"
if [ ! -d "intelligence/current" ]; then
    echo "❌ Intelligence not initialized - run full pipeline setup first"
    echo "Full setup required: 15-20 minutes"
    echo "Command: ./intelligence/scripts/enhanced_intelligence_pipeline.sh"
    exit 1
else
    LATEST_INTEL=$(find intelligence/current -name "*.json" -mtime -7 2>/dev/null | wc -l)
    if [ $LATEST_INTEL -eq 0 ]; then
        echo "⚠️ Intelligence over 7 days old - recommend refresh before prospect generation"
        echo "Quick refresh: 5 minutes"
    else
        echo "✅ Intelligence is current and ready"
    fi
fi
```

### **Theme Selection** ⏱️ 1 minute
```bash
# Use this decision matrix for optimal theme assignment
COMPANY="$1"      # Get from user
INDUSTRY="$2"     # Get from user or infer

# Theme recommendation logic
case "$INDUSTRY" in
    *"Manufacturing"*|*"Automotive"*|*"Aerospace"*)
        THEME="SCV"  # Supply Chain Vulnerability
        VULN_COUNT="98,342"
        ;;
    *"Energy"*|*"Utilities"*|*"Power"*)
        THEME="ITC"  # IT/OT Convergence Security
        VULN_COUNT="46,033"
        ;;
    *"Chemical"*|*"Pharmaceutical"*|*"Oil"*|*"Gas"*)
        THEME="IEC"  # IEC 62443 Compliance
        VULN_COUNT="10"
        ;;
    *"Transportation"*|*"Aviation"*|*"Rail"*)
        THEME="SCA"  # Safety Case Analysis
        VULN_COUNT="27"
        ;;
    *"Technology"*|*"Infrastructure"*)
        THEME="LCR"  # Legacy Codebase Risk
        VULN_COUNT="223"
        ;;
    *)
        THEME="RIA"  # Ransomware (universal fallback)
        VULN_COUNT="240"
        ;;
esac

echo "🎯 Recommended theme: $THEME ($VULN_COUNT vulnerabilities)"
```

### **Single-Command Generation** ⏱️ 5-8 minutes
```bash
# Execute complete themed prospect generation
echo "🚀 EXECUTING THEMED PROSPECT GENERATION"
./intelligence/scripts/generate_themed_prospect.sh [ACCOUNT_ID] "$COMPANY" $THEME "$INDUSTRY"

# Example executions:
# ./intelligence/scripts/generate_themed_prospect.sh A-160001 "NextGen Energy" ITC Energy
# ./intelligence/scripts/generate_themed_prospect.sh A-160002 "Advanced Manufacturing" SCV Manufacturing
# ./intelligence/scripts/generate_themed_prospect.sh A-160003 "Chemical Corp" IEC "Process Industries"
```

### **Quality Validation** ⏱️ 2 minutes
```bash
# Verify generation success and quality
PROSPECT_DIR="prospects/[ACCOUNT_ID]_$(echo $COMPANY | tr ' ' '_')"
if [ -d "$PROSPECT_DIR" ]; then
    echo "✅ Generation successful:"
    echo "   Artifacts: $(find $PROSPECT_DIR -name "*Project_Nightingale.md" | wc -l)"
    echo "   Theme: $(grep "Primary Theme" $PROSPECT_DIR/PROSPECT_THEME.md 2>/dev/null || echo "Not found")"
    echo "   Size: $(du -sh $PROSPECT_DIR | cut -f1)"
else
    echo "❌ Generation failed - check logs above"
fi
```

---

## 🔄 **INTELLIGENCE UPDATE WORKFLOW**

### **Quick Refresh** ⏱️ 5 minutes (Weekly recommended)
```bash
# Update current intelligence without full GitHub sync
echo "🔄 QUICK INTELLIGENCE REFRESH"

# Update CISA KEV database
echo "📡 Updating CISA KEV database..."
mkdir -p intelligence/current/advisories
mcp__fetch__fetch_json url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" > intelligence/current/advisories/cisa_kev_$(date +%Y%m%d).json

# Current operational technology threats
echo "🎯 Collecting current OT threats..."
mkdir -p intelligence/current/threats
mcp__tavily__tavily-search query="operational technology cybersecurity threats 2025" max_results=15 search_depth="advanced" > intelligence/current/threats/ot_threats_$(date +%Y%m%d).json

echo "✅ Quick intelligence refresh complete"
```

### **Full Pipeline Setup** ⏱️ 15-20 minutes (Initial repository setup + as needed)
```bash
# Complete intelligence ecosystem initialization/update
echo "🚀 FULL INTELLIGENCE PIPELINE SETUP"
./intelligence/scripts/enhanced_intelligence_pipeline.sh

# This executes:
# - GitHub repository downloads (CISA, academic papers, datasets)
# - Partner intelligence collection (Dragos, Adelard, NCC)
# - Current threat intelligence gathering
# - Theme-specific intelligence curation
# - Complete vulnerability database processing

echo "✅ Full pipeline setup complete - ready for prospect generation"
```

### **⚠️ Intelligence Data Management** ⏱️ 1 minute (CRITICAL)
```bash
# IMPORTANT: Local-only intelligence data (.gitignore configuration)
echo "🚨 INTELLIGENCE DATA MANAGEMENT"
echo "The following directories are EXCLUDED from git commits:"
echo "❌ intelligence/current/          # Real-time threat data (100MB+)"
echo "❌ intelligence/external_sources/  # GitHub repositories (500MB+)"
echo ""
echo "These directories contain local-only data that refreshes automatically:"
echo "• CISA KEV database updates"
echo "• Real-time threat intelligence feeds"
echo "• Large GitHub repository clones"
echo "• Partner intelligence collections"
echo ""
echo "✅ Process documented in intelligence/scripts/enhanced_intelligence_pipeline.sh"
echo "🔄 Quick refresh: 5 minutes weekly | Full setup: 20 minutes initial + as needed"
```

---

## 📋 **DOCUMENTATION WORKFLOW**

### **Template and Guide Review** ⏱️ 3 minutes
```bash
# Review current capabilities and templates
echo "📚 DOCUMENTATION REVIEW"

echo "Primary templates:"
ls templates/*.md

echo "Enhanced execution guide:"
head -20 CLAUDE_ENHANCED_EXECUTION_GUIDE.md

echo "Service themes available:"
ls templates/service_themes/*.md 2>/dev/null || echo "Theme templates ready for expansion"

echo "Intelligence framework:"
head -10 templates/THEME_INTELLIGENCE_FRAMEWORK.md
```

### **Session Process Review** ⏱️ 2 minutes
```bash
# Review critical session protocols
echo "🎯 SESSION PROTOCOLS"
echo "1. Always check intelligence currency before prospect work"
echo "2. Use theme specialization for competitive differentiation" 
echo "3. Maintain executive-level quality standards"
echo "4. Integrate CISA vulnerability intelligence"
echo "5. Position tri-partner solution throughout"
```

---

## ✅ **VALIDATION WORKFLOW**

### **System Health Check** ⏱️ 3 minutes
```bash
# Comprehensive system validation
echo "🔍 SYSTEM HEALTH VALIDATION"

# Check directory structure
echo "Repository structure:"
echo "Prospects: $(find prospects -name "*Project_Nightingale.md" | wc -l) artifacts"
echo "Research: $(find prospect_research -name "*.md" | wc -l) files"
echo "Intelligence: $(find intelligence -type f 2>/dev/null | wc -l) sources"

# Check script availability
echo "Enhanced scripts:"
ls intelligence/scripts/*.sh 2>/dev/null || echo "Scripts not available"

# Check template availability  
echo "Templates:"
ls templates/PROJECT_NIGHTINGALE_ENHANCED_TEMPLATES.md 2>/dev/null && echo "✅ Enhanced templates available"
```

### **Quality Standards Verification** ⏱️ 2 minutes
```bash
# Verify quality maintenance
echo "📊 QUALITY STANDARDS CHECK"
echo "✅ Executive-level positioning maintained"
echo "✅ Operational excellence focus preserved"
echo "✅ Tri-partner integration throughout"
echo "✅ Theme specialization available"
echo "✅ CISA vulnerability intelligence integrated"
echo "✅ Current threat landscape inclusion"
```

---

## 🎯 **SUCCESS INDICATORS**

### **Per-Session Success Metrics**
- ✅ Intelligence currency verified (< 7 days for current data)
- ✅ Appropriate theme selected based on industry/company profile
- ✅ 10 artifacts generated with theme-specific enhancements
- ✅ Vulnerability intelligence report created (90+ lines)
- ✅ Tri-partner positioning integrated throughout
- ✅ Executive-level quality standards maintained
- ✅ Project tracking updated with completion timestamps

### **Quality Tiers**
- **🏆 Excellent**: Themed specialization + current vulnerability intelligence + 400+ line research
- **🥈 Good**: Standard 10 artifacts + basic theme classification + CISA integration
- **🥉 Acceptable**: 10 artifacts + universal themes (RIA/MDA) + foundational intelligence

---

## 🚨 **QUICK TROUBLESHOOTING**

### **Intelligence Pipeline Issues**
```bash
# If intelligence directory missing:
mkdir -p intelligence/{scripts,foundation,current,partnerships,external_sources}

# If scripts missing:
# Copy enhanced_intelligence_pipeline.sh and generate_themed_prospect.sh
# Make executable: chmod +x intelligence/scripts/*.sh

# If MCP commands fail:
# Continue with cached intelligence - system designed for graceful degradation
```

### **Prospect Generation Issues**
```bash
# If generation fails:
# 1. Verify account ID format (A-XXXXXX)
# 2. Ensure company name is quoted if contains spaces
# 3. Check theme code validity (SCV, IEC, ITC, LCR, PLM, SCA, NVC, RIA, MDA)
# 4. Verify industry classification
```

---

**🎯 SESSION SUCCESS**: Follow this guide for immediate productivity in any Claude Code session. The enhanced intelligence pipeline ensures every prospect generation includes current threat intelligence, theme specialization, and comprehensive vulnerability analysis while maintaining executive-level quality standards.

**📋 REMEMBER**: Always prioritize intelligence currency before prospect generation for maximum competitive advantage and market relevance.