#!/bin/bash
# enhanced_intelligence_pipeline.sh
# Comprehensive intelligence collection from multiple GitHub repositories and partner sources

echo "🚀 Enhanced Intelligence Pipeline - Comprehensive Collection System"
echo "=================================================================="

INTELLIGENCE_DIR="/home/jim/gtm-campaign-project/intelligence"
ANNUAL_REPORTS_DIR="/home/jim/gtm-campaign-project/Annual_cyber_reports"
TEMP_DIR="$INTELLIGENCE_DIR/temp"

# Create temporary directory for processing
mkdir -p "$TEMP_DIR"

echo ""
echo "📚 PHASE 1: GITHUB REPOSITORY INTELLIGENCE COLLECTION"
echo "======================================================"

# Function to clone/update GitHub repositories
update_github_repo() {
    local repo_url="$1"
    local repo_name="$2"
    local target_dir="$INTELLIGENCE_DIR/external_sources/$repo_name"
    
    echo "Processing: $repo_name"
    
    if [ -d "$target_dir" ]; then
        echo "  🔄 Updating existing repository..."
        cd "$target_dir" && git pull origin main 2>/dev/null || git pull origin master 2>/dev/null
    else
        echo "  📥 Cloning new repository..."
        mkdir -p "$INTELLIGENCE_DIR/external_sources"
        git clone "$repo_url" "$target_dir"
    fi
    
    if [ $? -eq 0 ]; then
        echo "  ✅ Successfully updated $repo_name"
        
        # Count and catalog new content
        local file_count=$(find "$target_dir" -type f \( -name "*.md" -o -name "*.pdf" -o -name "*.csv" -o -name "*.json" \) | wc -l)
        echo "  📊 Found $file_count relevant files"
        
        # Create repository summary
        echo "# $repo_name Repository Summary" > "$target_dir/REPO_SUMMARY.md"
        echo "**Updated**: $(date)" >> "$target_dir/REPO_SUMMARY.md"
        echo "**Source**: $repo_url" >> "$target_dir/REPO_SUMMARY.md"
        echo "**Files**: $file_count" >> "$target_dir/REPO_SUMMARY.md"
        echo "" >> "$target_dir/REPO_SUMMARY.md"
        
        # List recent additions (last 30 days)
        echo "## Recent Additions (Last 30 Days)" >> "$target_dir/REPO_SUMMARY.md"
        find "$target_dir" -type f \( -name "*.md" -o -name "*.pdf" \) -mtime -30 -printf "%f\n" | head -20 >> "$target_dir/REPO_SUMMARY.md"
        
    else
        echo "  ❌ Failed to update $repo_name"
    fi
    
    cd "$INTELLIGENCE_DIR"
}

# 1. Awesome Annual Security Reports
echo "1️⃣ Collecting Annual Security Reports..."
update_github_repo "https://github.com/jacobdjwilson/awesome-annual-security-reports" "awesome_annual_reports"

# 2. Cybersecurity Papers Collection
echo "2️⃣ Collecting Academic Cybersecurity Papers..."
update_github_repo "https://github.com/ThreatIntelligenceLab/collection-cybersecurity-papers" "cybersecurity_papers"

# 3. Cybersecurity Datasets
echo "3️⃣ Collecting Cybersecurity Datasets..."
update_github_repo "https://github.com/shramos/Awesome-Cybersecurity-Datasets" "cybersecurity_datasets"

# 4. Critical CISA vulnerability intelligence repositories
echo "4️⃣ Collecting CISA Vulnerability Intelligence..."
update_github_repo "https://github.com/cisagov/vulnrichment" "cisa_vulnrichment"
update_github_repo "https://github.com/cisagov/kev-data" "cisa_kev_data"

# 5. Additional valuable repositories for OT/ICS security
echo "5️⃣ Collecting OT/ICS Security Resources..."
update_github_repo "https://github.com/hslatman/awesome-industrial-control-system-security" "ics_security_awesome"
update_github_repo "https://github.com/mpgn/CyberSecurityRSS" "cybersecurity_rss"
update_github_repo "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES" "attack_samples"

echo ""
echo "🏢 PHASE 2: PARTNER INTELLIGENCE UPDATES"
echo "========================================"

# Function to collect partner intelligence via MCP
collect_partner_intelligence() {
    local partner="$1"
    local partner_dir="$INTELLIGENCE_DIR/partnerships/$partner"
    
    echo "Collecting current intelligence for: $partner"
    mkdir -p "$partner_dir/current"
    
    case $partner in
        "dragos")
            echo "  🐉 Collecting Dragos intelligence..."
            
            # Dragos company information
            mcp__tavily__tavily-search query="Dragos cybersecurity threat intelligence platform 2025" max_results=15 search_depth="advanced" > "$partner_dir/current/dragos_overview_2025.json"
            
            # Dragos capabilities and services
            mcp__tavily__tavily-search query="Dragos OT cybersecurity services platform capabilities" max_results=15 search_depth="advanced" > "$partner_dir/current/dragos_capabilities_2025.json"
            
            # Dragos threat intelligence
            mcp__tavily__tavily-search query="Dragos industrial cybersecurity threat intelligence ICS" max_results=20 search_depth="advanced" > "$partner_dir/current/dragos_threat_intel_2025.json"
            
            # Dragos recent research and reports
            mcp__tavily__tavily-search query="Dragos cybersecurity research reports 2024 2025" max_results=15 search_depth="advanced" > "$partner_dir/current/dragos_research_2025.json"
            
            # Convert to markdown summary
            echo "# Dragos Partner Intelligence Update" > "$partner_dir/current/dragos_summary.md"
            echo "**Generated**: $(date)" >> "$partner_dir/current/dragos_summary.md"
            echo "**Sources**: Tavily search, company research" >> "$partner_dir/current/dragos_summary.md"
            ;;
            
        "adelard")
            echo "  🔬 Collecting Adelard intelligence..."
            
            # Adelard company and safety case expertise
            mcp__tavily__tavily-search query="Adelard safety case analysis verification mathematical proof" max_results=15 search_depth="advanced" > "$partner_dir/current/adelard_overview_2025.json"
            
            # Adelard ASCE platform and methodologies
            mcp__tavily__tavily-search query="Adelard ASCE platform safety verification formal methods" max_results=15 search_depth="advanced" > "$partner_dir/current/adelard_methodologies_2025.json"
            
            # Adelard safety-security integration
            mcp__tavily__tavily-search query="Adelard safety security integration IEC 61508 cybersecurity" max_results=15 search_depth="advanced" > "$partner_dir/current/adelard_safety_security_2025.json"
            
            echo "# Adelard Partner Intelligence Update" > "$partner_dir/current/adelard_summary.md"
            echo "**Generated**: $(date)" >> "$partner_dir/current/adelard_summary.md"
            echo "**Sources**: Tavily search, safety case research" >> "$partner_dir/current/adelard_summary.md"
            ;;
            
        "ncc_otce")
            echo "  🛡️ Collecting NCC Group OTCE intelligence..."
            
            # NCC Group OTCE platform and services
            mcp__tavily__tavily-search query="NCC Group OTCE operational technology cyber exposure assessment" max_results=15 search_depth="advanced" > "$partner_dir/current/ncc_otce_overview_2025.json"
            
            # NCC Group OT cybersecurity services
            mcp__tavily__tavily-search query="NCC Group operational technology cybersecurity consulting services" max_results=15 search_depth="advanced" > "$partner_dir/current/ncc_otce_services_2025.json"
            
            # NCC Group recent research and capabilities
            mcp__tavily__tavily-search query="NCC Group cybersecurity research industrial control systems" max_results=15 search_depth="advanced" > "$partner_dir/current/ncc_research_2025.json"
            
            echo "# NCC Group OTCE Partner Intelligence Update" > "$partner_dir/current/ncc_otce_summary.md"
            echo "**Generated**: $(date)" >> "$partner_dir/current/ncc_otce_summary.md"
            echo "**Sources**: Tavily search, company research" >> "$partner_dir/current/ncc_otce_summary.md"
            ;;
    esac
    
    local file_count=$(find "$partner_dir/current" -type f | wc -l)
    echo "  ✅ Collected $file_count intelligence files for $partner"
}

# Collect partner intelligence
collect_partner_intelligence "dragos"
collect_partner_intelligence "adelard" 
collect_partner_intelligence "ncc_otce"

echo ""
echo "🔄 PHASE 3: CURRENT ADVISORIES AND THREAT INTELLIGENCE"
echo "====================================================="

# Function to refresh current security advisories
refresh_current_advisories() {
    local current_dir="$INTELLIGENCE_DIR/current"
    mkdir -p "$current_dir"/{advisories,threats,vulnerabilities,incidents}
    
    echo "Refreshing current security intelligence..."
    
    # CISA Known Exploited Vulnerabilities - Enhanced with repositories
    echo "  📡 Collecting CISA KEV database and enrichment data..."
    mcp__fetch__fetch_json url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" > "$current_dir/advisories/cisa_kev.json" 2>/dev/null || echo "CISA KEV fetch failed"
    
    # Process enriched vulnerability data from CISA repositories
    if [ -d "$INTELLIGENCE_DIR/external_sources/cisa_vulnrichment" ]; then
        echo "  🔍 Processing CISA vulnerability enrichment data..."
        find "$INTELLIGENCE_DIR/external_sources/cisa_vulnrichment" -name "*.json" -type f | head -100 | xargs cat > "$current_dir/vulnerabilities/cisa_enriched_vulns.json" 2>/dev/null
    fi
    
    if [ -d "$INTELLIGENCE_DIR/external_sources/cisa_kev_data" ]; then
        echo "  💥 Processing CISA KEV historical data..."
        find "$INTELLIGENCE_DIR/external_sources/cisa_kev_data" -name "*.json" -type f | head -50 | xargs cat > "$current_dir/advisories/cisa_kev_historical.json" 2>/dev/null
    fi
    
    # Current OT/ICS threats via Tavily
    echo "  🎯 Collecting current OT/ICS threats..."
    mcp__tavily__tavily-search query="operational technology cybersecurity threats 2025 ICS SCADA attacks" max_results=20 search_depth="advanced" > "$current_dir/threats/ot_threats_current.json"
    
    # Industrial cybersecurity incidents
    echo "  🚨 Collecting recent industrial cybersecurity incidents..."
    mcp__tavily__tavily-search query="industrial cybersecurity incidents 2025 OT attacks manufacturing" max_results=20 search_depth="advanced" > "$current_dir/incidents/industrial_incidents_2025.json"
    
    # Supply chain cybersecurity current events
    echo "  🔗 Collecting supply chain security updates..."
    mcp__tavily__tavily-search query="supply chain cybersecurity attacks 2025 third party vendor security" max_results=15 search_depth="advanced" > "$current_dir/threats/supply_chain_threats_2025.json"
    
    # IEC 62443 and compliance updates
    echo "  📋 Collecting compliance and standards updates..."
    mcp__tavily__tavily-search query="IEC 62443 compliance updates 2025 industrial cybersecurity standards" max_results=15 search_depth="advanced" > "$current_dir/regulatory/compliance_updates_2025.json"
    
    # Create current intelligence summary
    echo "# Current Intelligence Summary" > "$current_dir/CURRENT_SUMMARY.md"
    echo "**Last Updated**: $(date)" >> "$current_dir/CURRENT_SUMMARY.md"
    echo "**Sources**: CISA, Tavily threat intelligence, industry monitoring" >> "$current_dir/CURRENT_SUMMARY.md"
    echo "" >> "$current_dir/CURRENT_SUMMARY.md"
    
    local file_count=$(find "$current_dir" -name "*.json" | wc -l)
    echo "  ✅ Collected $file_count current intelligence files"
}

refresh_current_advisories

echo ""
echo "📊 PHASE 4: THEME-SPECIFIC INTELLIGENCE CURATION"
echo "==============================================="

# Function to curate theme-specific intelligence from all sources
curate_theme_intelligence() {
    local theme_code="$1"
    local theme_name="$2"
    shift 2
    local search_terms=("$@")
    
    echo "Curating intelligence for: $theme_name [$theme_code]"
    
    local theme_dir="$INTELLIGENCE_DIR/foundation/${theme_code}_$(echo $theme_name | tr ' ' '_' | tr '[:upper:]' '[:lower:]')"
    mkdir -p "$theme_dir"/{annual_reports,external_sources,academic_papers,datasets,current_intel,vulnerabilities,exploits}
    
    # Build search pattern
    local pattern=""
    for term in "${search_terms[@]}"; do
        if [ -z "$pattern" ]; then
            pattern="$term"
        else
            pattern="$pattern\|$term"
        fi
    done
    
    echo "  📚 Curating from annual reports..."
    find "$ANNUAL_REPORTS_DIR" -name "*.md" -exec grep -l -i "$pattern" {} \; > "$theme_dir/annual_reports/relevant_reports.txt"
    local annual_count=$(wc -l < "$theme_dir/annual_reports/relevant_reports.txt" 2>/dev/null || echo "0")
    
    echo "  🔬 Curating from academic papers..."
    find "$INTELLIGENCE_DIR/external_sources/cybersecurity_papers" -name "*.md" -o -name "*.pdf" 2>/dev/null | xargs grep -l -i "$pattern" 2>/dev/null > "$theme_dir/academic_papers/relevant_papers.txt" || touch "$theme_dir/academic_papers/relevant_papers.txt"
    local academic_count=$(wc -l < "$theme_dir/academic_papers/relevant_papers.txt")
    
    echo "  📊 Curating from datasets..."
    find "$INTELLIGENCE_DIR/external_sources/cybersecurity_datasets" -name "*.md" 2>/dev/null | xargs grep -l -i "$pattern" 2>/dev/null > "$theme_dir/datasets/relevant_datasets.txt" || touch "$theme_dir/datasets/relevant_datasets.txt"
    local dataset_count=$(wc -l < "$theme_dir/datasets/relevant_datasets.txt")
    
    echo "  📡 Curating current intelligence..."
    find "$INTELLIGENCE_DIR/current" -name "*.json" 2>/dev/null | xargs grep -l -i "$pattern" 2>/dev/null > "$theme_dir/current_intel/relevant_current.txt" || touch "$theme_dir/current_intel/relevant_current.txt"
    local current_count=$(wc -l < "$theme_dir/current_intel/relevant_current.txt")
    
    echo "  💥 Curating CISA vulnerability intelligence..."
    # Process CISA vulnerability data for theme-specific exploitability
    if [ -d "$INTELLIGENCE_DIR/external_sources/cisa_vulnrichment" ]; then
        find "$INTELLIGENCE_DIR/external_sources/cisa_vulnrichment" -name "*.json" 2>/dev/null | xargs grep -l -i "$pattern" 2>/dev/null > "$theme_dir/vulnerabilities/cisa_relevant_vulns.txt" || touch "$theme_dir/vulnerabilities/cisa_relevant_vulns.txt"
        local vuln_count=$(wc -l < "$theme_dir/vulnerabilities/cisa_relevant_vulns.txt")
        echo "    ✅ Found $vuln_count theme-relevant CISA vulnerabilities"
    fi
    
    echo "  🎯 Curating exploitability data..."
    # Process KEV data for theme-specific known exploited vulnerabilities
    if [ -d "$INTELLIGENCE_DIR/external_sources/cisa_kev_data" ]; then
        find "$INTELLIGENCE_DIR/external_sources/cisa_kev_data" -name "*.json" 2>/dev/null | xargs grep -l -i "$pattern" 2>/dev/null > "$theme_dir/exploits/kev_relevant_exploits.txt" || touch "$theme_dir/exploits/kev_relevant_exploits.txt"
        local exploit_count=$(wc -l < "$theme_dir/exploits/kev_relevant_exploits.txt")
        echo "    ✅ Found $exploit_count theme-relevant known exploited vulnerabilities"
    fi
    
    # Create comprehensive theme summary
    echo "# $theme_name Intelligence Collection" > "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    echo "**Theme Code**: $theme_code" >> "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    echo "**Generated**: $(date)" >> "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    echo "**Search Terms**: ${search_terms[*]}" >> "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    echo "" >> "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    echo "## Intelligence Sources Summary" >> "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    echo "- **Annual Reports**: $annual_count relevant reports" >> "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    echo "- **Academic Papers**: $academic_count relevant papers" >> "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    echo "- **Datasets**: $dataset_count relevant datasets" >> "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    echo "- **Current Intelligence**: $current_count current sources" >> "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    
    # Add vulnerability and exploit counts if available
    if [ -f "$theme_dir/vulnerabilities/cisa_relevant_vulns.txt" ]; then
        local vuln_count=$(wc -l < "$theme_dir/vulnerabilities/cisa_relevant_vulns.txt" 2>/dev/null || echo "0")
        echo "- **CISA Vulnerabilities**: $vuln_count relevant vulnerabilities" >> "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    fi
    
    if [ -f "$theme_dir/exploits/kev_relevant_exploits.txt" ]; then
        local exploit_count=$(wc -l < "$theme_dir/exploits/kev_relevant_exploits.txt" 2>/dev/null || echo "0")
        echo "- **Known Exploited Vulnerabilities**: $exploit_count relevant KEVs" >> "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    fi
    
    echo "" >> "$theme_dir/THEME_INTELLIGENCE_SUMMARY.md"
    
    local total_sources=$((annual_count + academic_count + dataset_count + current_count))
    echo "  ✅ Curated $total_sources total intelligence sources for $theme_name"
    
    return $total_sources
}

# Curate intelligence for all 9 themes
echo "Curating comprehensive intelligence for all service themes..."

curate_theme_intelligence "SCV" "Supply Chain Vulnerability" \
    "supply chain" "third.party" "vendor" "sbom" "software.*bill.*materials" "supplier" "procurement"

curate_theme_intelligence "IEC" "IEC 62443 Compliance" \
    "62443" "iec.*62443" "industrial.*cybersecurity" "zone.*conduit" "operational.*technology.*security"

curate_theme_intelligence "ITC" "IT OT Convergence Security" \
    "convergence" "digital.*transformation" "remote.*access" "network.*segmentation" "it.*ot"

curate_theme_intelligence "LCR" "Legacy Codebase Risk" \
    "legacy.*system" "end.*of.*life" "unsupported.*software" "obsolete" "aging.*infrastructure"

curate_theme_intelligence "PLM" "Product Lifecycle Monitoring" \
    "product.*lifecycle" "vulnerability.*management" "patch.*management" "asset.*management"

curate_theme_intelligence "SCA" "Safety Case Analysis" \
    "safety.*case" "safety.*critical" "functional.*safety" "61508" "61511" "safety.*integrity"

curate_theme_intelligence "NVC" "Network Visibility Compliance" \
    "network.*monitoring" "traffic.*analysis" "network.*segmentation" "intrusion.*detection"

curate_theme_intelligence "RIA" "Ransomware Impact Assessment" \
    "ransomware" "crypto.*locker" "encryption.*attack" "backup.*recovery" "business.*continuity"

curate_theme_intelligence "MDA" "M&A Due Diligence" \
    "merger" "acquisition" "due.*diligence" "m.*a" "integration.*security"

echo ""
echo "🎯 FINAL SUMMARY: COMPREHENSIVE INTELLIGENCE ECOSYSTEM"
echo "====================================================="

# Generate final summary report
echo "Generating comprehensive intelligence ecosystem summary..."

total_annual_reports=$(find "$ANNUAL_REPORTS_DIR" -name "*.md" | wc -l)
total_external_files=$(find "$INTELLIGENCE_DIR/external_sources" -type f 2>/dev/null | wc -l)
total_partner_files=$(find "$INTELLIGENCE_DIR/partnerships" -type f 2>/dev/null | wc -l)
total_current_files=$(find "$INTELLIGENCE_DIR/current" -type f 2>/dev/null | wc -l)
total_theme_summaries=$(find "$INTELLIGENCE_DIR/foundation" -name "THEME_INTELLIGENCE_SUMMARY.md" 2>/dev/null | wc -l)

echo "📊 Intelligence Ecosystem Statistics:"
echo "======================================"
printf "%-30s: %6d files\n" "Annual Reports" "$total_annual_reports"
printf "%-30s: %6d files\n" "External GitHub Sources" "$total_external_files"
printf "%-30s: %6d files\n" "Partner Intelligence" "$total_partner_files"
printf "%-30s: %6d files\n" "Current Threat Intel" "$total_current_files"
printf "%-30s: %6d themes\n" "Theme Collections" "$total_theme_summaries"

total_intelligence=$((total_annual_reports + total_external_files + total_partner_files + total_current_files))
echo "======================================"
echo "Total Intelligence Sources: $total_intelligence files"

echo ""
echo "✅ ENHANCED INTELLIGENCE PIPELINE COMPLETE"
echo "=========================================="
echo "🎯 Ready for theme-specific prospect research with comprehensive intelligence"
echo "📁 Intelligence location: $INTELLIGENCE_DIR"
echo "🔄 All sources updated and curated for 9 service themes"
echo "🚀 Next: Use collect_themed_prospect_research.sh for prospect-specific analysis"

# Cleanup
rm -rf "$TEMP_DIR"