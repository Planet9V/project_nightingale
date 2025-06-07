#!/bin/bash
# build_foundation_intelligence.sh
# Automated theme categorization of Annual Cyber Reports for foundation intelligence

echo "🧠 Building Foundation Intelligence Collections from Annual Reports..."
echo "Processing 377+ annual cyber reports into theme-specific collections..."

ANNUAL_REPORTS_DIR="/home/jim/gtm-campaign-project/Annual_cyber_reports"
FOUNDATION_DIR="/home/jim/gtm-campaign-project/intelligence/foundation"

# Function to search and categorize reports
categorize_reports() {
    local theme_dir="$1"
    local theme_name="$2"
    shift 2
    local search_terms=("$@")
    
    echo "Processing theme: $theme_name"
    
    # Build grep pattern from search terms
    local pattern=""
    for term in "${search_terms[@]}"; do
        if [ -z "$pattern" ]; then
            pattern="$term"
        else
            pattern="$pattern\|$term"
        fi
    done
    
    # Search for reports containing theme-relevant terms
    find "$ANNUAL_REPORTS_DIR" -name "*.md" -exec grep -l -i "$pattern" {} \; > "$FOUNDATION_DIR/$theme_dir/relevant_reports.txt"
    
    local count=$(wc -l < "$FOUNDATION_DIR/$theme_dir/relevant_reports.txt")
    echo "  ✅ Found $count relevant reports for $theme_name"
    
    # Create summary file
    echo "# $theme_name Foundation Intelligence" > "$FOUNDATION_DIR/$theme_dir/README.md"
    echo "**Reports Found**: $count" >> "$FOUNDATION_DIR/$theme_dir/README.md"
    echo "**Search Terms**: ${search_terms[*]}" >> "$FOUNDATION_DIR/$theme_dir/README.md"
    echo "**Generated**: $(date)" >> "$FOUNDATION_DIR/$theme_dir/README.md"
    echo "" >> "$FOUNDATION_DIR/$theme_dir/README.md"
    echo "## Relevant Reports" >> "$FOUNDATION_DIR/$theme_dir/README.md"
    while read report; do
        basename "$report" >> "$FOUNDATION_DIR/$theme_dir/README.md"
    done < "$FOUNDATION_DIR/$theme_dir/relevant_reports.txt"
}

# Supply Chain Vulnerability (SCV)
categorize_reports "SCV_supply_chain" "Supply Chain Vulnerability" \
    "supply chain" "third.party" "vendor" "sbom" "software.*bill.*materials" \
    "supplier" "procurement" "third party" "dependency" "component.*security"

# IEC 62443 Compliance (IEC)  
categorize_reports "IEC_compliance" "IEC 62443 Compliance" \
    "62443" "iec.*62443" "industrial.*cybersecurity" "zone.*conduit" \
    "operational.*technology.*security" "ot.*security.*standard" "industrial.*control.*security"

# IT/OT Convergence Security (ITC)
categorize_reports "ITC_convergence" "IT/OT Convergence Security" \
    "convergence" "digital.*transformation" "remote.*access" "network.*segmentation" \
    "it.*ot" "operational.*technology.*integration" "industrial.*internet" "industry.*4"

# Legacy Codebase Risk (LCR)
categorize_reports "LCR_legacy_systems" "Legacy Codebase Risk" \
    "legacy.*system" "end.*of.*life" "unsupported.*software" "obsolete" \
    "aging.*infrastructure" "legacy.*code" "deprecated" "maintenance.*mode"

# Product Lifecycle Monitoring (PLM)
categorize_reports "PLM_product_lifecycle" "Product Lifecycle Monitoring" \
    "product.*lifecycle" "vulnerability.*management" "patch.*management" \
    "asset.*management" "inventory" "configuration.*management" "software.*inventory"

# Safety Case Analysis (SCA)
categorize_reports "SCA_safety_case" "Safety Case Analysis" \
    "safety.*case" "safety.*critical" "functional.*safety" "61508" "61511" \
    "safety.*integrity" "hazard.*analysis" "risk.*assessment" "safety.*security"

# Network Visibility & Compliance (NVC)
categorize_reports "NVC_network_visibility" "Network Visibility & Compliance" \
    "network.*monitoring" "traffic.*analysis" "network.*segmentation" "firewall" \
    "intrusion.*detection" "network.*security.*monitoring" "packet.*inspection"

# Ransomware Impact Assessment (RIA)
categorize_reports "RIA_ransomware" "Ransomware Impact Assessment" \
    "ransomware" "crypto.*locker" "encryption.*attack" "ransom" \
    "backup.*recovery" "business.*continuity" "disaster.*recovery" "incident.*response"

# M&A Due Diligence (MDA)
categorize_reports "MDA_ma_diligence" "M&A Due Diligence" \
    "merger" "acquisition" "due.*diligence" "m.*a" "consolidation" \
    "integration.*security" "organizational.*change" "compliance.*assessment"

echo ""
echo "🎯 Foundation Intelligence Collection Summary:"
echo "=============================================="

total_reports=0
for theme_dir in SCV_supply_chain IEC_compliance ITC_convergence LCR_legacy_systems PLM_product_lifecycle SCA_safety_case NVC_network_visibility RIA_ransomware MDA_ma_diligence; do
    if [ -f "$FOUNDATION_DIR/$theme_dir/relevant_reports.txt" ]; then
        count=$(wc -l < "$FOUNDATION_DIR/$theme_dir/relevant_reports.txt")
        theme_name=$(echo $theme_dir | cut -d'_' -f2- | tr '_' ' ' | sed 's/\b\w/\U&/g')
        printf "%-30s: %3d reports\n" "$theme_name" "$count"
        total_reports=$((total_reports + count))
    fi
done

echo "=============================================="
echo "Total theme-categorized reports: $total_reports"
echo ""
echo "✅ Foundation Intelligence Collections Built Successfully"
echo "📁 Location: $FOUNDATION_DIR"
echo "🔍 Next: Run refresh_current_intelligence.sh for current threat data"