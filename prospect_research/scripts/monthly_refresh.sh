#!/bin/bash
# monthly_refresh.sh - Simple monthly refresh workflow

# Configuration
RESEARCH_DIR="/home/jim/gtm-campaign-project/prospect_research"
TODAY=$(date +%Y-%m-%d)
MONTH=$(date +%B)
YEAR=$(date +%Y)

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "================================================"
echo "   Prospect Research Monthly Refresh"
echo "   Month: $MONTH $YEAR"
echo "================================================"

# Function to update last_refreshed date
update_refresh_date() {
    local file=$1
    if [[ -f "$file" ]]; then
        # Update the last_refreshed field in YAML frontmatter
        sed -i.bak "s/last_refreshed:.*/last_refreshed: $TODAY/" "$file"
        rm "${file}.bak"
        echo -e "${GREEN}✓${NC} Updated refresh date in $file"
    fi
}

# Function to generate research URLs
generate_research_urls() {
    local company=$1
    local company_encoded=$(echo "$company" | sed 's/ /%20/g')
    
    echo ""
    echo "Research URLs for $company:"
    echo "----------------------------"
    echo "News:      https://www.google.com/search?q=\"${company_encoded}\"+cybersecurity+news&tbs=qdr:m"
    echo "LinkedIn:  https://www.linkedin.com/company/${company_encoded}/people/"
    echo "SEC:       https://www.sec.gov/edgar/search/?q=${company_encoded}"
    echo "GitHub:    https://github.com/search?q=${company_encoded}"
    echo ""
}

# Get list of prospects based on week of month
WEEK=$(( ($(date +%d) - 1) / 7 + 1 ))
case $WEEK in
    1) PATTERN="[A-D]*_Prospect_Intelligence.md" ;;
    2) PATTERN="[E-J]*_Prospect_Intelligence.md" ;;
    3) PATTERN="[K-P]*_Prospect_Intelligence.md" ;;
    4) PATTERN="[Q-Z]*_Prospect_Intelligence.md" ;;
    *) PATTERN="*_Prospect_Intelligence.md" ;;
esac

echo "Week $WEEK of month - Processing pattern: $PATTERN"
echo ""

# Count prospects for this week
cd "$RESEARCH_DIR"
PROSPECT_COUNT=$(ls $PATTERN 2>/dev/null | wc -l)

if [[ $PROSPECT_COUNT -eq 0 ]]; then
    echo -e "${RED}No prospects found matching pattern: $PATTERN${NC}"
    exit 1
fi

echo "Found $PROSPECT_COUNT prospects to refresh this week"
echo ""

# Process each prospect
COMPLETED=0
for file in $PATTERN; do
    if [[ -f "$file" ]]; then
        # Extract company name
        COMPANY=$(basename "$file" _Prospect_Intelligence.md | tr '_' ' ')
        
        echo "================================================"
        echo -e "${YELLOW}Researching: $COMPANY${NC}"
        echo "File: $file"
        
        # Generate research URLs
        generate_research_urls "$COMPANY"
        
        # Update refresh date
        update_refresh_date "$file"
        
        # Open file in default editor
        echo "Opening file for updates..."
        ${EDITOR:-nano} "$file"
        
        # Mark complete
        ((COMPLETED++))
        echo -e "${GREEN}✓ Completed $COMPLETED/$PROSPECT_COUNT${NC}"
        echo ""
        
        # Optional: Add delay between prospects
        echo "Press Enter to continue to next prospect..."
        read
    fi
done

# Generate summary report
echo ""
echo "================================================"
echo "   Monthly Refresh Summary"
echo "================================================"
echo "Date:       $TODAY"
echo "Week:       $WEEK of $MONTH"
echo "Processed:  $COMPLETED prospects"
echo ""

# Update progress tracker
TRACKER="$RESEARCH_DIR/REFRESH_TRACKER.md"
if [[ ! -f "$TRACKER" ]]; then
    echo "# Research Refresh Tracker" > "$TRACKER"
    echo "" >> "$TRACKER"
    echo "| Date | Week | Prospects Refreshed | Notes |" >> "$TRACKER"
    echo "|------|------|-------------------|-------|" >> "$TRACKER"
fi

echo "| $TODAY | Week $WEEK | $COMPLETED | Monthly refresh |" >> "$TRACKER"

# Commit changes
echo "Committing updates to git..."
cd "$RESEARCH_DIR"
git add *.md
git add scripts/
git commit -m "Monthly refresh - Week $WEEK of $MONTH $YEAR - $COMPLETED prospects updated"

echo -e "${GREEN}✓ Monthly refresh complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Review the REFRESH_TRACKER.md for progress"
echo "2. Run gap analysis to identify missing information"
echo "3. Schedule deep dives for high-priority prospects"