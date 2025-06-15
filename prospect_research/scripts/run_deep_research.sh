#!/bin/bash
# run_deep_research.sh - Run JINA AI deep research enhancement on all prospects

# Set API keys
export JINA_API_KEY="jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q"
export TAVILY_API_KEY="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"

# Change to script directory
cd "$(dirname "$0")"

# Display banner
echo "🔬 JINA AI Deep Research Enhancement System"
echo "=========================================="
echo ""
echo "This will perform comprehensive deep research on ALL prospect files using:"
echo "  ✓ JINA AI Reader - Full web content extraction"
echo "  ✓ JINA AI Search - Semantic intelligence discovery"
echo "  ✓ Tavily Search - Recent web results"
echo "  ✓ Advanced pattern recognition for:"
echo "    • Vulnerabilities & CVEs"
echo "    • Security incidents & breaches"
echo "    • Leadership changes"
echo "    • Digital transformation opportunities"
echo "    • Compliance requirements"
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Install required packages if needed
echo "📦 Checking dependencies..."
pip3 install aiohttp pyyaml --quiet

# Run the deep research enhancement
echo ""
echo "🚀 Starting Deep Research Enhancement..."
echo ""

python3 enhance_all_prospects_jina.py

echo ""
echo "✅ Deep research enhancement complete!"
echo ""
echo "📊 Check the generated report for detailed metrics"