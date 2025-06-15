#!/bin/bash
# run_enhancement.sh - Run the prospect enhancement with API keys

# Set API keys
export JINA_API_KEY="jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q"
export TAVILY_API_KEY="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"

# Change to script directory
cd "$(dirname "$0")"

# Run the enhancement
echo "🚀 Starting Prospect Intelligence Enhancement"
echo "==========================================="
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Install required packages if needed
pip3 install aiohttp pyyaml --quiet

# Run the enhancement script
python3 enhance_all_prospects.py

echo ""
echo "✅ Enhancement process complete!"