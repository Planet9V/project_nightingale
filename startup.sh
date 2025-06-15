#!/bin/bash

# Project Nightingale Unified Startup Check
# This script provides a complete view of all MCP servers and project status

echo "🚀 Project Nightingale Unified Startup Check"
echo "============================================"
echo ""

# 1. Show current date/time
echo "📅 Current Date/Time:"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S %Z')
echo "$TIMESTAMP"
echo ""

# Store timestamp for later use
export STARTUP_TIMESTAMP="$TIMESTAMP"

# 2. Check all MCP servers
echo "🔍 Checking ALL MCP Servers..."
echo "--------------------------------------------"
cd Project_Seldon && npm run mcp-check 2>&1 | tail -n +4
cd ..
echo ""

# 3. Run Project Seldon startup checks
echo "🏗️  Project Seldon Status..."
echo "--------------------------------------------"
cd Project_Seldon && npm run startup 2>&1 | grep -E "(✅|❌|⚠️|Missing|Ready|configured)" | grep -v "npm run"
cd ..
echo ""

# 4. Show SuperMemory initialization
echo "📝 SuperMemory Initialization:"
echo "--------------------------------------------"
echo "1. Store session start:"
echo "   \"Remember that [$STARTUP_TIMESTAMP] SESSION_START: New session initiated\""
echo ""
echo "2. Load previous session:"
echo "   \"What do you remember about the last session?\""
echo ""

# 5. Show quick reference
echo "📋 Quick Reference:"
echo "--------------------------------------------"
echo "• Full MCP status:        npm run mcp-status"
echo "• Critical services only: npm run mcp-health"
echo "• SuperMemory init:       npm run supermemory-init"
echo "• Project Seldon checks:  npm run startup"
echo "• This unified check:     ./startup.sh"
echo ""
echo "• Start session with:     'Remembering...'"
echo "• Use Context7 with:      'use context7'"
echo "• Store progress with:    'Remember that [timestamp] [action]'"
echo ""

# Make the script executable on first run
chmod +x startup.sh 2>/dev/null

echo "✅ Startup check complete!"