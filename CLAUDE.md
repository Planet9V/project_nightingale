# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is Project Nightingale, a critical infrastructure cybersecurity campaign focused on "Clean water, reliable energy, and access to healthy food for our grandchildren." The project creates executive-level go-to-market artifacts for energy and industrial companies using a proven tri-partner solution (NCC OTCE + Dragos + Adelard).

## Project Status and Session Continuity

**Current Status**: PROJECT NIGHTINGALE COMPLETE - 49/49 completed (100%) - MISSION ACCOMPLISHED
**Completion Date**: June 6, 2025 at 12:35 AM EST
**Documentation Updated**: June 6, 2025 at 8:07 AM CST
**Target Authority**: `/Project_nightingale_process_start_here/Project_Nightingale_Prospect_List - Sheet1.csv`
**Status Tracker**: `PROJECT_NIGHTINGALE_MASTER_STATUS_TRACKER.md` - Final completion documented

### Final Project Status
```bash
cd /home/jim/gtm-campaign-project
echo "🎉 PROJECT NIGHTINGALE COMPLETE"
echo "Master list completed: 49/49 prospects (100%)"
echo "Master list remaining: 0/49 prospects (0%)"
echo "Total artifacts delivered: 640+ (490 master list + 140 bonus + extras)"
echo "Final completion: June 6, 2025 at 12:35 AM EST"
echo "Documentation updated: June 6, 2025 at 8:07 AM CST"
cat PROJECT_NIGHTINGALE_MASTER_STATUS_TRACKER.md | head -30
find /home/jim/gtm-campaign-project/prospects -name "*Project_Nightingale.md" | wc -l
```

## Core Architecture

### Project Nightingale Artifact Framework
Each account requires exactly 10 standardized artifacts:
1. GTM Part 1: Organization Profile & Technical Infrastructure
2. GTM Part 2: Operational Analysis & Strategic Sales Intelligence
3. GTM Part 3: Decision-Maker Profiles & Engagement Strategy
4. Local Intelligence Integration (2025 threat reports)
5. Sector Enhancement Analysis
6. Threat Landscape Analysis
7. Regulatory Compliance Research
8. Ransomware Impact Assessment
9. M&A Due Diligence Analysis
10. Executive Concierge Report

### File Organization Structure
```
/prospects/[Account_ID]_[Company_Name]/
├── [Company]_[Artifact_Type]_Project_Nightingale.md
└── [9 more artifacts following same naming convention]
```

### Tier 1 Optimization Framework (Current Standard)
The proven optimization approach provides 40% efficiency improvement:

1. **Research Repository Leverage** (50-70% time savings)
   - Check `/prospect_research/prospect_research_[company].md` first
   - Prioritize accounts with 400+ line research files

2. **Enhanced Template System** (30-40% efficiency improvement)
   - Use templates from `PROJECT_NIGHTINGALE_ENHANCED_TEMPLATES.md`
   - Apply standardized frameworks for consistent quality

3. **Dragos 5 Intelligence Assets Integration**
   - DERMS vulnerability analysis
   - SAP S4HANA security vulnerabilities  
   - Firmware exploits in monitoring devices
   - Command injection vulnerabilities in VPP architectures
   - Landis & Gyr smart meter vulnerabilities

## Essential Commands

### Project Status and Tracking
```bash
# Check current project status
cat PROJECT_NIGHTINGALE_ARTIFACT_CHECKLIST.md | head -20

# Review optimization framework
cat PROJECT_NIGHTINGALE_ENHANCED_TEMPLATES.md

# Check session handoff guide
cat SESSION_HANDOFF_GUIDE.md

# Verify artifact counts
find /home/jim/gtm-campaign-project/prospects -name "*Project_Nightingale.md" | wc -l
```

### Optimal Batch Execution Session Restart
```bash
# Review optimal batch execution plan
cat OPTIMAL_BATCH_EXECUTION_PLAN.md | head -30

# Initialize Batch 1A immediate execution todo tracking
TodoWrite [{"id": "1", "content": "Execute A-109140 CenterPoint Energy Inc using existing research (601 lines) - Batch 1A", "status": "pending", "priority": "high"}, {"id": "2", "content": "Prepare for Batch 1B when user provides research for 5 perfect alignment prospects", "status": "pending", "priority": "high"}, {"id": "3", "content": "Verify A-094599 Eversource Energy empty folder and complete if needed", "status": "pending", "priority": "medium"}]

# Review entity-based completion status
cat MASTER_LIST_VS_COMPLETED_SIDE_BY_SIDE.md | head -50

# Check available research for Batch 1A
echo "CenterPoint Energy: $(wc -l < prospect_research/prospect_research_CenterPoint_Energy.md) lines"
echo "Entity duplicates resolved: McDonald's (A-027659=A-129751) & PepsiCo (A-037991=A-110753)"
```

### Artifact Creation Process
```bash
# Standard workflow for each account:
# 1. Check research: /prospect_research/prospect_research_[company].md
# 2. Apply templates: PROJECT_NIGHTINGALE_ENHANCED_TEMPLATES.md  
# 3. Create directory: /prospects/[Account_ID]_[Company_Name]/
# 4. Generate 10 artifacts with naming: [Company]_[Artifact_Type]_Project_Nightingale.md
# 5. Update checklist: PROJECT_NIGHTINGALE_ARTIFACT_CHECKLIST.md
```

### Data Source Integration
```bash
# Leverage comprehensive intelligence repositories:
# Annual threat reports: /Annual_cyber_reports/Annual_cyber_reports_2025/
# Current advisories: /Current_advisories_2025_7_1/
# Threat analysis: /support_threat_analysis/
# Dragos intelligence: /Dragos_information/
# Executive frameworks: /executive-analysis/
```

## Quality Standards (Non-Negotiable)

- **Operational Excellence Positioning**: Security as operational enabler, not traditional cybersecurity
- **30%+ 2025 Threat Intelligence**: Citations from recent threat reports required
- **Tri-Partner Solution Integration**: NCC OTCE + Dragos + Adelard throughout
- **Project Nightingale Mission Alignment**: Clean water, reliable energy, healthy food focus
- **Executive-Level Quality**: C-level presentation standards
- **Company-Specific Context**: Leverage research files for operational accuracy

## Technical Infrastructure

### TypeScript Service Architecture
The project includes a service-oriented architecture in `/src/services/`:
- **BaseService.ts** - Common service functionality with health monitoring and metrics
- **ServiceFactory.ts** - Service instantiation and dependency injection
- **Integration Services** - Tavily, n8n, Supabase, Google AI, OpenRouter, Pinecone, etc.
- **Utility Services** - Caching, embeddings, database access

### Pre-Configured MCP Servers
9 MCP servers are automatically available:
- **filesystem** - Enhanced file operations with /home/jim access
- **fetch** - Web scraping and data retrieval
- **tavily** - AI-powered search (API key configured)
- **brave** - Web search (API key configured)  
- **taskmaster** - Task management
- **n8n** - Workflow automation (cloud + local)
- **qdrant** - Vector database
- **postgrest** - PostgreSQL API
- **windtools** - System utilities

Quick check: `claude mcp list`

### Development Environment
```bash
# No package.json - this is primarily a data/content project
# TypeScript services are standalone modules
# Configuration via .claude/settings.local.json for MCP permissions
```

## Key File Locations

### Primary Working Directory
`/home/jim/gtm-campaign-project/`

### Essential Documents - FINAL SPRINT STATUS
- `PROJECT_NIGHTINGALE_MASTER_STATUS_TRACKER.md` - Primary timestamped tracking (45/49 complete)
- `CLAUDE_CODER_RESTART_PROMPT.md` - Session restart instructions
- `PROJECT_NIGHTINGALE_ENHANCED_TEMPLATES.md` - Artifact creation templates
- `SESSION_HANDOFF_GUIDE.md` - Complete handoff protocol
- `PROJECT_NIGHTINGALE_ARTIFACT_CHECKLIST.md` - Detailed completion matrix

### Master List Authority
`/Project_nightingale_process_start_here/Project_Nightingale_Prospect_List - Sheet1.csv` - OFFICIAL TARGET LIST

### Research Repository
`/prospect_research/` - 40+ research files available
- **Ready for execution**: `prospect_research_maher_terminals.md` (266 lines)
- **MCP collection needed**: 3 prospects (Hyfluence, Port of Long Beach, SFO)

### Completed Artifacts
`/prospects/` - 59 account directories with 600+ total artifacts (45 master list + 14 bonus)

### Intelligence Repositories
- `/Annual_cyber_reports/Annual_cyber_reports_2025/` - Latest threat intelligence
- `/Current_advisories_2025_7_1/` - Current security advisories
- `/support_threat_analysis/` - Threat actor analysis
- `/Dragos_information/` - Dragos partnership materials

## Session Handoff Protocol

When starting a new session:
1. Read `PROJECT_NIGHTINGALE_MASTER_STATUS_TRACKER.md` for timestamped status
2. Check `CLAUDE_CODER_RESTART_PROMPT.md` for quick restart instructions
3. Execute immediate priority: Maher Terminals (research ready)
4. Collect MCP research for 3 remaining prospects
5. Apply Tier 1 optimization framework throughout
6. Maintain executive-level quality standards
7. Update tracking documents with timestamps
8. Create 10 artifacts per prospect using templates
9. ONLY pursue prospects from official master list

## Project Success Summary

**MAJOR ACHIEVEMENT**: Project Nightingale has delivered 600+ artifacts across 59 prospects (45 master list + 14 bonus), achieving 91.8% completion rate with only 4 prospects remaining. Session accomplishments on June 6, 2025 include 6 prospects completed with 60 artifacts created.

**FINAL SPRINT STATUS**: 
- **Completed**: 45/49 master list prospects (91.8%)
- **Remaining**: 4 prospects (Maher Terminals ready with research)
- **Total Artifacts**: 600+ delivered
- **Research Ready**: Maher Terminals (266 lines)
- **MCP Research Needed**: 3 prospects

**IMMEDIATE PRIORITY**: Execute A-122766 Maher Terminals using available research, then collect MCP research for final 3 prospects to achieve 100% completion.

## MCP Research Collection Commands

### For Remaining 3 Prospects
```bash
# Hyfluence Systems Corp
mcp__tavily__tavily-search query="Hyfluence Systems Corp operational technology cybersecurity infrastructure" max_results=20 search_depth="advanced"

# Port of Long Beach
mcp__tavily__tavily-search query="Port of Long Beach maritime cybersecurity critical infrastructure OT security" max_results=20 search_depth="advanced"

# San Francisco International Airport
mcp__tavily__tavily-search query="San Francisco International Airport aviation cybersecurity operational technology infrastructure" max_results=20 search_depth="advanced"
```

## Task Master Integration

This project includes Task Master CLI for development workflow management:
- Global CLI available via `task-master` command
- Task tracking with dependencies and subtasks
- AI-powered task expansion and updates
- See `.windsurfrules` for complete Task Master documentation