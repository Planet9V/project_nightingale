# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is Project Nightingale, a critical infrastructure cybersecurity campaign focused on "Clean water, reliable energy, and access to healthy food for our grandchildren." The project creates executive-level go-to-market artifacts for energy and industrial companies using a proven tri-partner solution (NCC OTCE + Dragos + Adelard).

## Project Status and Session Continuity

**Current Status**: OFFICIAL MASTER LIST TRACKING - 29/56 completed (51.8%) - ENTITY-BASED COMPLETION
**Target Authority**: `/Project_nightingale_process_start_here/Project_Nightingale_Prospect_List - Sheet1.csv`
**Next Phase**: Complete remaining 27 prospects using optimal batch execution framework

### Quick Status Check
```bash
cd /home/jim/gtm-campaign-project
echo "Master list completed: 29/56 prospects (51.8%) - ENTITY-BASED COMPLETION"
echo "Master list remaining: 27/56 prospects (48.2%)"
echo "Total artifacts delivered: 440 (290 master list + 150 bonus)"
echo "Entity duplicates resolved: McDonald's & PepsiCo identified as completed"
echo "Batch 1A ready: 1 prospect with research (A-109140 CenterPoint Energy)"
cat OPTIMAL_BATCH_EXECUTION_PLAN.md | head -30
cat MASTER_LIST_VS_COMPLETED_SIDE_BY_SIDE.md | head -30
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

### Essential Documents - UPDATED FOR MASTER LIST AUTHORITY
- `SESSION_HANDOFF_GUIDE.md` - Complete restart instructions with accurate status
- `PROJECT_NIGHTINGALE_ARTIFACT_CHECKLIST.md` - Real-time progress tracking (27/56 complete)
- `MASTER_LIST_VS_COMPLETED_SIDE_BY_SIDE.md` - Accurate side-by-side comparison
- `OFFICIAL_MASTER_LIST_STATUS.md` - Authoritative tracking document
- `PROJECT_NIGHTINGALE_ENHANCED_TEMPLATES.md` - Optimization templates

### Master List Authority
`/Project_nightingale_process_start_here/Project_Nightingale_Prospect_List - Sheet1.csv` - OFFICIAL TARGET LIST

### Research Repository
`/prospect_research/` - 37 research files available (3 ready for immediate execution)

### Completed Artifacts
`/prospects/` - 42 account directories with 420 total artifacts (27 master list + 15 bonus)

### Research Collection Plan
`MASTER_LIST_RESEARCH_COLLECTION_PLAN.md` - MCP strategy for remaining 26 prospects

## Session Handoff Protocol

When starting a new session:
1. Check `SESSION_HANDOFF_GUIDE.md` for current accurate master list status
2. Review `MASTER_LIST_VS_COMPLETED_SIDE_BY_SIDE.md` for precise completion tracking
3. Execute immediate priorities: 3 prospects with research available
4. Review `PROJECT_NIGHTINGALE_ARTIFACT_CHECKLIST.md` for detailed completion matrix
5. Apply proven Tier 1 optimization framework for 40% efficiency improvement
6. Use available research files for enhanced quality and speed
7. Maintain executive-level quality standards throughout
8. Update tracking documents in real-time
9. ONLY pursue prospects from official master list - NO DEVIATIONS

## Project Success Summary

**MAJOR ACHIEVEMENT**: Project Nightingale has successfully delivered 440 artifacts across 44 prospects (29 master list + 15 bonus) using proven Tier 1 optimizations and ENTITY-BASED COMPLETION LOGIC, demonstrating 40% efficiency improvement while maintaining executive-level quality standards. Master list completion stands at 29/56 (51.8%) with optimal batch execution framework established.

**IMMEDIATE EXECUTION STATUS**: Batch 1A ready with 1 prospect (A-109140 CenterPoint Energy). Batch 1B prepared for 5 perfect alignment prospects awaiting user research. Optimal batch execution plan created for remaining 27 prospects. All documentation updated for seamless session handoff with ZERO duplicated work risk.

The project uses a proven methodology with template-driven efficiency while maintaining premium quality standards for executive engagement and perfect Project Nightingale mission alignment.

## Memories
- "to memorize"