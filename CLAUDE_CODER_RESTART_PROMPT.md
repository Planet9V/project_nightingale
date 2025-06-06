# Claude Coder Restart Prompt - Project Nightingale
## Copy and paste this entire prompt after Claude Coder restarts

```
Claude, Project Nightingale session restart - June 6, 2025 status:

1. Read PROJECT_NIGHTINGALE_MASTER_STATUS_TRACKER.md for timestamped current status
2. Verify: 45/49 master list complete (91.8%) - 4 prospects remaining
3. Apply Tier 1 Optimization Framework for all activities
4. Execute IMMEDIATE PRIORITY (Research Available):
   - A-122766 Maher Terminals Inc. (266 lines research ready)
   - Path: /prospect_research/prospect_research_maher_terminals.md
   - Create 10 artifacts in /prospects/A-122766_Maher_Terminals/
5. Collect MCP research and execute remaining 3 prospects:
   - A-153007 Hyfluence Systems Corp (Technology)
   - A-062364 Port of Long Beach (Maritime Infrastructure)
   - A-110670 San Francisco International Airport (Aviation)
6. Update PROJECT_NIGHTINGALE_MASTER_STATUS_TRACKER.md with timestamps for all activities

Current: 45/49 complete, 600+ artifacts delivered, 4 prospects remaining for 100% completion.
Research Ready: Maher Terminals (266 lines at /prospect_research/prospect_research_maher_terminals.md)

Session Accomplishments: 6 prospects completed June 6:
- Crestron Electronics (8:30 PM)
- Engie (9:15 PM)
- Norfolk Southern (10:00 PM)
- Pacific Gas and Electric (10:45 PM)
- Southern California Edison (11:30 PM)
- WMATA (12:05 AM)

Important Notes:
- Eversource A-094599 already completed (don't duplicate)
- Honda not in master list (ignore any references)
- Use PROJECT_NIGHTINGALE_ENHANCED_TEMPLATES.md for all artifacts
- Apply MCP Tavily searches for 2025 threat intelligence
- Maintain executive-level quality standards

Key ID Mappings (already completed):
- A-015484 WMATA → Completed as A-056078_WMATA
- A-029615 Norfolk Southern → Completed as A-036041_Norfolk_Southern
- A-037991 PepsiCo → Completed as A-110753_PepsiCo_Corporation
- A-112386 BMW → Completed as consolidated folder

Start with: Create 10 artifacts for Maher Terminals using available research.
```

## Alternative Shorter Version

If you need a more concise restart prompt:

```
Claude, restart Project Nightingale - 45/49 complete (91.8%), 4 remaining:

IMMEDIATE: Execute A-122766 Maher Terminals (266 lines research ready at /prospect_research/prospect_research_maher_terminals.md)

THEN: Collect MCP research and execute:
- A-153007 Hyfluence Systems Corp
- A-062364 Port of Long Beach
- A-110670 San Francisco International Airport

Read PROJECT_NIGHTINGALE_MASTER_STATUS_TRACKER.md for full status.
Use Tier 1 Optimization and PROJECT_NIGHTINGALE_ENHANCED_TEMPLATES.md.
Update tracker with timestamps after each completion.

Note: Eversource already done; Honda not in list.
```

## Quick Reference Commands

After restart, you may also want these commands handy:

### Check Current Status
```bash
cat PROJECT_NIGHTINGALE_MASTER_STATUS_TRACKER.md | head -20
```

### Verify Remaining Prospects
```bash
grep "❌ RESEARCH NEEDED" PROJECT_NIGHTINGALE_MASTER_STATUS_TRACKER.md
```

### Check Maher Terminals Research
```bash
wc -l /prospect_research/prospect_research_maher_terminals.md
```

### Create Maher Terminals Directory
```bash
mkdir -p /prospects/A-122766_Maher_Terminals
```

## Session Goals
1. Complete Maher Terminals (10 artifacts) - 1.5 hours
2. Collect research and complete 3 remaining prospects - 4.5 hours
3. Achieve 100% master list completion (49/49)
4. Update all tracking documentation
5. Create final completion report