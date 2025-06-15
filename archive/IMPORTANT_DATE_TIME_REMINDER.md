# IMPORTANT: Always Use Actual Date/Time

## Critical Reminder for All Sessions

**ALWAYS check the actual system date and time using:**
```bash
date
# or for formatted output:
date "+%B %d, %Y %I:%M %p %Z"
```

## Why This Matters
- Claude's internal clock may not match the actual system time
- Project Nightingale requires accurate timestamping for:
  - Version control tracking
  - Session handoff documentation
  - Activity logs
  - MCP configuration updates
  - Progress tracking

## Current System Time
As of this document creation: June 12, 2025 9:09 AM CDT

## Implementation
1. At the start of EVERY session, run: `date`
2. Use the actual system time for all timestamps
3. Never rely on Claude's perceived time
4. Update all documentation with real timestamps

**Remember**: Project documentation integrity depends on accurate timestamps!