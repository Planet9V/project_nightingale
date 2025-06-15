# SuperMemory MCP Integration Guide

## Overview
SuperMemory is a persistent memory system for Claude that maintains context across sessions. It stores memories in a cloud-based system accessible via a unique URL.

## Key Features
- **Persistent Storage**: Memories survive between sessions
- **Auto-approved Operations**: add_memory, get_memories, search_memories, delete_memory
- **Cloud-based**: Accessible from any device with your unique URL

## Implementation Strategy

### 1. Startup Memory Load
At the beginning of each session, SuperMemory should:
- Load previous session context
- Retrieve project status
- Get recent activity logs

### 2. Continuous Memory Updates
Throughout the session:
- Log all significant actions with timestamps
- Track completed tasks and milestones
- Record configuration changes
- Store error resolutions and fixes

### 3. Memory Structure
Each memory entry should include:
```
[TIMESTAMP] Category: Description
Example: [2025-06-14 10:30:00 CDT] PROJECT_STATUS: Removed 4 MCPs from configuration (graphlit, task-master-ai, brave, windtools)
```

### 4. Categories for Organization
- SESSION_START: Session initialization details
- PROJECT_STATUS: Major project updates
- TASK_COMPLETE: Completed tasks
- CONFIG_CHANGE: Configuration modifications
- ERROR_FIX: Problem resolutions
- DECISION: Important architectural decisions

## Usage Commands

### Store Memory
"Remember that [specific information]"

### Retrieve Memories
"What do you remember about [topic]?"

### Search Memories
"Search memories for [keyword]"

## Best Practices
1. Always include timestamps in memories
2. Use consistent categories
3. Be specific and concise
4. Store actionable information
5. Update progress regularly