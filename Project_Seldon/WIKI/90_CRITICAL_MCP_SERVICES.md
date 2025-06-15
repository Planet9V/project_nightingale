# Critical MCP Services Configuration

## Overview
Three MCP services are **CRITICAL** for Project Seldon development and must always be running:
1. **Context7** - Real-time documentation lookup
2. **SuperMemory** - Persistent memory across sessions
3. **Knowledge Graph Memory** - Entity and relationship tracking

## 🚨 IMPORTANT: Always Check Status!

Run this command at the start of every session:
```bash
node src/scripts/check-mcp-health.js
```

## Service Configurations

### 1. Context7 (Documentation)
**Status**: ✅ Configured  
**Purpose**: Fetches up-to-date documentation for libraries and frameworks

```json
{
  "context7": {
    "command": "npx",
    "args": ["-y", "@upstash/context7-mcp@latest"],
    "env": {},
    "disabled": false,
    "autoApprove": ["get-library-docs", "resolve-library-id"]
  }
}
```

**Usage**:
```
How to fix TypeScript errors? use context7
```

### 2. SuperMemory (Persistent Context)
**Status**: ✅ Configured  
**Purpose**: Maintains memory across different LLM sessions

```json
{
  "supermemory": {
    "command": "npx",
    "args": ["-y", "supermemoryai-supermemory-mcp@latest"],
    "env": {},
    "disabled": false,
    "autoApprove": ["add_memory", "get_memories", "search_memories", "delete_memory"]
  }
}
```

**Setup**:
1. Visit https://mcp.supermemory.ai
2. Get your unique URL (save it securely!)
3. The service will auto-configure

**Usage**:
- Add memory: "Remember that we fixed TypeScript module errors"
- Search: "What TypeScript errors did we fix?"

### 3. Knowledge Graph Memory (Relationships)
**Status**: ✅ Configured  
**Purpose**: Builds a knowledge graph of entities and relationships

```json
{
  "knowledge-graph-memory": {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-memory"],
    "env": {
      "MEMORY_FILE_PATH": "/home/jim/gtm-campaign-project/.mcp-memory/knowledge-graph.jsonl"
    },
    "disabled": false,
    "autoApprove": [
      "create_entities", "create_relations", "add_observations",
      "delete_entities", "delete_observations", "delete_relations",
      "read_graph", "search_nodes", "open_nodes"
    ]
  }
}
```

**Usage**:
- Start sessions with: "Remembering..."
- Creates entities for: Projects, Files, Errors, Solutions
- Tracks relationships between components

## Development Workflow

### 1. Session Start Checklist
```bash
# 1. Check MCP health
node src/scripts/check-mcp-health.js

# 2. Load previous context
"Remembering..." 

# 3. Check current todos
(Use TodoRead tool)

# 4. Review recent changes
git status
```

### 2. During Development

#### Use Context7 for Documentation
```
# TypeScript issues
"How to configure tsconfig for CommonJS? use context7"

# Library usage
"Pinecone upsert examples TypeScript use context7"

# Error resolution
"Fix TS2503 namespace error use context7"
```

#### Update SuperMemory Regularly
```
# After fixing issues
"Remember: Fixed TypeScript module resolution by changing to CommonJS"

# After configuration changes
"Remember: Updated Pinecone index to 768 dimensions for jina-clip-v2"

# After completing tasks
"Remember: Completed Jina + Pinecone integration documentation"
```

#### Build Knowledge Graph
The Knowledge Graph automatically tracks:
- **Entities**: Files, Errors, Solutions, Configurations
- **Relations**: "fixes", "causes", "depends_on", "configures"
- **Observations**: Timestamps, status changes, outcomes

### 3. Session End
```
# 1. Update final memories
"Remember: Session ended with X tasks completed, Y pending"

# 2. Check memory was saved
"What did we accomplish today?"

# 3. Verify knowledge graph
"Show current project status from memory"
```

## Troubleshooting

### If MCP Services Fail

1. **Check Node.js Version**
   ```bash
   node -v  # Must be 18+
   ```

2. **Restart Editor**
   - Close Cursor/VSCode completely
   - Reopen and check MCP panel

3. **Manual Test**
   ```bash
   # Test Context7
   npx -y @upstash/context7-mcp@latest

   # Test SuperMemory
   npx -y supermemoryai-supermemory-mcp@latest

   # Test Knowledge Graph
   npx -y @modelcontextprotocol/server-memory
   ```

4. **Check Logs**
   - Open Output panel in editor
   - Select "MCP" from dropdown
   - Look for error messages

### Common Issues

| Issue | Solution |
|-------|----------|
| "MCP server not found" | Restart editor, check config |
| "Context7 returns nothing" | Library might not be indexed, use web search |
| "Memory not persisting" | Check SuperMemory URL is saved |
| "Knowledge graph empty" | Start with "Remembering..." |

## Best Practices

### 1. Memory Hygiene
- Clear outdated memories periodically
- Use specific, searchable terms
- Tag memories with project/feature names

### 2. Context7 Efficiency
- Be specific about language/version
- Include error codes for better results
- Fall back to web search for very new features

### 3. Knowledge Graph Structure
- Create clear entity names
- Use consistent relationship types
- Add detailed observations

## Integration with Project Seldon

### Priority Usage
1. **Context7** - All TypeScript/library issues
2. **SuperMemory** - Session continuity, progress tracking
3. **Knowledge Graph** - Component relationships, error patterns

### Example Workflow
```bash
# Start
"Remembering..."  # Load knowledge graph
node src/scripts/startup-check.js  # Check health

# Debug TypeScript
"What causes TS2503 error? use context7"
"Remember: TS2503 fixed by importing zod correctly"

# Track progress
"Create entity: TypeScript-Fixes"
"Add observation to TypeScript-Fixes: Fixed 150 errors, 50 remaining"

# End session
"Remember: Completed TypeScript configuration fixes, pending Jina activation"
```

## Monitoring & Maintenance

### Daily Checks
- Run health check script
- Verify memory persistence
- Check knowledge graph growth

### Weekly Maintenance
- Review and clean old memories
- Export knowledge graph backup
- Update documentation with new patterns

### Backup Commands
```bash
# Backup knowledge graph
cp .mcp-memory/knowledge-graph.jsonl .mcp-memory/backup-$(date +%Y%m%d).jsonl

# Check memory size
du -h .mcp-memory/

# View recent memories
tail -20 .mcp-memory/knowledge-graph.jsonl | jq
```

---

**Remember**: These services are CRITICAL! Always ensure they're running for optimal development experience.

**Last Updated**: June 13, 2025  
**Priority**: CRITICAL - Check every session!