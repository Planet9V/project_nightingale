# MCP Server Quick Reference

## 🚀 Auto-Available Every Session

These 9 MCP servers are automatically loaded in every Claude Code session:

## Core Servers

### filesystem
- **Purpose**: Enhanced file operations beyond basic Claude tools
- **Access**: Full /home/jim directory access
- **Usage**: Advanced file manipulation, bulk operations

### fetch  
- **Purpose**: Web scraping and data retrieval
- **Features**: HTTP requests, content parsing, data extraction
- **Usage**: Fetch web content, APIs, download data

### taskmaster
- **Purpose**: Claude task management and coordination
- **Features**: Multi-step task planning, progress tracking
- **Usage**: Complex workflow management

## Search & Intelligence

### tavily ✅
- **Purpose**: AI-powered search with context understanding
- **API**: Pre-configured with TAVILY_API_KEY
- **Usage**: Intelligent research, contextual search

### brave ✅  
- **Purpose**: Privacy-focused web search
- **API**: Pre-configured with BRAVE_API_KEY
- **Usage**: Web search, news, current events

## Database & Storage

### qdrant
- **Purpose**: Vector database for embeddings
- **Features**: Similarity search, ML workflows
- **Usage**: AI/ML projects, semantic search

### postgrest
- **Purpose**: PostgreSQL database API
- **Features**: REST API for database operations
- **Usage**: Database integration, data storage

## Automation

### n8n ✅
- **Purpose**: Workflow automation platform
- **Cloud**: https://jims67mustang.app.n8n.cloud
- **Local**: 127.0.0.1:5678, 100.113.4.39:5678, 192.168.1.87:5678
- **API**: Pre-configured for both cloud and local

### windtools
- **Purpose**: Windows system utilities
- **Features**: System automation, Windows-specific operations
- **Usage**: System administration, automation scripts

## Quick Commands

```bash
# List all servers
claude mcp list

# Get server details  
claude mcp get <server-name>

# Remove a server (if needed)
claude mcp remove <server-name>

# Test server functionality
claude mcp get filesystem
```

## API Keys (Pre-Configured)

All these API keys are automatically available:
- TAVILY_API_KEY ✅
- BRAVE_API_KEY ✅  
- N8N_API_KEY ✅
- JINA_API_KEY
- KAGI_API_KEY
- NEWSAPI_KEY
- GOOGLE_SCHOLAR_API_KEY

## Integration Examples

### Search Intelligence
```
Use tavily for: "Research latest cybersecurity trends in energy sector"
Use brave for: "Find recent news about industrial control systems"
```

### Data Operations
```
Use fetch for: "Scrape vulnerability data from security websites"
Use qdrant for: "Store and search threat intelligence embeddings"
```

### Automation
```
Use n8n for: "Trigger workflows when new threats are detected"
Use taskmaster for: "Coordinate multi-step security assessments"
```

**No setup required** - all servers ready to use immediately in every Claude Code session!