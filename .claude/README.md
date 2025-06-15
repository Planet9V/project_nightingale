# Claude Code MCP Configuration

This directory contains the Model Context Protocol (MCP) server configuration for Claude Code.

## 📁 Directory Structure

- `mcp.json` - Main MCP server configuration (tracked in Git)
- `.env` - API keys and secrets (create from `.env.example`, NOT tracked in Git)
- `.env.example` - Template for API keys (tracked in Git)
- `README.md` - This file

## 🚀 Quick Start

1. **Check MCP Status**: Run `npm run mcp-status` from the project root
2. **Configure Missing Services**: Copy `.env.example` to `.env` and add your API keys
3. **Verify Critical Services**: Ensure Context7, SuperMemory, and Knowledge Graph are available

## 🔧 Available MCP Servers

### ✅ Critical Services (Required)
- **Context7**: Documentation and code context lookup
- **SuperMemory**: Cross-session memory persistence
- **Knowledge Graph Memory**: Entity relationship tracking

### 📊 Intelligence Services
- **Pinecone**: Vector search (670+ artifacts indexed)
- **Neo4j**: Graph database for relationships
- **Graphlit**: Document intelligence system
- **Jina AI**: Document processing and embeddings
- **Tavily**: Advanced web search

### 🛠️ Development Tools
- **Task Master AI**: Project management
- **Sequential Thinking**: Complex reasoning
- **AntV Charts**: Data visualization
- **Filesystem**: Local file operations
- **Fetch**: HTTP/API requests
- **Brave Search**: Web search

### ⚙️ Optional Services (Need Configuration)
- **n8n**: Workflow automation
- **PostgREST**: Database API
- **Qdrant**: Alternative vector database
- **Windtools**: Additional dev tools

## 📝 Configuration

The `mcp.json` file is tracked in Git and travels with the codebase. This ensures:
- Consistent MCP setup across workstations
- No manual configuration needed when cloning
- Version-controlled server definitions

API keys should be stored in `.env` (not tracked) or as environment variables.

## 🔍 Health Check Commands

```bash
# Check all MCP servers
npm run mcp-status

# Check only critical services
npm run mcp-health

# Full startup check
npm run check-all
```

## 🚨 Troubleshooting

If servers show as failed:
1. Check if API keys are missing (shown in health check output)
2. Ensure Node.js 18+ is installed
3. Check network connectivity
4. Review server-specific error messages

## 🔐 Security Notes

- Never commit API keys to Git
- Use `.env` file for local development
- Set environment variables in production
- The `.claude/` directory is intentionally tracked (except `.env`)