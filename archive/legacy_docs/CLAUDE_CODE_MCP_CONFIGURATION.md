# Claude Code MCP Configuration Documentation
## Project Nightingale - MCP Server Management

**Created**: January 7, 2025, 5:15 PM EST  
**Purpose**: Document MCP server configuration for Claude Code environment  

---

## 🔧 **ACTIVE MCP CONFIGURATION FILE**

**File Location**: `/home/jim/.vscode-server/data/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`

**Current Configured Servers**:
```json
✅ context7-mcp - Documentation and context management (@upstash/context7-mcp@latest)
✅ tavily-mcp - AI-powered search with API key (tavily-mcp@0.1.4)
✅ brave-search - Brave search API with key (@modelcontextprotocol/server-brave-search)
✅ github - GitHub operations with PAT (@modelcontextprotocol/server-github)  
✅ git - Git operations (mcp-server-git)
✅ filesystem - File operations (@modelcontextprotocol/server-filesystem)
```

**Additional Servers Available (Not in Config)**:
```json
✅ taskmaster - Project management (available via different mechanism)
✅ fetch - Web content fetching (available via different mechanism)
✅ ide - VS Code integration (available via different mechanism)
```

**Missing/Desired Servers**:
```json
❌ perplexity-search
❌ office-word-mcp-server
❌ excel-mcp-server  
❌ gmail
❌ google-calendar
❌ google-drive
```

---

## 📝 **CONFIGURATION FORMAT**

MCP servers are configured in JSON format with structure:
```json
{
  "mcpServers": {
    "server-name": {
      "command": "npx|uvx",
      "args": ["-y", "package-name@version"],
      "env": {
        "API_KEY": "value"
      },
      "disabled": false,
      "autoApprove": ["function1", "function2"]
    }
  }
}
```

---

## 🚀 **INSTALLATION ATTEMPTS**

### Office Word MCP Server Installation
**Command**: `npx -y @smithery/cli@latest install @GongRzhe/Office-Word-MCP-Server --client claude --key 41a4b4c3-fc25-49b1-9aaf-95d6ce56873b`
**Date**: January 7, 2025, 5:15 PM EST
**Status**: ✅ COMPLETED - Installation successful, Claude app restart requested
**Notes**: Smithery CLI installation completed successfully, anonymized usage data sharing accepted

---

**Note**: This file tracks MCP server configuration for Project Nightingale Claude Code environment.