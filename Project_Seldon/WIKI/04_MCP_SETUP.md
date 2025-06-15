# MCP Server Setup & Fixes

## Overview
This guide covers fixing ALL MCP servers including Context7, ensuring 100% functionality.

## Current MCP Configuration Issues & Fixes

### 1. Context7 Fix

**Issue**: Context7 not loading properly
**Solution**: Update MCP configuration with proper package name

```json
"context7": {
    "command": "npx",
    "args": [
        "-y",
        "--package=@context-labs/context7-mcp",
        "@context-labs/context7-mcp"
    ],
    "env": {
        "CONTEXT7_API_KEY": "optional-api-key"
    }
}
```

### 2. Task Master AI Fix

**Issue**: Missing API keys
**Solution**: Add actual API keys from environment

```json
"task-master-ai": {
    "command": "npx",
    "args": [
        "-y",
        "--package=task-master-ai",
        "task-master-ai"
    ],
    "env": {
        "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}",
        "PERPLEXITY_API_KEY": "pplx-YOUR_KEY_HERE",
        "OPENAI_API_KEY": "sk-YOUR_KEY_HERE",
        "GOOGLE_API_KEY": "YOUR_KEY_HERE",
        "MISTRAL_API_KEY": "YOUR_KEY_HERE"
    }
}
```

### 3. Complete MCP Health Check Script

```typescript
// src/scripts/check-mcp-servers.ts
import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile } from 'fs/promises';

const execAsync = promisify(exec);

interface MCPServer {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
}

export async function checkMCPServers() {
  const mcpConfig = JSON.parse(
    await readFile('.cursor/mcp.json', 'utf-8')
  );
  
  const results: Record<string, boolean> = {};
  
  for (const [name, config] of Object.entries(mcpConfig.mcpServers)) {
    try {
      console.log(`Checking ${name}...`);
      const server = config as MCPServer;
      
      // Test if package exists
      const testCmd = `${server.command} ${server.args.join(' ')} --version`;
      await execAsync(testCmd, { 
        env: { ...process.env, ...server.env } 
      });
      
      results[name] = true;
      console.log(`✅ ${name} is working`);
    } catch (error) {
      results[name] = false;
      console.log(`❌ ${name} failed: ${error.message}`);
    }
  }
  
  return results;
}
```

## MCP Server Capabilities

### 1. **Pinecone** (Vector Database)
- Store embeddings (768 dimensions)
- Semantic search
- Metadata filtering
- Namespace support

### 2. **Neo4j** (Graph Database)
- Entity relationships
- Graph traversal
- Pattern matching
- Visualization

### 3. **Graphlit** (Content Management)
- Document processing
- Content extraction
- Metadata enrichment

### 4. **Tavily** (Web Search)
- Real-time search
- Content extraction
- URL crawling
- Structured data

### 5. **Jina AI** (Embeddings & AI)
- Text embeddings
- Document reranking
- Classification
- Deep search

### 6. **Context7** (Documentation Search)
- Code search
- Documentation retrieval
- Context understanding

### 7. **Task Master AI** (Project Management)
- Task generation
- Progress tracking
- Complexity analysis
- Dependencies

### 8. **Sequential Thinking** (Analysis)
- Complex reasoning
- Step-by-step analysis
- Problem decomposition

### 9. **AntV Charts** (Visualization)
- Data visualization
- Chart generation
- Analytics dashboards

## Installation Commands

```bash
# Install all MCP dependencies
npm install -g @context-labs/context7-mcp
npm install -g @pinecone-database/mcp
npm install -g neo4j-mcpserver
npm install -g graphlit-mcp-server
npm install -g tavily-mcp@latest
npm install -g jina-ai-mcp-server
npm install -g @modelcontextprotocol/server-sequential-thinking
npm install -g @antv/mcp-server-chart
npm install -g task-master-ai

# Verify installations
npm list -g --depth=0 | grep mcp
```

## Environment Variables Required

```bash
# .env file
PINECONE_API_KEY=pcsk_4J7GV7_87FLZsGapSz7gF6885tYRGU34rTKJLZd62RjQpH2F4iA1kgikkRH4PYAkX2RjYH
NEO4J_URI=neo4j+s://82dcab45.databases.neo4j.io
NEO4J_USER=neo4j
NEO4J_PASSWORD=0Vd7DG61C472nBRCysOtD3NCQjPDRmpL6SFlm-K7XSE
TAVILY_API_KEY=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
JINA_API_KEY=jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q
GRAPHLIT_JWT_SECRET=L0Gis4mvVmBYYmAiJco1VKKfC6rrMM8oEL0uKBJTTOc=
```

## Testing MCP Integration

```typescript
// Example: Using Tavily for research
const searchResults = await tavily.search({
  query: "latest cybersecurity threats 2025",
  max_results: 10,
  search_depth: "advanced"
});

// Example: Using Jina for embeddings
const embedding = await jina.embed({
  text: "Sample document content",
  model: "jina-embeddings-v2-base-en"
});

// Example: Using Context7 for docs
const docs = await context7.search({
  query: "how to implement vector search",
  scope: "documentation"
});
```

## Troubleshooting

### Common Issues:

1. **"Package not found"**
   - Run: `npm cache clean --force`
   - Reinstall with `--force` flag

2. **"Permission denied"**
   - Use `sudo` for global installs
   - Or use local installation

3. **"API key invalid"**
   - Check environment variables
   - Verify key format

4. **"Connection timeout"**
   - Check network connectivity
   - Verify server URLs

## Next Steps
- [Database Architecture](./10_DATABASE_ARCHITECTURE.md)
- [ETL Pipeline Design](./11_ETL_PIPELINE.md)