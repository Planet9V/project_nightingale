# Project Nightingale MCP Configuration Guide
## Complete Setup Instructions for All MCP Servers

**Document Classification**: Technical Configuration - SENSITIVE  
**Created**: January 11, 2025  
**Purpose**: Complete MCP server setup for Project Nightingale on new WSL/Claude Code installation  
**Security Note**: This document contains credentials - handle with care

---

## 🚀 Quick Setup Steps

### 1. Prerequisites
```bash
# Ensure Node.js and npm are installed
node --version  # Should be 18.x or higher
npm --version   # Should be 8.x or higher

# Create project directory if needed
mkdir -p ~/gtm-campaign-project
cd ~/gtm-campaign-project
```

### 2. Install All MCP Packages
```bash
# Install all MCP server packages
npm install --save-dev \
  @pinecone-database/mcp \
  graphlit-mcp-server \
  neo4j-mcpserver \
  task-master-ai

# Install supporting packages
npm install \
  @pinecone-database/pinecone \
  neo4j-driver
```

### 3. Create MCP Configuration File
Create the file `.cursor/mcp.json` with the complete configuration below:

```json
{
    "mcpServers": {
        "task-master-ai": {
            "command": "npx",
            "args": [
                "-y",
                "--package=task-master-ai",
                "task-master-ai"
            ],
            "env": {
                "ANTHROPIC_API_KEY": "ANTHROPIC_API_KEY_HERE",
                "PERPLEXITY_API_KEY": "PERPLEXITY_API_KEY_HERE",
                "OPENAI_API_KEY": "OPENAI_API_KEY_HERE",
                "GOOGLE_API_KEY": "GOOGLE_API_KEY_HERE",
                "XAI_API_KEY": "XAI_API_KEY_HERE",
                "OPENROUTER_API_KEY": "OPENROUTER_API_KEY_HERE",
                "MISTRAL_API_KEY": "MISTRAL_API_KEY_HERE",
                "AZURE_OPENAI_API_KEY": "AZURE_OPENAI_API_KEY_HERE",
                "OLLAMA_API_KEY": "OLLAMA_API_KEY_HERE"
            }
        },
        "graphlit": {
            "command": "npx",
            "args": [
                "-y",
                "--package=graphlit-mcp-server",
                "graphlit-mcp-server"
            ],
            "env": {
                "GRAPHLIT_API_URL": "https://data-scus.graphlit.io/api/v1/graphql",
                "GRAPHLIT_JWT_SECRET": "L0Gis4mvVmBYYmAiJco1VKKfC6rrMM8oEL0uKBJTTOc=",
                "GRAPHLIT_ORGANIZATION_ID": "92f3481e-24cf-4f7c-bb58-a544b226a571",
                "GRAPHLIT_ENVIRONMENT_ID": "3fbe0e93-733b-461b-a950-7f87d3d85d05"
            }
        },
        "pinecone": {
            "command": "npx",
            "args": [
                "-y",
                "--package=@pinecone-database/mcp",
                "@pinecone-database/mcp"
            ],
            "env": {
                "PINECONE_API_KEY": "pcsk_4J7GV7_87FLZsGapSz7gF6885tYRGU34rTKJLZd62RjQpH2F4iA1kgikkRH4PYAkX2RjYH",
                "PINECONE_HOST": "https://nightingale-dwk2rdy.svc.aped-4627-b74a.pinecone.io",
                "PINECONE_ENVIRONMENT": "us-east-1",
                "PINECONE_INDEX_NAME": "nightingale"
            }
        },
        "neo4j": {
            "command": "npx",
            "args": [
                "-y",
                "--package=neo4j-mcpserver",
                "neo4j-mcpserver"
            ],
            "env": {
                "NEO4J_URI": "neo4j+s://82dcab45.databases.neo4j.io",
                "NEO4J_USER": "neo4j",
                "NEO4J_PASSWORD": "0Vd7DG61C472nBRCysOtD3NCQjPDRmpL6SFlm-K7XSE",
                "NEO4J_DATABASE": "neo4j"
            }
        }
    }
}
```

---

## 📋 Individual MCP Server Details

### 1. Pinecone Vector Database
**Purpose**: Semantic search across Project Nightingale artifacts

**Credentials**:
- **API Key**: `pcsk_4J7GV7_87FLZsGapSz7gF6885tYRGU34rTKJLZd62RjQpH2F4iA1kgikkRH4PYAkX2RjYH`
- **Host**: `https://nightingale-dwk2rdy.svc.aped-4627-b74a.pinecone.io`
- **Index Name**: `nightingale`
- **Environment**: `us-east-1`
- **Dimensions**: 1024
- **Current Status**: Empty (0 vectors)

**Test Connection**:
```javascript
const { Pinecone } = require('@pinecone-database/pinecone');
const pc = new Pinecone({
  apiKey: 'pcsk_4J7GV7_87FLZsGapSz7gF6885tYRGU34rTKJLZd62RjQpH2F4iA1kgikkRH4PYAkX2RjYH'
});
const index = pc.index('nightingale', 'https://nightingale-dwk2rdy.svc.aped-4627-b74a.pinecone.io');
const stats = await index.describeIndexStats();
console.log(stats);
```

### 2. Neo4j Graph Database
**Purpose**: Relationship mapping for prospects, threats, and technologies

**Credentials**:
- **URI**: `neo4j+s://82dcab45.databases.neo4j.io`
- **Username**: `neo4j`
- **Password**: `0Vd7DG61C472nBRCysOtD3NCQjPDRmpL6SFlm-K7XSE`
- **Database**: `neo4j`
- **Version**: Neo4j 5.27-aura (enterprise)
- **Current Status**: Empty (0 nodes)

**Test Connection**:
```bash
# Using Neo4j driver
NEO4J_URI="neo4j+s://82dcab45.databases.neo4j.io" \
NEO4J_USER="neo4j" \
NEO4J_PASSWORD="0Vd7DG61C472nBRCysOtD3NCQjPDRmpL6SFlm-K7XSE" \
npx neo4j-mcpserver
```

### 3. Graphlit Content Management
**Purpose**: Document ingestion and content intelligence

**Credentials**:
- **API URL**: `https://data-scus.graphlit.io/api/v1/graphql`
- **JWT Secret**: `L0Gis4mvVmBYYmAiJco1VKKfC6rrMM8oEL0uKBJTTOc=`
- **Organization ID**: `92f3481e-24cf-4f7c-bb58-a544b226a571`
- **Environment ID**: `3fbe0e93-733b-461b-a950-7f87d3d85d05`
- **Current Status**: Connected but may need token refresh

### 4. Task Master AI
**Purpose**: Project and task management with AI assistance

**API Keys Required** (add your own):
- **ANTHROPIC_API_KEY**: Your Anthropic API key
- **PERPLEXITY_API_KEY**: Your Perplexity API key
- **OPENAI_API_KEY**: Your OpenAI API key
- Other keys as needed for your AI providers

---

## 🔧 Installation Script

Save this as `setup-mcp-servers.sh` and run it:

```bash
#!/bin/bash

echo "🚀 Setting up Project Nightingale MCP Servers..."

# Create directories
mkdir -p .cursor

# Install packages
echo "📦 Installing MCP packages..."
npm install --save-dev \
  @pinecone-database/mcp \
  graphlit-mcp-server \
  neo4j-mcpserver \
  task-master-ai \
  @pinecone-database/pinecone \
  neo4j-driver

# Create MCP configuration
echo "📝 Creating MCP configuration..."
cat > .cursor/mcp.json << 'EOF'
{
    "mcpServers": {
        "task-master-ai": {
            "command": "npx",
            "args": [
                "-y",
                "--package=task-master-ai",
                "task-master-ai"
            ],
            "env": {
                "ANTHROPIC_API_KEY": "ANTHROPIC_API_KEY_HERE",
                "PERPLEXITY_API_KEY": "PERPLEXITY_API_KEY_HERE",
                "OPENAI_API_KEY": "OPENAI_API_KEY_HERE",
                "GOOGLE_API_KEY": "GOOGLE_API_KEY_HERE",
                "XAI_API_KEY": "XAI_API_KEY_HERE",
                "OPENROUTER_API_KEY": "OPENROUTER_API_KEY_HERE",
                "MISTRAL_API_KEY": "MISTRAL_API_KEY_HERE",
                "AZURE_OPENAI_API_KEY": "AZURE_OPENAI_API_KEY_HERE",
                "OLLAMA_API_KEY": "OLLAMA_API_KEY_HERE"
            }
        },
        "graphlit": {
            "command": "npx",
            "args": [
                "-y",
                "--package=graphlit-mcp-server",
                "graphlit-mcp-server"
            ],
            "env": {
                "GRAPHLIT_API_URL": "https://data-scus.graphlit.io/api/v1/graphql",
                "GRAPHLIT_JWT_SECRET": "L0Gis4mvVmBYYmAiJco1VKKfC6rrMM8oEL0uKBJTTOc=",
                "GRAPHLIT_ORGANIZATION_ID": "92f3481e-24cf-4f7c-bb58-a544b226a571",
                "GRAPHLIT_ENVIRONMENT_ID": "3fbe0e93-733b-461b-a950-7f87d3d85d05"
            }
        },
        "pinecone": {
            "command": "npx",
            "args": [
                "-y",
                "--package=@pinecone-database/mcp",
                "@pinecone-database/mcp"
            ],
            "env": {
                "PINECONE_API_KEY": "pcsk_4J7GV7_87FLZsGapSz7gF6885tYRGU34rTKJLZd62RjQpH2F4iA1kgikkRH4PYAkX2RjYH",
                "PINECONE_HOST": "https://nightingale-dwk2rdy.svc.aped-4627-b74a.pinecone.io",
                "PINECONE_ENVIRONMENT": "us-east-1",
                "PINECONE_INDEX_NAME": "nightingale"
            }
        },
        "neo4j": {
            "command": "npx",
            "args": [
                "-y",
                "--package=neo4j-mcpserver",
                "neo4j-mcpserver"
            ],
            "env": {
                "NEO4J_URI": "neo4j+s://82dcab45.databases.neo4j.io",
                "NEO4J_USER": "neo4j",
                "NEO4J_PASSWORD": "0Vd7DG61C472nBRCysOtD3NCQjPDRmpL6SFlm-K7XSE",
                "NEO4J_DATABASE": "neo4j"
            }
        }
    }
}
EOF

echo "✅ MCP servers configured successfully!"
echo ""
echo "⚠️  IMPORTANT: Add your AI API keys to .cursor/mcp.json for Task Master AI"
echo ""
echo "🔄 Next steps:"
echo "1. Add any missing API keys to the configuration"
echo "2. Restart Claude Code to load the MCP servers"
echo "3. Check available tools with each MCP prefix:"
echo "   - mcp__pinecone__*"
echo "   - mcp__neo4j__*"
echo "   - mcp__graphlit__*"
echo "   - mcp__taskmaster__*"
```

---

## 🛠️ Available MCP Tools After Setup

### Pinecone Tools
- `mcp__pinecone__upsert` - Add vectors to index
- `mcp__pinecone__query` - Search for similar vectors
- `mcp__pinecone__delete` - Remove vectors
- `mcp__pinecone__fetch` - Get specific vectors
- `mcp__pinecone__update` - Update vector metadata

### Neo4j Tools
- `mcp__neo4j__execute_query` - Run Cypher queries
- `mcp__neo4j__create_node` - Create graph nodes
- `mcp__neo4j__create_relationship` - Create relationships
- `mcp__neo4j__get_schema` - View database schema
- `mcp__neo4j__import_data` - Bulk import data

### Graphlit Tools
- `mcp__graphlit__ingest` - Ingest documents
- `mcp__graphlit__query` - Query content
- `mcp__graphlit__search` - Search ingested content
- `mcp__graphlit__delete` - Remove content
- `mcp__graphlit__extract` - Extract insights

### Task Master Tools
- `mcp__taskmaster__initialize_project` - Set up project
- `mcp__taskmaster__parse_prd` - Parse requirements
- `mcp__taskmaster__get_tasks` - List tasks
- `mcp__taskmaster__add_task` - Create new tasks
- `mcp__taskmaster__update_task` - Update existing tasks

---

## 🔐 Security Best Practices

1. **Never commit this file to git** - Add to `.gitignore`:
   ```bash
   echo "Nightingale_MCP_Config.md" >> .gitignore
   ```

2. **Use environment variables** for production:
   ```bash
   export PINECONE_API_KEY="pcsk_4J7GV7_..."
   export NEO4J_PASSWORD="0Vd7DG61C472..."
   ```

3. **Rotate credentials regularly** - Contact service providers for new keys

4. **Limit access** - Only share with authorized team members

---

## 📊 Current Database Status

### Pinecone Vector Database
- **Status**: Operational, empty
- **Action Required**: Begin vectorizing Project Nightingale artifacts
- **First Priority**: Enhanced Executive Concierge Reports

### Neo4j Graph Database  
- **Status**: Operational, empty
- **Action Required**: Create initial schema and import prospect data
- **First Priority**: Prospect nodes and relationships

### Graphlit Content Management
- **Status**: Connected, authentication may need refresh
- **Action Required**: Verify JWT token validity
- **First Priority**: Test document ingestion

---

## 🚨 Troubleshooting

### MCP Tools Not Appearing
1. Ensure all packages are installed: `npm list`
2. Check `.cursor/mcp.json` exists and is valid JSON
3. Completely restart Claude Code (not just reload)
4. Check Claude Code logs for MCP errors

### Connection Failures
1. Verify credentials are correct
2. Check network connectivity
3. Ensure services are not down
4. Try manual connection tests shown above

### Package Installation Issues
```bash
# Clear npm cache
npm cache clean --force

# Remove node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

---

## 📞 Support Contacts

- **Pinecone Support**: https://www.pinecone.io/contact/
- **Neo4j Support**: https://neo4j.com/contact-us/
- **Graphlit Support**: https://www.graphlit.com/support
- **Task Master AI**: GitHub issues on the repository

---

**Document Status**: Complete with all credentials and setup instructions  
**Last Updated**: January 11, 2025  
**Security Classification**: SENSITIVE - Contains API credentials  

*Remember: This document contains sensitive credentials. Handle with appropriate security measures.*