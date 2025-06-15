# Neo4j MCP Setup Guide for Project Nightingale

## ✅ Installation Complete

The Neo4j MCP server has been installed and added to your configuration. You now need to add your Neo4j cloud connection details.

## 🔧 Configuration Required

Edit the file `.cursor/mcp.json` and replace the placeholder values in the `neo4j` section:

```json
"neo4j": {
    "command": "npx",
    "args": [
        "-y",
        "--package=neo4j-mcpserver",
        "neo4j-mcpserver"
    ],
    "env": {
        "NEO4J_URI": "YOUR_NEO4J_CLOUD_URI_HERE",
        "NEO4J_USER": "YOUR_NEO4J_USERNAME_HERE",
        "NEO4J_PASSWORD": "YOUR_NEO4J_PASSWORD_HERE"
    }
}
```

### Example Configuration

For Neo4j Aura (cloud), your configuration would look like:

```json
"env": {
    "NEO4J_URI": "neo4j+s://abcd1234.databases.neo4j.io",
    "NEO4J_USER": "neo4j",
    "NEO4J_PASSWORD": "your-secure-password-here"
}
```

### Alternative: Connection String Format

You can also use a single connection string instead:

```json
"env": {
    "NEO4J_CONNECTION": "neo4j+s://abcd1234.databases.neo4j.io,neo4j,your-password"
}
```

## 📊 Neo4j Cloud Setup (if needed)

If you don't have a Neo4j cloud instance yet:

1. **Go to Neo4j Aura**: https://neo4j.com/cloud/aura/
2. **Create a free account** (or sign in)
3. **Create a new database**:
   - Choose "AuraDB Free" for testing
   - Select your region
   - Note down your connection URI and password

## 🚀 Testing the Connection

After adding your credentials, test the connection:

```bash
# Test Neo4j MCP directly
NEO4J_URI="your-uri" NEO4J_USER="your-user" NEO4J_PASSWORD="your-password" npx neo4j-mcpserver

# Or with connection string
NEO4J_CONNECTION="your-uri,your-user,your-password" npx neo4j-mcpserver
```

## 🔄 Restart Claude

After updating the configuration:
1. Close Claude completely
2. Restart Claude
3. Neo4j MCP tools should now be available

## 🛠️ Available Neo4j MCP Tools

Once connected, you'll have access to tools like:
- `mcp__neo4j__execute_query` - Run Cypher queries
- `mcp__neo4j__create_node` - Create graph nodes
- `mcp__neo4j__create_relationship` - Create relationships
- `mcp__neo4j__get_schema` - View database schema
- `mcp__neo4j__import_data` - Bulk import data

## 📈 Project Nightingale Use Cases

### 1. Prospect Relationship Mapping
```cypher
// Create prospect network
CREATE (p1:Prospect {id: 'A-030734', name: 'Consumers Energy', industry: 'Energy'})
CREATE (p2:Prospect {id: 'A-030922', name: 'Evergy', industry: 'Energy'})
CREATE (p1)-[:SIMILAR_THREAT_PROFILE]->(p2)
```

### 2. Threat Actor Tracking
```cypher
// Map threat actors to targets
CREATE (ta:ThreatActor {name: 'BAUXITE', type: 'Ransomware'})
CREATE (p:Prospect {id: 'A-018814', name: 'Boeing'})
CREATE (ta)-[:TARGETS {confidence: 0.85}]->(p)
```

### 3. Technology Stack Analysis
```cypher
// Technology relationships
CREATE (t:Technology {name: 'SCADA', vendor: 'Schneider'})
CREATE (p:Prospect {id: 'A-037323', name: 'PG&E'})
CREATE (p)-[:USES {criticality: 'HIGH'}]->(t)
```

### 4. Account Manager Performance
```cypher
// AM prospect relationships
CREATE (am:AccountManager {name: 'Jim Vranicar'})
CREATE (p:Prospect {id: 'A-030734', name: 'Consumers Energy'})
CREATE (am)-[:MANAGES {since: '2024-01-01'}]->(p)
```

## 📊 Graph Database Benefits for Project Nightingale

1. **Relationship Discovery**: Find hidden connections between prospects, threats, and technologies
2. **Pattern Recognition**: Identify attack patterns across industries
3. **Risk Propagation**: Understand how vulnerabilities spread through supply chains
4. **Performance Analytics**: Track AM success patterns and prospect conversion paths
5. **Intelligence Networks**: Build comprehensive threat intelligence graphs

## 🔒 Security Note

Remember to:
- Never commit credentials to git
- Use environment variables for sensitive data
- Rotate passwords regularly
- Use Neo4j's role-based access control

---

**Next Steps**: Add your Neo4j cloud credentials to `.cursor/mcp.json` and restart Claude to begin using graph database capabilities!