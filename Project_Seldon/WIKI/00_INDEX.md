# Project Seldon ETL Pipeline Wiki
## Complete Documentation & Knowledge Base

### 🚀 Quick Start
- [Installation Guide](./01_INSTALLATION.md)
- [Configuration Setup](./02_CONFIGURATION.md)
- [First Run Tutorial](./03_FIRST_RUN.md)
- [MCP Server Setup](./04_MCP_SETUP.md)

### 📚 Core Components
- [Database Architecture](./10_DATABASE_ARCHITECTURE.md)
- [ETL Pipeline Design](./11_ETL_PIPELINE.md)
- [Citation System](./12_CITATION_SYSTEM.md)
- [Progress Tracking](./13_PROGRESS_TRACKING.md)

### 🗄️ Database Documentation
- [Supabase Schema](./20_SUPABASE_SCHEMA.md)
- [Pinecone Configuration](./21_PINECONE_CONFIG.md)
- [Neo4j Graph Model](./22_NEO4J_MODEL.md)
- [S3 Storage Structure](./23_S3_STRUCTURE.md)

### 🔧 Services Documentation
- [Health Check System](./30_HEALTH_CHECKS.md)
- [Jina AI Integration](./31_JINA_INTEGRATION.md)
- [Error Recovery](./32_ERROR_RECOVERY.md)
- [Performance Optimization](./33_PERFORMANCE.md)

### 🛠️ Troubleshooting
- [Common Errors](./40_COMMON_ERRORS.md)
- [MCP Server Issues](./41_MCP_ISSUES.md)
- [Database Connection Problems](./42_DB_ISSUES.md)
- [Performance Tuning](./43_PERFORMANCE_TUNING.md)

### 📊 Operations
- [Monitoring & Metrics](./50_MONITORING.md)
- [Backup & Recovery](./51_BACKUP.md)
- [Scaling Guide](./52_SCALING.md)
- [Security Best Practices](./53_SECURITY.md)

### 🧪 Testing
- [Test Suite Documentation](./60_TESTING.md)
- [Integration Tests](./61_INTEGRATION_TESTS.md)
- [Performance Benchmarks](./62_BENCHMARKS.md)

### 🔧 Fixes & Solutions
- [TypeScript Configuration Fixes](./60_TYPESCRIPT_FIXES.md)

### 🔌 Integrations
- [Jina AI + Pinecone Complete Guide](./70_JINA_PINECONE_INTEGRATION.md)
- [Context7 MCP Configuration & Usage](./80_CONTEXT7_MCP_CONFIGURATION.md)
- [**CRITICAL** MCP Services (Context7, SuperMemory, Knowledge Graph)](./90_CRITICAL_MCP_SERVICES.md)

### 📝 API Reference
- [ETL Pipeline API](./70_ETL_API.md)
- [Query API](./71_QUERY_API.md)
- [Admin API](./72_ADMIN_API.md)

---

## System Status Dashboard

| Component | Status | Version | Health Check |
|-----------|--------|---------|--------------|
| Supabase | 🟢 Ready | 2.44.2 | [Check](./30_HEALTH_CHECKS.md#supabase) |
| Pinecone | 🟢 Ready | 2.2.2 | [Check](./30_HEALTH_CHECKS.md#pinecone) |
| Neo4j | 🟢 Ready | 5.23.0 | [Check](./30_HEALTH_CHECKS.md#neo4j) |
| Jina AI | 🟢 Ready | v2 | [Check](./30_HEALTH_CHECKS.md#jina) |
| S3 | 🔴 Config Needed | - | [Setup](./23_S3_STRUCTURE.md) |

## Quick Commands

```bash
# Run health checks
npm run health-check

# Setup databases
npm run setup-databases

# Run ETL pipeline
npm run etl -- --input /path/to/documents

# Run test suite
npm test

# View progress
npm run progress
```

Last Updated: June 13, 2025