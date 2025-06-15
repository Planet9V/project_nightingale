# Project Seldon - Implementation Guide

## Overview

This guide provides detailed instructions for implementing Project Seldon's microservices architecture, integrating with Project Nightingale, and deploying the system for production use.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Service Implementation](#service-implementation)
4. [Database Configuration](#database-configuration)
5. [Integration with Project Nightingale](#integration-with-project-nightingale)
6. [Testing](#testing)
7. [Deployment](#deployment)
8. [Monitoring & Maintenance](#monitoring--maintenance)

## Prerequisites

### Required Software
- **Node.js**: v14.0+ (v18 recommended)
- **Python**: 3.8+ (3.10 recommended)
- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **Git**: 2.30+
- **Neo4j**: 5.x
- **PostgreSQL**: 14+

### Required API Keys
```bash
# Create .env file from template
cp config/development/.env.example .env

# Required API keys:
OPENAI_API_KEY=sk-...
TAVILY_API_KEY=tvly-...
BRAVE_API_KEY=BSA...
PINECONE_API_KEY=...
PINECONE_ENVIRONMENT=...
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=...
POSTGRES_CONNECTION_STRING=...
```

### MCP Configuration
Ensure your MCP configuration includes all required services:
```json
{
  "mcpServers": {
    "tavily": {
      "command": "npx",
      "args": ["-y", "@tavily/mcp"],
      "env": {
        "TAVILY_API_KEY": "${TAVILY_API_KEY}"
      }
    },
    "brave": {
      "command": "npx",
      "args": ["-y", "@brave/mcp"],
      "env": {
        "BRAVE_API_KEY": "${BRAVE_API_KEY}"
      }
    },
    "fetch": {
      "command": "npx",
      "args": ["-y", "@fetch/mcp"]
    },
    "taskmaster": {
      "command": "npx",
      "args": ["-y", "@taskmaster/mcp"]
    }
  }
}
```

## Environment Setup

### 1. Clone Repository
```bash
# Clone Project Seldon
cd /home/jim/gtm-campaign-project
git clone https://github.com/your-org/project-seldon.git Project_Seldon
cd Project_Seldon
```

### 2. Install Dependencies

#### Node.js Dependencies
```bash
# Install global tools
npm install -g typescript ts-node nodemon pm2

# Install project dependencies
npm install

# Install TypeScript types
npm install --save-dev @types/node @types/express @types/jest
```

#### Python Dependencies
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt
```

### 3. Database Setup

#### Neo4j Configuration
```bash
# Pull Neo4j Docker image
docker pull neo4j:5-enterprise

# Create Neo4j container
docker run -d \
  --name seldon-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/your-password \
  -e NEO4J_ACCEPT_LICENSE_AGREEMENT=yes \
  -e NEO4J_dbms_memory_heap_max__size=2G \
  -v $PWD/data/neo4j:/data \
  neo4j:5-enterprise

# Wait for Neo4j to start
sleep 30

# Create indexes and constraints
docker exec seldon-neo4j cypher-shell -u neo4j -p your-password < deployment/neo4j/init.cypher
```

#### Pinecone Setup
```python
# Initialize Pinecone index
import pinecone

pinecone.init(
    api_key=os.getenv("PINECONE_API_KEY"),
    environment=os.getenv("PINECONE_ENVIRONMENT")
)

# Create index for Project Seldon
pinecone.create_index(
    name="seldon-intelligence",
    dimension=1024,
    metric="cosine",
    pod_type="p1.x1"
)
```

#### PostgreSQL Configuration
```sql
-- Create Project Seldon database
CREATE DATABASE project_seldon;

-- Create schema
\c project_seldon;

CREATE SCHEMA intelligence;
CREATE SCHEMA artifacts;
CREATE SCHEMA analytics;

-- Run migrations
\i deployment/postgres/migrations/001_initial_schema.sql
\i deployment/postgres/migrations/002_intelligence_tables.sql
\i deployment/postgres/migrations/003_artifact_tables.sql
```

## Service Implementation

### 1. Intelligence Engine (Port 8000)

#### Directory Structure
```
src/services/intelligence/
├── index.ts              # Service entry point
├── server.ts             # Express server setup
├── routes/               # API routes
│   ├── analyze.ts
│   ├── threats.ts
│   └── vulnerabilities.ts
├── controllers/          # Business logic
│   ├── AnalysisController.ts
│   ├── ThreatController.ts
│   └── VulnerabilityController.ts
├── services/             # Core services
│   ├── GraphService.ts
│   ├── VectorService.ts
│   └── PsychohistoryService.ts
└── models/               # Data models
    ├── Threat.ts
    ├── Vulnerability.ts
    └── Prospect.ts
```

#### Implementation Example
```typescript
// src/services/intelligence/server.ts
import express from 'express';
import { Neo4jService } from './services/Neo4jService';
import { PineconeService } from './services/PineconeService';
import { IntelligenceRouter } from './routes';

const app = express();
const PORT = process.env.INTELLIGENCE_PORT || 8000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize services
const neo4j = new Neo4jService(process.env.NEO4J_URI!);
const pinecone = new PineconeService(process.env.PINECONE_API_KEY!);

// Routes
app.use('/api/v1/intelligence', IntelligenceRouter({ neo4j, pinecone }));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'intelligence-engine' });
});

app.listen(PORT, () => {
  console.log(`Intelligence Engine running on port ${PORT}`);
});
```

### 2. EAB Generator (Port 8001)

#### Core Components
```typescript
// src/services/eab/generators/ExpressAttackBriefGenerator.ts
export class ExpressAttackBriefGenerator {
  constructor(
    private intelligenceService: IntelligenceService,
    private templateEngine: TemplateEngine,
    private mitreMappingService: MitreService
  ) {}

  async generate(params: EABParams): Promise<ExpressAttackBrief> {
    // 1. Gather intelligence
    const threatData = await this.intelligenceService.getThreatData(params);
    
    // 2. Analyze with MITRE ATT&CK
    const mitreMapping = await this.mitreMappingService.mapTechniques(threatData);
    
    // 3. Generate timeline
    const timeline = this.generateAttackTimeline(threatData, mitreMapping);
    
    // 4. Create executive summary
    const summary = await this.createExecutiveSummary(threatData);
    
    // 5. Apply template
    return this.templateEngine.render('eab', {
      threatData,
      mitreMapping,
      timeline,
      summary
    });
  }
}
```

### 3. Report Generator (Port 8002)

#### Report Types Implementation
```typescript
// src/services/reports/generators/ReportFactory.ts
export class ReportFactory {
  private generators: Map<ReportType, IReportGenerator>;

  constructor(dependencies: ServiceDependencies) {
    this.generators = new Map([
      ['executive-concierge', new ExecutiveConciergeGenerator(dependencies)],
      ['landing-page', new LandingPageGenerator(dependencies)],
      ['nurture-sequence', new NurtureSequenceGenerator(dependencies)],
      ['am-playbook', new AMPlaybookGenerator(dependencies)]
    ]);
  }

  async generate(type: ReportType, params: ReportParams): Promise<Report> {
    const generator = this.generators.get(type);
    if (!generator) {
      throw new Error(`Unknown report type: ${type}`);
    }
    
    return generator.generate(params);
  }
}
```

## Database Configuration

### Neo4j Schema
```cypher
// Create constraints and indexes
CREATE CONSTRAINT prospect_id IF NOT EXISTS ON (p:Prospect) ASSERT p.id IS UNIQUE;
CREATE CONSTRAINT threat_actor_id IF NOT EXISTS ON (ta:ThreatActor) ASSERT ta.id IS UNIQUE;
CREATE CONSTRAINT vulnerability_cve IF NOT EXISTS ON (v:Vulnerability) ASSERT v.cve IS UNIQUE;

// Create indexes for performance
CREATE INDEX prospect_sector IF NOT EXISTS FOR (p:Prospect) ON (p.sector);
CREATE INDEX threat_actor_sophistication IF NOT EXISTS FOR (ta:ThreatActor) ON (ta.sophistication);
CREATE INDEX vulnerability_cvss IF NOT EXISTS FOR (v:Vulnerability) ON (v.cvssScore);

// Example relationship creation
MATCH (p:Prospect {name: 'Consumers Energy'})
MATCH (ta:ThreatActor {name: 'Volt Typhoon'})
CREATE (ta)-[:TARGETS {confidence: 0.85, lastSeen: datetime()}]->(p);
```

### Pinecone Configuration
```python
# Vector embedding configuration
EMBEDDING_CONFIG = {
    "model": "text-embedding-ada-002",
    "dimensions": 1024,
    "batch_size": 100,
    "namespace_strategy": "sector-based"
}

# Index metadata schema
METADATA_SCHEMA = {
    "prospect_id": "string",
    "sector": "string", 
    "theme": "string",
    "threat_level": "number",
    "last_updated": "string",
    "source": "string"
}
```

## Integration with Project Nightingale

### 1. Database Connection
```typescript
// Share PostgreSQL connection with Project Nightingale
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_ANON_KEY!
);

// Access Project Nightingale tables
const { data: prospects } = await supabase
  .from('prospects')
  .select('*')
  .eq('sector', 'energy');
```

### 2. MCP Service Integration
```typescript
// Use shared MCP services
import { MCPClient } from '@anthropic/mcp';

const mcpClient = new MCPClient({
  servers: {
    tavily: { /* config */ },
    brave: { /* config */ },
    taskmaster: { /* config */ }
  }
});

// Research with Tavily
const research = await mcpClient.call('tavily', 'search', {
  query: 'Volt Typhoon critical infrastructure attacks 2025',
  search_depth: 'advanced'
});
```

### 3. Artifact Generation
```typescript
// Generate artifacts compatible with Project Nightingale
export class NightingaleCompatibleGenerator {
  async generateExecutiveConcierge(prospect: Prospect): Promise<Artifact> {
    // Use Project Nightingale template structure
    const template = await this.loadNightingaleTemplate('executive-concierge');
    
    // Apply Project Seldon intelligence
    const intelligence = await this.gatherIntelligence(prospect);
    
    // Merge and generate
    return this.renderArtifact(template, {
      ...prospect,
      ...intelligence,
      generatedBy: 'Project Seldon',
      version: '2.0'
    });
  }
}
```

## Testing

### Unit Tests
```bash
# Run all unit tests
npm test

# Run with coverage
npm run test:coverage

# Run specific test suite
npm test -- IntelligenceEngine.test.ts
```

### Integration Tests
```bash
# Start test environment
docker-compose -f docker-compose.test.yml up -d

# Run integration tests
npm run test:integration

# Cleanup
docker-compose -f docker-compose.test.yml down
```

### E2E Tests
```typescript
// tests/e2e/intelligence-flow.test.ts
describe('Intelligence Analysis Flow', () => {
  it('should analyze prospect and generate report', async () => {
    // 1. Submit prospect for analysis
    const analysisResponse = await api.post('/intelligence/analyze', {
      prospect: 'American Water Works',
      depth: 'comprehensive'
    });
    
    // 2. Generate EAB
    const eabResponse = await api.post('/eab/generate', {
      analysisId: analysisResponse.data.id,
      threatActor: 'Volt Typhoon'
    });
    
    // 3. Create executive report
    const reportResponse = await api.post('/reports/executive-concierge', {
      analysisId: analysisResponse.data.id,
      eabId: eabResponse.data.id
    });
    
    expect(reportResponse.status).toBe(200);
    expect(reportResponse.data).toHaveProperty('artifactUrl');
  });
});
```

## Deployment

### Docker Compose Configuration
```yaml
# docker-compose.yml
version: '3.8'

services:
  intelligence-engine:
    build: 
      context: .
      dockerfile: deployment/docker/intelligence.Dockerfile
    ports:
      - "8000:8000"
    environment:
      - NODE_ENV=production
      - NEO4J_URI=bolt://neo4j:7687
    depends_on:
      - neo4j
      - postgres

  eab-generator:
    build:
      context: .
      dockerfile: deployment/docker/eab.Dockerfile
    ports:
      - "8001:8001"
    environment:
      - NODE_ENV=production
    depends_on:
      - intelligence-engine

  report-generator:
    build:
      context: .
      dockerfile: deployment/docker/reports.Dockerfile
    ports:
      - "8002:8002"
    environment:
      - NODE_ENV=production
    depends_on:
      - intelligence-engine

  neo4j:
    image: neo4j:5-enterprise
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      - NEO4J_AUTH=neo4j/${NEO4J_PASSWORD}
      - NEO4J_ACCEPT_LICENSE_AGREEMENT=yes
    volumes:
      - neo4j_data:/data

  postgres:
    image: postgres:14-alpine
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_DB=project_seldon
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  neo4j_data:
  postgres_data:
```

### Kubernetes Deployment
```yaml
# deployment/kubernetes/intelligence-engine.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: intelligence-engine
  namespace: project-seldon
spec:
  replicas: 3
  selector:
    matchLabels:
      app: intelligence-engine
  template:
    metadata:
      labels:
        app: intelligence-engine
    spec:
      containers:
      - name: intelligence-engine
        image: project-seldon/intelligence:latest
        ports:
        - containerPort: 8000
        env:
        - name: NODE_ENV
          value: "production"
        - name: NEO4J_URI
          valueFrom:
            secretKeyRef:
              name: seldon-secrets
              key: neo4j-uri
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
```

## Monitoring & Maintenance

### Health Checks
```typescript
// Health check endpoint implementation
app.get('/health', async (req, res) => {
  const checks = await Promise.all([
    checkNeo4jConnection(),
    checkPineconeConnection(),
    checkPostgresConnection()
  ]);
  
  const healthy = checks.every(check => check.status === 'healthy');
  
  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'healthy' : 'unhealthy',
    services: checks,
    timestamp: new Date().toISOString()
  });
});
```

### Logging Configuration
```typescript
// Winston logging setup
import winston from 'winston';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});
```

### Performance Monitoring
```yaml
# Prometheus metrics
- job_name: 'project-seldon'
  static_configs:
    - targets: 
      - 'intelligence-engine:8000'
      - 'eab-generator:8001'
      - 'report-generator:8002'
  metrics_path: '/metrics'
  scrape_interval: 15s
```

## Troubleshooting

### Common Issues

1. **Neo4j Connection Failed**
   ```bash
   # Check Neo4j logs
   docker logs seldon-neo4j
   
   # Verify connection
   cypher-shell -a bolt://localhost:7687 -u neo4j
   ```

2. **Pinecone Rate Limits**
   ```typescript
   // Implement exponential backoff
   const retryWithBackoff = async (fn, maxRetries = 3) => {
     for (let i = 0; i < maxRetries; i++) {
       try {
         return await fn();
       } catch (error) {
         if (i === maxRetries - 1) throw error;
         await new Promise(resolve => 
           setTimeout(resolve, Math.pow(2, i) * 1000)
         );
       }
     }
   };
   ```

3. **Memory Issues**
   ```bash
   # Increase Node.js heap size
   NODE_OPTIONS="--max-old-space-size=4096" npm start
   
   # Monitor memory usage
   pm2 monit
   ```

## Next Steps

1. **Complete Service Implementation**
   - Finish all three microservices
   - Implement authentication/authorization
   - Add rate limiting and caching

2. **Integration Testing**
   - Test with Project Nightingale data
   - Validate artifact compatibility
   - Performance benchmarking

3. **Production Readiness**
   - Security audit
   - Load testing
   - Disaster recovery planning
   - Documentation completion

---

For additional support, refer to:
- [API Documentation](API_DOCUMENTATION.md)
- [Deployment Guide](DEPLOYMENT_GUIDE.md)
- [Architecture Documentation](/Architecture/)
- [Research Papers](/Research/)