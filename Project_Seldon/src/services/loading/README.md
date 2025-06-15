# DocumentLoadingService

A robust multi-database loading service for the Psychohistory research platform. This service handles parallel loading of transformed documents to Supabase (PostgreSQL), Pinecone (vector database), and Neo4j (graph database) with full error handling and rollback support.

## Features

- **Parallel Loading**: Efficiently loads documents to all three databases simultaneously
- **Transaction Support**: Full rollback capabilities if any database operation fails
- **Batch Processing**: Handles large document sets with configurable batch sizes
- **Cross-Database References**: Maintains references between database records
- **Error Recovery**: Comprehensive error handling with database-specific rollback
- **Health Monitoring**: Built-in health checks for all database connections
- **Concurrency Control**: Configurable concurrency limits to prevent overload

## Architecture

### Database Roles

1. **Supabase (PostgreSQL)**
   - Primary document storage
   - Structured data and metadata
   - Full-text search capabilities
   - Cross-database reference tracking

2. **Pinecone**
   - Vector embeddings for semantic search
   - Chunk-level similarity matching
   - Metadata filtering support

3. **Neo4j**
   - Document relationship graphs
   - Citation networks
   - Chunk sequencing and relationships

### Data Model

```typescript
// Document Structure
Document
├── id: string
├── title: string
├── authors: string[]
├── publicationDate: Date
├── abstract: string
├── keywords: string[]
├── methodology: string
├── keyFindings: string
├── chunks: Chunk[]
│   ├── id: string
│   ├── content: string
│   ├── embedding: number[]
│   ├── citations: Citation[]
│   └── metadata: ChunkMetadata
└── metadata: DocumentMetadata
```

## Usage

### Basic Configuration

```typescript
import { DocumentLoadingService } from './DocumentLoadingService';

const service = new DocumentLoadingService({
  supabase: {
    connectionString: 'postgresql://user:pass@host:5432/db',
    schema: 'psychohistory'
  },
  pinecone: {
    apiKey: 'your-pinecone-api-key',
    environment: 'us-east-1',
    indexName: 'psychohistory-docs',
    namespace: 'research-papers'
  },
  neo4j: {
    uri: 'bolt://localhost:7687',
    username: 'neo4j',
    password: 'password',
    database: 'psychohistory'
  },
  batchSize: 100,
  maxConcurrency: 5
});
```

### Loading Documents

```typescript
const documents: TransformedDocument[] = [
  // Your transformed documents
];

const results = await service.loadDocuments(documents);

results.forEach(result => {
  if (result.status === 'success') {
    console.log(`Document ${result.documentId} loaded successfully`);
  } else {
    console.error(`Failed to load ${result.documentId}:`, result.errors);
  }
});
```

### Health Checks

```typescript
const health = await service.healthCheck();
console.log('Database Status:', {
  supabase: health.supabase ? '✅' : '❌',
  pinecone: health.pinecone ? '✅' : '❌',
  neo4j: health.neo4j ? '✅' : '❌'
});
```

## Database Schemas

### Supabase Schema

```sql
-- Documents table
CREATE TABLE documents (
  id UUID PRIMARY KEY,
  collection_id TEXT NOT NULL,
  type TEXT NOT NULL,
  source_url TEXT,
  title TEXT NOT NULL,
  authors JSONB NOT NULL,
  publication_date TIMESTAMP,
  abstract TEXT,
  keywords TEXT[],
  methodology TEXT,
  key_findings TEXT,
  limitations TEXT,
  future_work TEXT,
  metadata JSONB,
  processing_status TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Chunks table
CREATE TABLE chunks (
  id UUID PRIMARY KEY,
  document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
  chunk_index INTEGER NOT NULL,
  content TEXT NOT NULL,
  start_page INTEGER,
  end_page INTEGER,
  section_title TEXT,
  chunk_type TEXT,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Citations table
CREATE TABLE citations (
  id UUID PRIMARY KEY,
  chunk_id UUID REFERENCES chunks(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  authors JSONB,
  year INTEGER,
  title TEXT,
  journal TEXT,
  doi TEXT,
  url TEXT,
  citation_type TEXT,
  confidence_score FLOAT,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Cross-database references
CREATE TABLE cross_database_references (
  document_id UUID PRIMARY KEY,
  supabase_id UUID NOT NULL,
  pinecone_namespace TEXT NOT NULL,
  neo4j_node_id TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
```

### Neo4j Schema

```cypher
// Node types
(:Document {
  id: string,
  title: string,
  authors: [string],
  publicationDate: datetime,
  abstract: string,
  keywords: [string],
  documentType: string,
  sourceUrl: string,
  methodology: string,
  keyFindings: string
})

(:Chunk {
  id: string,
  index: integer,
  content: string,
  sectionTitle: string,
  chunkType: string,
  startPage: integer,
  endPage: integer
})

(:Citation {
  id: string,
  text: string,
  authors: [string],
  year: integer,
  title: string,
  journal: string,
  doi: string,
  url: string,
  type: string,
  confidenceScore: float
})

// Relationships
(Document)-[:HAS_CHUNK {index: integer}]->(Chunk)
(Chunk)-[:NEXT]->(Chunk)
(Chunk)-[:CITES]->(Citation)
```

## Error Handling

The service implements a comprehensive error handling strategy:

1. **Transaction Rollback**: If any database operation fails, all previous operations are rolled back
2. **Partial Success Tracking**: Returns detailed status for each document
3. **Database-Specific Errors**: Identifies which database failed for targeted debugging
4. **Retry Logic**: Can be wrapped with retry mechanisms for transient failures

## Performance Considerations

- **Batch Size**: Adjust based on document size and database capacity
- **Concurrency**: Balance between speed and database load
- **Embedding Size**: Pinecone performance depends on vector dimensions
- **Network Latency**: Consider co-locating services for optimal performance

## Monitoring

The service logs detailed information for monitoring:

- Document processing status
- Database operation timings
- Error details with stack traces
- Rollback operations
- Health check results

## Security

- Use environment variables for sensitive configuration
- Implement proper access controls on all databases
- Enable SSL/TLS for database connections
- Regular credential rotation
- Audit logging for compliance
