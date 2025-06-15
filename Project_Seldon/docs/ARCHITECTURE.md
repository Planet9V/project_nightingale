# Project Seldon Architecture

## Directory Structure

```
Project_Seldon/
├── src/                          # Source code
│   ├── config/                   # Configuration management
│   │   └── ConfigurationManager.ts
│   ├── connectors/               # Database connectors
│   │   ├── Neo4jConnector.ts
│   │   ├── PineconeConnector.ts
│   │   └── SupabaseConnector.ts
│   ├── pipelines/                # ETL and processing pipelines
│   │   ├── ComprehensiveETLPipeline.ts
│   │   ├── JinaEmbeddingPipeline.ts
│   │   └── index.ts
│   ├── processors/               # Document processors
│   │   ├── BatchProcessor.ts
│   │   ├── DocumentProcessor.ts
│   │   └── PDFProcessor.ts
│   ├── services/                 # Business logic services
│   │   ├── jina/                # Jina AI services
│   │   ├── citation/            # Citation tracking
│   │   ├── extraction/          # Document extraction
│   │   ├── loading/             # Data loading
│   │   ├── orchestration/       # Pipeline orchestration
│   │   └── transformation/      # Data transformation
│   ├── scripts/                  # Utility and runner scripts
│   │   ├── test/                # Test scripts
│   │   ├── run-etl-pipeline.ts  # Main ETL runner
│   │   └── test-etl-components.ts
│   ├── types/                    # TypeScript definitions
│   │   └── index.ts             # Central type exports
│   ├── utils/                    # Utility functions
│   │   └── logger.ts
│   └── index.ts                  # Main entry point
├── docs/                         # Documentation
│   ├── design/                   # Design documents
│   └── ARCHITECTURE.md          # This file
├── database/                     # Database schemas
├── tests/                        # Unit and integration tests
├── package.json                  # Dependencies and scripts
├── tsconfig.json                # TypeScript configuration
└── .env                         # Environment variables
```

## Key Design Principles

### 1. Separation of Concerns
- **Connectors**: Handle database-specific operations
- **Processors**: Transform documents into structured data
- **Services**: Implement business logic
- **Pipelines**: Orchestrate the complete flow

### 2. Modularity
- Each component has a single responsibility
- Services are organized by domain (jina, citation, etc.)
- Clear interfaces between components

### 3. Scalability
- Batch processing support
- Rate limiting for external APIs
- Configurable concurrency

### 4. Error Handling
- Comprehensive error tracking
- Retry mechanisms with backoff
- Failed document quarantine

## Data Flow

```
1. Document Input (S3/Local)
   ↓
2. Document Processor (PDF/MD/TXT)
   ↓
3. Chunking & Preprocessing
   ↓
4. Jina AI Services
   - Embedding Generation
   - Classification
   - Reranking
   ↓
5. Multi-Database Storage
   - Supabase (metadata)
   - Pinecone (vectors)
   - Neo4j (relationships)
   ↓
6. S3 Archive (processed documents)
```

## Running the Pipeline

### Development
```bash
# Install dependencies
npm install

# Run tests
npm run test:etl -- --all

# Process documents
npm run etl -- --input /path/to/docs --pattern "*.pdf"
```

### Production
```bash
# Build the project
npm run build

# Run with production config
NODE_ENV=production npm run etl -- --input s3://bucket/path
```

## Configuration

All configuration is managed through:
1. Environment variables (`.env`)
2. Configuration files
3. Runtime parameters

See `src/config/ConfigurationManager.ts` for details.

## Database Schema

- **Supabase**: Document metadata, processing status, citations
- **Pinecone**: Vector embeddings with metadata
- **Neo4j**: Document relationships, knowledge graph
- **S3**: Original and processed document storage

## Best Practices

1. **Type Safety**: Use TypeScript interfaces for all data structures
2. **Error Handling**: Always handle errors gracefully
3. **Logging**: Use structured logging with appropriate levels
4. **Testing**: Write tests for critical paths
5. **Documentation**: Keep code and architecture docs updated