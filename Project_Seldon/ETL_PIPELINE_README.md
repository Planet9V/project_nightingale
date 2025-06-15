# Project Seldon ETL Pipeline

Production-ready ETL pipeline for processing Project Nightingale artifacts with advanced intelligence extraction capabilities.

## Overview

The Project Seldon ETL pipeline is designed to:
- Extract and parse markdown documents from Project Nightingale
- Generate embeddings using Jina AI services
- Store documents in Supabase PostgreSQL
- Index vectors in Pinecone for semantic search
- Build relationship graphs in Neo4j
- Track character-level citations for traceability

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Document       │────▶│  Jina Embedding  │────▶│  Database       │
│  Processor      │     │  Pipeline        │     │  Connectors     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                         │
         ▼                       ▼                         ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Batch          │     │  Citation        │     │  Supabase       │
│  Processor      │     │  Tracker         │     │  Pinecone       │
└─────────────────┘     └──────────────────┘     │  Neo4j          │
                                                  └─────────────────┘
```

## Features

- **Parallel Processing**: Configurable concurrency for optimal performance
- **Rate Limiting**: Built-in rate limiting for API calls
- **Error Handling**: Comprehensive error handling with retry logic
- **Progress Tracking**: Real-time progress updates and metrics
- **Citation Support**: Character-level citation tracking
- **Batch Operations**: Efficient batch processing for large datasets
- **Health Monitoring**: Built-in health checks for all services

## Installation

1. Install dependencies:
```bash
cd Project_Seldon
npm install
```

2. Copy environment configuration:
```bash
cp .env.example .env
```

3. Configure your environment variables in `.env`

4. Build the project:
```bash
npm run build
```

## Configuration

### Environment Variables

Key configuration options:

- `ETL_BATCH_SIZE`: Number of items to process in each batch (default: 50)
- `ETL_CONCURRENCY`: Number of parallel workers (default: 5)
- `JINA_API_KEY`: Your Jina AI API key (required)
- `SUPABASE_URL`: Your Supabase project URL (required)
- `PINECONE_API_KEY`: Your Pinecone API key (required)
- `NEO4J_URI`: Neo4j database URI (required)

See `.env.example` for complete list.

## Usage

### Process a Directory

```bash
# Process all markdown files in a directory
npm run start /path/to/documents

# Process with custom configuration
NODE_ENV=production npm run start /path/to/documents
```

### Run Test Pipeline

```bash
# Run test with 5 sample documents
npm run test-pipeline

# This will process 5 documents from Annual_cyber_reports_2023
```

### Programmatic Usage

```typescript
import { ProjectSeldonETL } from './src/index.js';

const etl = new ProjectSeldonETL();

try {
  await etl.initialize();
  await etl.processDirectory('/path/to/documents');
} finally {
  await etl.cleanup();
}
```

## API Reference

### Main Classes

#### ProjectSeldonETL
Main ETL orchestrator that coordinates all pipeline components.

#### DocumentProcessor
Handles document parsing, metadata extraction, and chunking.

```typescript
const processor = new DocumentProcessor(config);
const result = await processor.processFile(filePath, {
  chunkSize: 1000,
  chunkOverlap: 100,
  includeMetadata: true
});
```

#### JinaEmbeddingPipeline
Manages embedding generation with rate limiting.

```typescript
const pipeline = new JinaEmbeddingPipeline(config);
const embeddings = await pipeline.processChunks(chunks, context, {
  batchSize: 50,
  maxRetries: 3
});
```

#### BatchProcessor
Handles parallel processing with progress tracking.

```typescript
const processor = new BatchProcessor(config);
const result = await processor.processBatch(items, processorFn, context, {
  concurrency: 5,
  onProgress: (progress) => console.log(progress)
});
```

## Database Schema

### Supabase (PostgreSQL)
- `documents`: Stores document content and metadata
- `chunk_metadata`: Stores chunk-level information
- `citations`: Stores citation references

### Pinecone
- Vectors indexed by chunk ID
- Metadata includes document ID, chunk index, and custom properties

### Neo4j
- Nodes: Document, Entity, Tag, Prospect, Threat
- Relationships: MENTIONS, REFERENCES, RELATED_TO

## Monitoring

### Metrics
- Documents processed per second
- Embedding generation rate
- Database insertion rate
- Error rates by component

### Health Checks
```typescript
const health = await embeddingPipeline.getHealth();
console.log(health.status); // 'healthy' | 'degraded' | 'unhealthy'
```

### Logging
Logs are written to:
- Console (configurable)
- File: `./logs/app.log`
- Error file: `./logs/error.log`

## Performance Optimization

1. **Batch Size**: Adjust `ETL_BATCH_SIZE` based on document size
2. **Concurrency**: Set `ETL_CONCURRENCY` based on available resources
3. **Chunk Size**: Configure `CHUNK_SIZE` for optimal embedding performance
4. **Rate Limits**: Adjust Jina rate limits based on your API tier

## Error Handling

The pipeline includes:
- Automatic retry with exponential backoff
- Circuit breaker for failing services
- Graceful degradation
- Comprehensive error logging

## Troubleshooting

### Common Issues

1. **Connection Errors**
   - Verify database credentials in `.env`
   - Check network connectivity
   - Ensure services are running

2. **Rate Limiting**
   - Reduce `ETL_CONCURRENCY`
   - Increase `JINA_RATE_LIMIT_*` delays

3. **Memory Issues**
   - Reduce `ETL_BATCH_SIZE`
   - Process smaller directories

### Debug Mode

Enable debug logging:
```bash
LOG_LEVEL=debug npm run start
```

## Development

### Running Tests
```bash
npm test
```

### Type Checking
```bash
npm run typecheck
```

### Linting
```bash
npm run lint
```

## Production Deployment

1. Set `NODE_ENV=production`
2. Configure production database credentials
3. Enable monitoring (Prometheus)
4. Set appropriate resource limits
5. Configure log rotation

## License

Proprietary - Project Nightingale

## Support

For issues or questions, contact the Project Nightingale team.