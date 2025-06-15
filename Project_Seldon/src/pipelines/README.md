# Project Seldon Pipelines

This directory contains the core ETL and processing pipelines for Project Seldon.

## Pipeline Architecture

```
pipelines/
├── ComprehensiveETLPipeline.ts    # Main ETL orchestrator
├── JinaEmbeddingPipeline.ts       # Specialized embedding pipeline
└── README.md                      # This file
```

## Available Pipelines

### ComprehensiveETLPipeline
The main ETL pipeline that orchestrates the complete document processing flow:
- Document extraction (PDF, MD, TXT)
- Text chunking and preprocessing
- Embedding generation via Jina AI
- Multi-database storage (Supabase, Pinecone, Neo4j)
- S3 document archival
- Citation tracking and relationship mapping

### JinaEmbeddingPipeline
Specialized pipeline for high-throughput embedding generation:
- Batch processing with rate limiting
- Multiple embedding models support
- Automatic retry and error handling
- Progress tracking and metrics

## Usage

### Running the ETL Pipeline

```bash
# Process a single PDF
npm run etl -- --input /path/to/document.pdf

# Process all PDFs in a directory
npm run etl -- --input /path/to/directory --pattern "*.pdf"

# Process with specific options
npm run etl -- \
  --input /path/to/documents \
  --batch-size 20 \
  --max-files 100 \
  --skip-neo4j
```

### Testing Components

```bash
# Test all components
npm run test:etl -- --all

# Test specific components
npm run test:etl -- --jina --pinecone
```

## Pipeline Configuration

Pipelines use the central configuration from `src/config/ConfigurationManager.ts`.

Key configuration sections:
- `etl`: General ETL settings (batch size, timeouts, retries)
- `databases`: Connection settings for all databases
- `jina`: Jina AI API configuration
- `s3`: S3 bucket configuration

## Adding New Pipelines

1. Create a new TypeScript file in this directory
2. Extend the base pipeline interface or create a specialized one
3. Implement the required methods:
   - `initialize()`: Set up connections and resources
   - `process()`: Main processing logic
   - `shutdown()`: Clean up resources
4. Add error handling and progress tracking
5. Update this README with the new pipeline

## Best Practices

1. **Error Handling**: All pipelines should handle errors gracefully and provide meaningful error messages
2. **Progress Tracking**: Use the ProgressTracker service for long-running operations
3. **Resource Management**: Always clean up resources in the shutdown method
4. **Logging**: Use the central logger for consistent logging
5. **Metrics**: Track key metrics for monitoring and optimization
6. **Testing**: Write unit tests for pipeline components

## Related Components

- `/processors`: Document processors (PDF, text, etc.)
- `/connectors`: Database connectors
- `/services`: Supporting services (Jina, S3, etc.)
- `/types`: TypeScript type definitions
- `/scripts`: Pipeline runner scripts