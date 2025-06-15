# Jina AI Services Integration for Project Seldon

**Generated**: June 13, 2025  
**Version**: 1.0 - Production Ready  
**API Key**: `jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q`

## 🎯 Overview

This comprehensive Jina AI service integration provides rate-limited, fault-tolerant access to all Jina AI capabilities within the Project Seldon ETL pipeline. The system implements advanced queue management, circuit breakers, and comprehensive error handling to ensure reliable operation at scale.

## 📦 Service Architecture

### Core Components

| Component | Purpose | Rate Limit |
|-----------|---------|------------|
| **JinaEmbeddingService** | Generate high-quality embeddings | 2000 RPM |
| **JinaRerankingService** | Advanced relevance scoring | 2000 RPM |
| **JinaClassifierService** | Content classification | 60 RPM |
| **JinaDeepSearchService** | Semantic search and discovery | 500 RPM |
| **JinaRateLimiter** | Queue management and rate limiting | All services |
| **JinaServiceManager** | Unified service orchestration | N/A |
| **JinaErrorHandler** | Circuit breakers and retry logic | N/A |

### Rate Limiting Configuration

```typescript
const RATE_LIMITS = {
  embedding: { concurrency: 10, intervalCap: 2000, interval: 60000 },
  reranking: { concurrency: 10, intervalCap: 2000, interval: 60000 },
  classifier: { concurrency: 3, intervalCap: 60, interval: 60000 },
  deepSearch: { concurrency: 5, intervalCap: 500, interval: 60000 }
};
```

## 🚀 Quick Start

### Basic Usage

```typescript
import { JinaServiceManager } from './services/jina';

// Initialize service manager
const jinaManager = new JinaServiceManager({
  apiKey: 'jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q',
  enableHealthChecks: true,
  healthCheckInterval: 300000 // 5 minutes
});

// Process document chunks
const processedDoc = await jinaManager.processDocumentChunks(chunks, {
  embedding: { dimensions: 768, batchSize: 10 },
  classification: { confidence_threshold: 0.7 },
  reranking: { top_k: 20, scoreThreshold: 0.5 }
});

// Perform semantic search
const searchResults = await jinaManager.semanticSearch(query, chunks, {
  embedding_search: true,
  rerank_results: true,
  deep_search: true,
  top_k: 10
});
```

### ETL Pipeline Integration

```typescript
import { JinaETLIntegration } from './services/jina/JinaETLIntegration';

const jinaETL = new JinaETLIntegration('your-api-key');

// Process document for ETL pipeline
const result = await jinaETL.processDocumentForETL('doc_123', chunks, {
  generateEmbeddings: true,
  classifyContent: true,
  performSearch: true,
  searchQuery: 'cybersecurity threats'
});
```

## 🔧 Individual Service Usage

### Embedding Service

```typescript
import { JinaEmbeddingService, JinaRateLimiter } from './services/jina';

const rateLimiter = new JinaRateLimiter();
const embeddingService = new JinaEmbeddingService(rateLimiter, 'your-api-key');

// Generate single embedding
const embedding = await embeddingService.generateEmbedding('your text here');

// Generate batch embeddings
const embeddings = await embeddingService.generateBatchEmbeddings([
  'text 1', 'text 2', 'text 3'
], { batchSize: 10 });

// Generate embeddings for document chunks
const chunkEmbeddings = await embeddingService.generateChunkEmbeddings(chunks);
```

### Reranking Service

```typescript
import { JinaRerankingService } from './services/jina';

const rerankingService = new JinaRerankingService(rateLimiter, 'your-api-key');

// Rerank documents
const rerankResults = await rerankingService.rerankDocuments(
  'query text',
  ['doc1', 'doc2', 'doc3'],
  { top_k: 5, return_documents: true }
);

// Rerank chunks with metadata preservation
const chunkResults = await rerankingService.rerankChunks(
  'query text',
  chunks,
  { top_k: 10, scoreThreshold: 0.5 }
);
```

### Classification Service

```typescript
import { JinaClassifierService } from './services/jina';

const classifierService = new JinaClassifierService(rateLimiter, 'your-api-key');

// Classify single text
const classification = await classifierService.classifyText(
  'your text here',
  {
    labels: ['threat_intelligence', 'vulnerability_report', 'executive_summary'],
    confidence_threshold: 0.7
  }
);

// Cybersecurity-specific classification
const cyberClassification = await classifierService.classifyCybersecurity(
  'security document content',
  { confidence_threshold: 0.8 }
);

// Multi-label classification
const multiLabelResult = await classifierService.classifyMultiLabel(
  'complex document',
  { confidence_threshold: 0.5, max_labels: 3 }
);
```

### Deep Search Service

```typescript
import { JinaDeepSearchService } from './services/jina';

const searchService = new JinaDeepSearchService(rateLimiter, 'your-api-key');

// Basic semantic search
const searchResults = await searchService.searchChunks(
  'cybersecurity threats',
  chunks,
  { top_k: 10, search_depth: 'advanced' }
);

// Multi-query search
const multiResults = await searchService.multiQuerySearch(
  ['query1', 'query2', 'query3'],
  chunks,
  { top_k_per_query: 5, deduplicate: true }
);

// Advanced search with filters
const filteredResults = await searchService.searchWithFilters(
  'search query',
  chunks,
  {
    min_token_count: 100,
    max_token_count: 1000,
    document_types: ['threat_intelligence', 'vulnerability_report']
  },
  { top_k: 15 }
);
```

## 🛡️ Error Handling and Reliability

### Circuit Breaker Pattern

The system implements circuit breakers for each service to prevent cascading failures:

```typescript
import { JinaErrorHandler, CircuitBreakerState } from './services/jina';

const errorHandler = new JinaErrorHandler({
  maxRetries: 3,
  baseDelay: 1000,
  maxDelay: 30000
}, {
  failureThreshold: 5,
  recoveryTimeout: 60000
});

// Execute with error handling
const result = await errorHandler.executeWithRetry(
  'embedding',
  () => embeddingService.generateEmbedding('text'),
  'generate-embedding-operation'
);

// Check circuit breaker status
const status = errorHandler.getCircuitBreakerStatus('embedding');
console.log('Circuit breaker state:', status.state);
```

### Retry Logic

Automatic retry with exponential backoff for:
- Rate limit errors (longer delays)
- Network timeouts
- Server errors (5xx)
- Connection failures

Non-retryable errors:
- Authentication errors (401)
- Client errors (4xx except 429)
- Invalid request format

## 📊 Monitoring and Metrics

### Service Metrics

```typescript
// Get comprehensive metrics
const metrics = jinaManager.getServiceMetrics();

// Sample metrics structure
{
  embedding: {
    pending: 0,
    running: 2,
    completed: 150,
    failed: 3,
    totalProcessed: 153,
    averageProcessingTime: 1250,
    rateLimitHits: 0
  },
  // ... other services
  search_analytics: {
    total_queries: 45,
    average_results_per_query: 8.2,
    average_relevance_score: 0.76
  },
  overall_health: {
    embedding: 'healthy',
    reranking: 'healthy',
    classifier: 'degraded',
    deepSearch: 'healthy',
    overall: 'degraded'
  }
}
```

### Health Monitoring

```typescript
// Get health status
const health = jinaManager.getHealthStatus();

// Test all connections
const connectionStatus = await jinaManager.testAllConnections();

// Get comprehensive health report
const healthReport = errorHandler.getHealthReport();
```

## 🔄 ETL Pipeline Integration

### Document Processing Flow

1. **Extraction**: S3 document ingestion with metadata
2. **Transformation**: Jina AI processing with rate limits
3. **Loading**: Multi-database storage (Supabase, Pinecone, Neo4j)

### Citation Support

Full traceability from vectors back to original S3-stored documents:

```typescript
// Chunk with citation information
const chunk: DocumentChunk = {
  chunk_id: 'chunk_001',
  content: 'document content...',
  citation: {
    document_id: 'doc_001',
    s3_key: 'project_aeon_dt/raw_documents/2025/06/project_nightingale/...',
    section_index: 0,
    paragraph_index: 1,
    sentence_range: { start: 0, end: 2 },
    character_range: { start: 0, end: 125 }
  },
  token_count: 25,
  chunk_index: 0
};
```

### Batch Processing

Optimized for large-scale document processing:

```typescript
// Process multiple documents
const batchResults = await jinaETL.processBatchForETL(
  documents.map(doc => ({ documentId: doc.id, chunks: doc.chunks })),
  {
    generateEmbeddings: true,
    classifyContent: true,
    batchSize: 5
  }
);
```

## ⚙️ Configuration

### Environment Variables

```bash
# Required
JINA_API_KEY=jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q

# Optional
JINA_EMBEDDING_MODEL=jina-embeddings-v2-base-en
JINA_RERANKING_MODEL=jina-reranker-v1-base-en
JINA_CLASSIFIER_MODEL=jina-classifier-v1-base-en
JINA_SEARCH_MODEL=jina-search-v1-base-en
```

### Service Configuration

```typescript
const config: JinaServiceManagerConfig = {
  apiKey: process.env.JINA_API_KEY!,
  logger: console,
  enableHealthChecks: true,
  healthCheckInterval: 300000 // 5 minutes
};
```

## 🧪 Testing

### Connection Testing

```typescript
// Test individual service
await embeddingService.testConnection();

// Test all services
const allStatus = await jinaManager.testAllConnections();

// ETL integration test
const etlStatus = await jinaETL.testETLConnections();
```

### Example Test Data

```typescript
const testChunks: DocumentChunk[] = [
  {
    chunk_id: 'test_001',
    content: 'Cybersecurity threats in critical infrastructure...',
    citation: { /* citation data */ },
    token_count: 50,
    chunk_index: 0
  }
];
```

## 📈 Performance Optimization

### Batch Size Recommendations

| Service | Recommended Batch Size | Max Input Length |
|---------|----------------------|------------------|
| Embedding | 10-20 texts | 8192 tokens |
| Reranking | 50 documents | 2048 tokens per doc |
| Classification | 3-5 texts | 2000 tokens |
| Deep Search | 30-50 documents | 2048 tokens per doc |

### Rate Limit Management

- Automatic queue management with configurable concurrency
- Exponential backoff for rate limit errors
- Circuit breakers prevent overwhelming failing services
- Health checks monitor service availability

## 🚨 Error Scenarios

### Common Issues and Solutions

1. **Rate Limit Exceeded (429)**
   - Automatic retry with exponential backoff
   - Queue management prevents overwhelming
   - Circuit breaker opens after repeated failures

2. **Authentication Error (401)**
   - Check API key configuration
   - Non-retryable - fix configuration

3. **Server Error (5xx)**
   - Automatic retry with backoff
   - Circuit breaker protection
   - Health monitoring alerts

4. **Network Timeout**
   - Automatic retry
   - Configurable timeout settings
   - Connection pooling

## 📝 Best Practices

### Service Usage

1. **Initialize once**: Create service manager at application startup
2. **Batch operations**: Use batch methods for multiple items
3. **Monitor health**: Enable health checks for production
4. **Handle errors**: Implement proper error handling
5. **Resource cleanup**: Call destroy() when shutting down

### Performance

1. **Optimal batch sizes**: Follow recommended batch sizes
2. **Parallel processing**: Use batch methods for concurrent processing
3. **Rate limit awareness**: Monitor metrics to stay within limits
4. **Circuit breaker respect**: Handle service unavailability gracefully

### Security

1. **API key protection**: Store in environment variables
2. **Request validation**: Validate inputs before sending
3. **Error information**: Don't expose sensitive data in errors
4. **Audit logging**: Log important operations

## 🔧 Troubleshooting

### Common Problems

**Problem**: High rate limit hits  
**Solution**: Reduce batch sizes, increase delays between batches

**Problem**: Circuit breaker frequently opening  
**Solution**: Check network connectivity, API key validity, service status

**Problem**: Low classification confidence  
**Solution**: Review labels, ensure text quality, consider custom models

**Problem**: Poor search relevance  
**Solution**: Try different search depths, adjust relevance thresholds

### Debug Information

```typescript
// Get detailed metrics
const metrics = jinaManager.getServiceMetrics();
console.log('Detailed metrics:', JSON.stringify(metrics, null, 2));

// Check error details
const errorMetrics = errorHandler.getAllErrorMetrics();
console.log('Error breakdown:', errorMetrics);

// Health report
const healthReport = errorHandler.getHealthReport();
console.log('Health recommendations:', healthReport.recommendations);
```

## 🔗 Integration with Project Seldon

This Jina AI integration is designed to seamlessly integrate with:

- **S3 Document Storage**: Process documents directly from S3
- **Supabase Metadata**: Store processing results and metrics
- **Pinecone Vector DB**: Store embeddings with full citation support
- **Neo4j Knowledge Graph**: Create relationships between entities
- **ETL Pipeline**: Full integration with document processing workflow

## 📚 API Reference

See individual service files for complete API documentation:
- [JinaEmbeddingService.ts](./JinaEmbeddingService.ts)
- [JinaRerankingService.ts](./JinaRerankingService.ts)
- [JinaClassifierService.ts](./JinaClassifierService.ts)
- [JinaDeepSearchService.ts](./JinaDeepSearchService.ts)
- [JinaServiceManager.ts](./JinaServiceManager.ts)

---

*"Intelligence without limits, reliability without compromise."* - Project Seldon