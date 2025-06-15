# Monitoring & Metrics

## System Health Dashboard

### Real-time Monitoring
The ETL pipeline provides comprehensive monitoring through multiple channels:

1. **CLI Progress Bars**
   - File processing progress
   - Chunk generation progress  
   - Embedding generation progress
   - Real-time speed metrics
   - ETA calculations

2. **Structured Logging**
   - Winston logger with multiple transports
   - File rotation (daily)
   - Log levels: debug, info, warn, error
   - Structured JSON format for parsing

3. **Health Checks**
   ```bash
   npm run health-check
   ```
   - Database connectivity
   - API availability
   - Service health
   - Resource usage

## Key Metrics

### Performance Metrics
- **Files/minute**: Processing speed
- **Chunks/second**: Chunking throughput
- **Embeddings/second**: Vector generation rate
- **API latency**: Service response times
- **Success rate**: % of successful operations

### Resource Metrics
- **Memory usage**: Node.js heap and RSS
- **CPU usage**: Process CPU percentage
- **Network I/O**: Bytes sent/received
- **Disk I/O**: Read/write operations

### Business Metrics
- **Documents processed**: Total count
- **Embeddings generated**: Vector count
- **Citations extracted**: Reference count
- **Errors encountered**: Failure analysis
- **Cost tracking**: API usage costs

## Monitoring Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌────────────────┐
│  ETL Pipeline   │────▶│   Metrics    │────▶│   Dashboard    │
│                 │     │  Collector   │     │                │
└─────────────────┘     └──────────────┘     └────────────────┘
         │                      │                      │
         ▼                      ▼                      ▼
┌─────────────────┐     ┌──────────────┐     ┌────────────────┐
│   Log Files     │     │  Supabase    │     │   Grafana      │
│                 │     │  Metrics DB  │     │  (Optional)    │
└─────────────────┘     └──────────────┘     └────────────────┘
```

## Progress Tracking

### CLI Interface
```
Files       |████████████████████| 45/100 | 45% | ETA: 5m 23s
Chunks      |██████████░░░░░░░░░░| 450/1000 | 45% | ETA: 2m 15s  
Embeddings  |████████░░░░░░░░░░░░| 400/1000 | 40% | ETA: 3m 00s

Speed: 9.2 files/min | Success: 98.5% | ETA: 5m 23s | Stage: embedding
```

### Progress Persistence
- Checkpoints saved every 5 seconds
- Resume capability after interruption
- Batch-level granularity
- File-level status tracking

## Error Monitoring

### Error Categories
1. **Connection Errors**
   - Database timeouts
   - Network failures
   - API unavailability

2. **Processing Errors**
   - Invalid documents
   - Parsing failures
   - Encoding issues

3. **Rate Limit Errors**
   - API quota exceeded
   - Throttling events
   - Circuit breaker trips

### Error Handling
```typescript
interface ErrorMetrics {
  category: string;
  count: number;
  lastOccurred: Date;
  samples: ErrorSample[];
}

interface ErrorSample {
  timestamp: Date;
  file: string;
  error: string;
  stack?: string;
}
```

## API Usage Tracking

### Jina AI Metrics
- Embedding requests/minute
- Reranking requests/minute
- Token consumption
- Cost estimation
- Rate limit status

### Database Metrics
- Query count
- Query latency
- Connection pool status
- Transaction success rate

## Alerting

### Alert Conditions
1. **Critical**
   - All database connections down
   - API key invalid
   - Disk space < 1GB
   - Memory usage > 90%

2. **Warning**
   - Success rate < 90%
   - Processing speed < 5 files/min
   - Error rate > 5%
   - API rate limit > 80%

3. **Info**
   - Batch completed
   - Checkpoint saved
   - Service recovered

### Alert Channels
- Console output (default)
- Log files
- Email (optional)
- Slack webhook (optional)

## Performance Optimization

### Bottleneck Detection
1. **CPU Bound**
   - Document parsing
   - Text processing
   - Compression

2. **I/O Bound**
   - File reading
   - Database writes
   - Network requests

3. **Memory Bound**
   - Large documents
   - Batch processing
   - Cache size

### Optimization Strategies
- Dynamic batch sizing
- Adaptive concurrency
- Smart caching
- Connection pooling

## Dashboard Views

### Overview Dashboard
- Total documents processed
- Current processing rate
- Success/failure ratio
- Resource utilization
- Cost tracking

### Detail Dashboard
- Per-file status
- Error breakdown
- API usage details
- Database performance
- Queue statistics

### Historical Dashboard
- Processing trends
- Error patterns
- Cost analysis
- Performance history
- Capacity planning

## Logging Best Practices

### Log Levels
```typescript
logger.debug('Detailed processing info');
logger.info('Normal operations');
logger.warn('Potential issues');
logger.error('Failures requiring attention');
```

### Structured Logging
```json
{
  "timestamp": "2025-06-13T10:30:45.123Z",
  "level": "info",
  "message": "Document processed",
  "metadata": {
    "documentId": "doc-123",
    "processingTime": 1234,
    "chunks": 15,
    "embeddings": 15,
    "success": true
  }
}
```

## Monitoring Commands

```bash
# View real-time logs
tail -f logs/etl-pipeline.log | jq

# Check error frequency
grep ERROR logs/etl-pipeline.log | wc -l

# Monitor resource usage
npm run monitor

# Generate performance report
npm run report

# Check API usage
npm run api-stats
```

## Metrics Storage

### Supabase Tables
- `api_usage_metrics`: API call tracking
- `processing_logs`: ETL execution logs
- `performance_metrics`: System performance
- `error_logs`: Error tracking

### Query Examples
```sql
-- Daily processing summary
SELECT 
  DATE(created_at) as date,
  COUNT(*) as documents,
  AVG(duration_ms) as avg_time,
  SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as success
FROM processing_logs
GROUP BY DATE(created_at)
ORDER BY date DESC;

-- API cost analysis
SELECT 
  service,
  DATE(created_at) as date,
  SUM(tokens_used) as tokens,
  SUM(cost_usd) as cost
FROM api_usage_metrics
GROUP BY service, DATE(created_at)
ORDER BY date DESC;
```