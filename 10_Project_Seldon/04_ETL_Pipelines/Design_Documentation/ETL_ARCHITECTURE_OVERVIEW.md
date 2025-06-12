# ETL Architecture Overview
## Project Seldon - Intelligence Data Pipeline

**Version**: 1.0  
**Date**: December 6, 2025  
**Classification**: Production Architecture Document

## Executive Summary

This document outlines the comprehensive ETL (Extract, Transform, Load) architecture for Project Seldon's intelligence data pipeline, processing 100,406+ sources into Neo4j knowledge graph and Pinecone vector databases for advanced threat intelligence and prospect analysis.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Data Flow Diagrams](#data-flow-diagrams)
3. [Collection Stage](#collection-stage)
4. [Transformation Stage](#transformation-stage)
5. [Loading Stage](#loading-stage)
6. [Parallel Processing](#parallel-processing)
7. [Error Handling](#error-handling)
8. [Monitoring & Alerting](#monitoring--alerting)
9. [Performance Optimization](#performance-optimization)
10. [Security Considerations](#security-considerations)

## Architecture Overview

### Core Components

```mermaid
graph TB
    subgraph "Data Sources"
        A1[CISA Advisories]
        A2[GitHub Repositories]
        A3[Annual Reports]
        A4[Threat Intelligence Feeds]
        A5[OSINT Sources]
    end
    
    subgraph "Collection Layer"
        B1[API Collectors]
        B2[Web Scrapers]
        B3[Feed Parsers]
        B4[Document Processors]
    end
    
    subgraph "Processing Layer"
        C1[Data Validation]
        C2[Entity Extraction]
        C3[Relationship Mapping]
        C4[Embedding Generation]
    end
    
    subgraph "Storage Layer"
        D1[Neo4j Graph DB]
        D2[Pinecone Vector DB]
        D3[PostgreSQL Metadata]
        D4[S3 Raw Storage]
    end
    
    A1 --> B1
    A2 --> B1
    A3 --> B2
    A4 --> B3
    A5 --> B4
    
    B1 --> C1
    B2 --> C1
    B3 --> C1
    B4 --> C1
    
    C1 --> C2
    C2 --> C3
    C3 --> D1
    C2 --> C4
    C4 --> D2
    C1 --> D3
    B1 --> D4
```

## Data Flow Diagrams

### Primary Data Pipeline

```mermaid
sequenceDiagram
    participant S as Source Systems
    participant C as Collectors
    participant Q as Message Queue
    participant P as Processors
    participant V as Validators
    participant T as Transformers
    participant L as Loaders
    participant DB as Databases
    
    S->>C: Raw Data
    C->>Q: Enqueue Messages
    Q->>P: Dequeue for Processing
    P->>V: Validate Data
    V->>T: Transform & Enrich
    T->>L: Load Operations
    L->>DB: Store in Neo4j/Pinecone
    
    alt Validation Failure
        V-->>Q: Retry Queue
    end
    
    alt Processing Error
        P-->>Q: Dead Letter Queue
    end
```

### Real-time Intelligence Pipeline

```mermaid
graph LR
    subgraph "Stream Processing"
        A[Kafka Streams] --> B[Apache Flink]
        B --> C[Real-time Enrichment]
        C --> D[Stream Analytics]
    end
    
    subgraph "Storage"
        D --> E[Neo4j Real-time]
        D --> F[Pinecone Updates]
        D --> G[Alert Engine]
    end
    
    G --> H[Notification Service]
```

## Collection Stage

### 1. Source Configuration

```yaml
sources:
  cisa:
    type: api
    endpoint: https://www.cisa.gov/api/v1/
    rate_limit: 100/min
    retry_policy:
      max_retries: 3
      backoff: exponential
    
  github:
    type: api
    endpoints:
      - search: https://api.github.com/search/repositories
      - content: https://api.github.com/repos/{owner}/{repo}/contents
    auth: bearer_token
    rate_limit: 5000/hour
    
  annual_reports:
    type: scraper
    targets:
      - pattern: "*.pdf"
      - pattern: "*.html"
    parallel_workers: 10
```

### 2. Collection Architecture

```mermaid
graph TB
    subgraph "Collection Workers"
        W1[API Worker Pool]
        W2[Scraper Pool]
        W3[Document Pool]
    end
    
    subgraph "Queue Management"
        Q1[Priority Queue]
        Q2[Batch Queue]
        Q3[Real-time Queue]
    end
    
    subgraph "Storage"
        S1[Raw Data Lake]
        S2[Staging Area]
        S3[Processing Queue]
    end
    
    W1 --> Q1
    W2 --> Q2
    W3 --> Q2
    
    Q1 --> S3
    Q2 --> S2
    Q3 --> S3
    
    S2 --> S1
    S3 --> S1
```

### 3. Collector Implementation

```python
class IntelligenceCollector:
    def __init__(self, source_config):
        self.config = source_config
        self.rate_limiter = RateLimiter(source_config.rate_limit)
        self.retry_policy = RetryPolicy(source_config.retry_policy)
        
    async def collect(self):
        async with aiohttp.ClientSession() as session:
            tasks = []
            for endpoint in self.config.endpoints:
                task = self.collect_endpoint(session, endpoint)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return self.process_results(results)
```

## Transformation Stage

### 1. Data Processing Pipeline

```mermaid
graph LR
    subgraph "Validation"
        A[Schema Validation]
        B[Data Quality Checks]
        C[Deduplication]
    end
    
    subgraph "Enrichment"
        D[Entity Recognition]
        E[Relationship Extraction]
        F[Threat Scoring]
    end
    
    subgraph "Transformation"
        G[Format Conversion]
        H[Normalization]
        I[Embedding Generation]
    end
    
    A --> B --> C
    C --> D --> E --> F
    F --> G --> H --> I
```

### 2. Entity Extraction Pipeline

```python
class EntityExtractor:
    def __init__(self):
        self.nlp = spacy.load("en_core_web_trf")
        self.custom_patterns = self.load_patterns()
        
    def extract_entities(self, text):
        doc = self.nlp(text)
        
        entities = {
            'organizations': [],
            'threat_actors': [],
            'vulnerabilities': [],
            'technologies': [],
            'locations': []
        }
        
        # NER extraction
        for ent in doc.ents:
            if ent.label_ == "ORG":
                entities['organizations'].append(ent.text)
                
        # Custom pattern matching
        for pattern in self.custom_patterns:
            matches = pattern.findall(text)
            entities[pattern.category].extend(matches)
            
        return entities
```

### 3. Relationship Mapping

```mermaid
graph TB
    subgraph "Relationship Types"
        R1[Threat Actor -> Target]
        R2[Vulnerability -> Technology]
        R3[Organization -> Sector]
        R4[Incident -> Timeline]
    end
    
    subgraph "Graph Construction"
        G1[Node Creation]
        G2[Edge Definition]
        G3[Property Assignment]
        G4[Graph Validation]
    end
    
    R1 --> G1
    R2 --> G1
    R3 --> G2
    R4 --> G3
    G1 --> G4
    G2 --> G4
    G3 --> G4
```

## Loading Stage

### 1. Neo4j Graph Loading

```python
class Neo4jLoader:
    def __init__(self, uri, auth):
        self.driver = GraphDatabase.driver(uri, auth=auth)
        
    async def load_batch(self, entities, relationships):
        async with self.driver.async_session() as session:
            # Create nodes
            await session.run("""
                UNWIND $entities AS entity
                MERGE (n:Entity {id: entity.id})
                SET n += entity.properties
            """, entities=entities)
            
            # Create relationships
            await session.run("""
                UNWIND $relationships AS rel
                MATCH (a:Entity {id: rel.source})
                MATCH (b:Entity {id: rel.target})
                MERGE (a)-[r:RELATED {type: rel.type}]->(b)
                SET r += rel.properties
            """, relationships=relationships)
```

### 2. Pinecone Vector Loading

```python
class PineconeLoader:
    def __init__(self, api_key, environment):
        pinecone.init(api_key=api_key, environment=environment)
        self.index = pinecone.Index("intelligence-vectors")
        
    async def load_embeddings(self, documents):
        batch_size = 100
        
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i+batch_size]
            
            vectors = []
            for doc in batch:
                vector = {
                    'id': doc['id'],
                    'values': doc['embedding'],
                    'metadata': {
                        'source': doc['source'],
                        'timestamp': doc['timestamp'],
                        'entity_type': doc['entity_type']
                    }
                }
                vectors.append(vector)
            
            await self.index.upsert(vectors=vectors)
```

## Parallel Processing

### 1. Worker Pool Architecture

```mermaid
graph TB
    subgraph "Master Node"
        M[Task Scheduler]
        Q[Task Queue]
        R[Result Aggregator]
    end
    
    subgraph "Worker Nodes"
        W1[Worker 1<br/>8 Threads]
        W2[Worker 2<br/>8 Threads]
        W3[Worker 3<br/>8 Threads]
        W4[Worker N<br/>8 Threads]
    end
    
    subgraph "Processing"
        P1[Collection Tasks]
        P2[Transform Tasks]
        P3[Load Tasks]
    end
    
    M --> Q
    Q --> W1
    Q --> W2
    Q --> W3
    Q --> W4
    
    W1 --> P1
    W2 --> P2
    W3 --> P3
    W4 --> P1
    
    P1 --> R
    P2 --> R
    P3 --> R
```

### 2. Distributed Processing Implementation

```python
from celery import Celery
from kombu import Queue

app = Celery('intelligence_etl')

app.conf.task_routes = {
    'etl.collect.*': {'queue': 'collection'},
    'etl.transform.*': {'queue': 'transformation'},
    'etl.load.*': {'queue': 'loading'}
}

app.conf.task_queues = (
    Queue('collection', routing_key='collect.#'),
    Queue('transformation', routing_key='transform.#'),
    Queue('loading', routing_key='load.#'),
)

@app.task(bind=True, max_retries=3)
def process_source(self, source_id, source_config):
    try:
        # Collection
        data = collect_data(source_config)
        
        # Transformation
        transformed = transform_data(data)
        
        # Loading
        load_to_databases(transformed)
        
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60)
```

## Error Handling

### 1. Error Handling Strategy

```mermaid
graph TB
    subgraph "Error Types"
        E1[Network Errors]
        E2[Data Validation Errors]
        E3[Processing Errors]
        E4[Storage Errors]
    end
    
    subgraph "Handling Strategy"
        H1[Retry with Backoff]
        H2[Dead Letter Queue]
        H3[Manual Review]
        H4[Alert & Log]
    end
    
    subgraph "Recovery"
        R1[Automatic Recovery]
        R2[Semi-automatic Recovery]
        R3[Manual Intervention]
    end
    
    E1 --> H1 --> R1
    E2 --> H2 --> R2
    E3 --> H3 --> R3
    E4 --> H4 --> R2
```

### 2. Retry Logic Implementation

```python
class RetryHandler:
    def __init__(self, max_retries=3, base_delay=1):
        self.max_retries = max_retries
        self.base_delay = base_delay
        
    async def execute_with_retry(self, func, *args, **kwargs):
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                return await func(*args, **kwargs)
                
            except RetriableError as e:
                last_exception = e
                delay = self.base_delay * (2 ** attempt)
                
                logger.warning(
                    f"Attempt {attempt + 1} failed: {e}. "
                    f"Retrying in {delay} seconds..."
                )
                
                await asyncio.sleep(delay)
                
            except NonRetriableError as e:
                logger.error(f"Non-retriable error: {e}")
                raise
                
        raise MaxRetriesExceeded(last_exception)
```

### 3. Dead Letter Queue Processing

```python
class DeadLetterProcessor:
    def __init__(self, dlq_config):
        self.dlq = DeadLetterQueue(dlq_config)
        self.analyzer = ErrorAnalyzer()
        
    async def process_failed_items(self):
        while True:
            failed_items = await self.dlq.get_batch(size=100)
            
            for item in failed_items:
                analysis = self.analyzer.analyze(item)
                
                if analysis.is_recoverable:
                    await self.requeue_for_processing(item)
                else:
                    await self.send_for_manual_review(item)
                    
            await asyncio.sleep(300)  # Process every 5 minutes
```

## Monitoring & Alerting

### 1. Monitoring Architecture

```mermaid
graph TB
    subgraph "Metrics Collection"
        M1[Application Metrics]
        M2[System Metrics]
        M3[Business Metrics]
    end
    
    subgraph "Monitoring Stack"
        P[Prometheus]
        G[Grafana]
        A[AlertManager]
    end
    
    subgraph "Dashboards"
        D1[ETL Performance]
        D2[Data Quality]
        D3[System Health]
    end
    
    subgraph "Alerts"
        AL1[Critical Alerts]
        AL2[Warning Alerts]
        AL3[Info Alerts]
    end
    
    M1 --> P
    M2 --> P
    M3 --> P
    
    P --> G
    P --> A
    
    G --> D1
    G --> D2
    G --> D3
    
    A --> AL1
    A --> AL2
    A --> AL3
```

### 2. Key Performance Indicators

```yaml
kpis:
  throughput:
    - records_per_second: 10000
    - bytes_per_second: 100MB
    
  latency:
    - p50: 100ms
    - p95: 500ms
    - p99: 1000ms
    
  quality:
    - validation_success_rate: 99.5%
    - duplicate_rate: < 0.1%
    - enrichment_rate: > 95%
    
  availability:
    - uptime: 99.9%
    - error_rate: < 0.1%
```

### 3. Alert Configuration

```python
class AlertingSystem:
    def __init__(self):
        self.rules = self.load_alert_rules()
        self.channels = self.configure_channels()
        
    def configure_alerts(self):
        return {
            'critical': {
                'etl_pipeline_down': {
                    'condition': 'up{job="etl_pipeline"} == 0',
                    'duration': '5m',
                    'severity': 'critical',
                    'channels': ['pagerduty', 'slack']
                },
                'high_error_rate': {
                    'condition': 'rate(errors[5m]) > 0.1',
                    'duration': '10m',
                    'severity': 'critical',
                    'channels': ['email', 'slack']
                }
            },
            'warning': {
                'slow_processing': {
                    'condition': 'avg(processing_time) > 1000',
                    'duration': '15m',
                    'severity': 'warning',
                    'channels': ['slack']
                }
            }
        }
```

## Performance Optimization

### 1. Optimization Strategies

```mermaid
graph LR
    subgraph "Collection Optimization"
        CO1[Connection Pooling]
        CO2[Batch Processing]
        CO3[Async Operations]
    end
    
    subgraph "Processing Optimization"
        PO1[Parallel Processing]
        PO2[Memory Management]
        PO3[Caching Strategy]
    end
    
    subgraph "Storage Optimization"
        SO1[Bulk Inserts]
        SO2[Index Optimization]
        SO3[Partitioning]
    end
    
    CO1 --> PO1
    CO2 --> PO2
    CO3 --> PO3
    
    PO1 --> SO1
    PO2 --> SO2
    PO3 --> SO3
```

### 2. Caching Implementation

```python
class IntelligenceCache:
    def __init__(self):
        self.redis = Redis(
            host='localhost',
            port=6379,
            decode_responses=True
        )
        self.ttl = 3600  # 1 hour
        
    async def get_or_compute(self, key, compute_func):
        # Check cache
        cached = await self.redis.get(key)
        if cached:
            return json.loads(cached)
            
        # Compute if not cached
        result = await compute_func()
        
        # Store in cache
        await self.redis.setex(
            key,
            self.ttl,
            json.dumps(result)
        )
        
        return result
```

## Security Considerations

### 1. Security Architecture

```mermaid
graph TB
    subgraph "Access Control"
        AC1[API Authentication]
        AC2[Role-based Access]
        AC3[Service Accounts]
    end
    
    subgraph "Data Security"
        DS1[Encryption at Rest]
        DS2[Encryption in Transit]
        DS3[Data Masking]
    end
    
    subgraph "Audit & Compliance"
        AU1[Access Logging]
        AU2[Data Lineage]
        AU3[Compliance Checks]
    end
    
    AC1 --> DS1
    AC2 --> DS2
    AC3 --> DS3
    
    DS1 --> AU1
    DS2 --> AU2
    DS3 --> AU3
```

### 2. Security Implementation

```python
class SecurityManager:
    def __init__(self):
        self.encryptor = DataEncryptor()
        self.auth_manager = AuthenticationManager()
        self.audit_logger = AuditLogger()
        
    async def secure_pipeline_operation(self, operation, user, data):
        # Authentication
        if not await self.auth_manager.verify_user(user):
            raise UnauthorizedError()
            
        # Authorization
        if not await self.auth_manager.check_permission(user, operation):
            raise ForbiddenError()
            
        # Encryption
        encrypted_data = self.encryptor.encrypt(data)
        
        # Audit logging
        await self.audit_logger.log_operation(
            user=user,
            operation=operation,
            timestamp=datetime.utcnow(),
            data_hash=hashlib.sha256(data).hexdigest()
        )
        
        return encrypted_data
```

## Implementation Checklist

- [ ] Set up development environment
- [ ] Configure source connections
- [ ] Implement collectors for each source type
- [ ] Build transformation pipeline
- [ ] Set up Neo4j and Pinecone instances
- [ ] Implement loading mechanisms
- [ ] Configure monitoring and alerting
- [ ] Conduct security review
- [ ] Performance testing and optimization
- [ ] Documentation and training
- [ ] Production deployment

## Conclusion

This ETL architecture provides a robust, scalable, and secure foundation for processing 100,406+ intelligence sources into actionable insights. The design emphasizes parallel processing, comprehensive error handling, and real-time monitoring to ensure reliable operation at scale.