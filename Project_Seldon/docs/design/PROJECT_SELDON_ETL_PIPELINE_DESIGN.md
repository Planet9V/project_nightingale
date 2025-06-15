# Project Seldon ETL Pipeline Design
## Document Processing with Citation Support and S3 Integration

**Created**: June 13, 2025 5:25 AM UTC  
**Version**: 1.0 - Foundation Phase  
**Purpose**: Complete ETL pipeline for Project Seldon Phase 1 implementation

---

## 🎯 Pipeline Overview

The Project Seldon ETL pipeline transforms raw documents into a comprehensive knowledge graph with full citation traceability from vectors back to original S3-stored documents.

### Core Components
- **Extract**: S3 document ingestion with metadata capture
- **Transform**: Jina AI processing with rate limits (embeddings, classification, reranking)
- **Load**: Multi-database storage (Supabase, Pinecone, Neo4j) with referential integrity

---

## 📊 S3 Bucket Structure Optimization

### Recommended Folder Structure for `project_aeon_dt`
```
project_aeon_dt/
├── raw_documents/                    # Original documents
│   ├── 2025/
│   │   ├── 06/                      # Year/Month structure
│   │   │   ├── project_nightingale/ # Source project
│   │   │   │   ├── prospects/       # Document type
│   │   │   │   │   ├── A-012345_consumers_energy/
│   │   │   │   │   │   ├── metadata.json
│   │   │   │   │   │   ├── executive_concierge_report.md
│   │   │   │   │   │   ├── osint_intelligence.md
│   │   │   │   │   │   └── express_attack_briefs.md
│   │   │   │   └── reports/
│   │   │   └── cisa_advisories/
│   │   └── 07/
│   └── processed/                   # Successfully processed
│       ├── chunks/                  # Document chunks with citations
│       ├── embeddings/              # Generated embeddings
│       └── classifications/         # Jina classification results
├── failed/                          # Processing failures for retry
├── quarantine/                      # Documents requiring manual review
└── archives/                        # Long-term storage
    └── by_year/
        └── 2024/
```

### File Naming Convention
```
{document_id}_{timestamp}_{hash}.{ext}
A-012345_20250613_a1b2c3d4.md
```

---

## ⚡ Jina AI Service Integration with Rate Limits

### Service Configuration
```typescript
interface JinaServiceConfig {
  embedding: {
    endpoint: 'https://api.jina.ai/v1/embeddings',
    model: 'jina-embeddings-v2-base-en',
    rateLimit: 2000, // RPM
    dimensions: 768
  },
  reranking: {
    endpoint: 'https://api.jina.ai/v1/rerank',
    model: 'jina-reranker-v1-base-en',
    rateLimit: 2000 // RPM
  },
  classifier: {
    endpoint: 'https://api.jina.ai/v1/classify',
    model: 'jina-classifier-v1-base-en',
    rateLimit: 60 // RPM
  },
  deepSearch: {
    endpoint: 'https://api.jina.ai/v1/search',
    model: 'jina-search-v1-base-en',
    rateLimit: 500 // RPM
  }
}
```

### Rate Limiting Implementation
```typescript
class JinaRateLimiter {
  private queues: Map<string, PQueue> = new Map();
  
  constructor() {
    // Initialize rate-limited queues
    this.queues.set('embedding', new PQueue({
      concurrency: 10,
      intervalCap: 2000,
      interval: 60000 // 1 minute
    }));
    
    this.queues.set('reranking', new PQueue({
      concurrency: 10,
      intervalCap: 2000,
      interval: 60000
    }));
    
    this.queues.set('classifier', new PQueue({
      concurrency: 3,
      intervalCap: 60,
      interval: 60000
    }));
    
    this.queues.set('deepSearch', new PQueue({
      concurrency: 5,
      intervalCap: 500,
      interval: 60000
    }));
  }
  
  async processWithLimit<T>(
    service: keyof JinaServiceConfig,
    operation: () => Promise<T>
  ): Promise<T> {
    const queue = this.queues.get(service);
    if (!queue) throw new Error(`Unknown service: ${service}`);
    
    return queue.add(operation);
  }
}
```

---

## 🔄 ETL Pipeline Architecture

### 1. Document Extraction Service
```typescript
class DocumentExtractionService {
  constructor(
    private s3Client: S3Client,
    private supabaseClient: SupabaseClient
  ) {}

  async extractDocument(s3Key: string): Promise<ExtractedDocument> {
    // Download from S3
    const s3Object = await this.s3Client.getObject({
      Bucket: 'project_aeon_dt',
      Key: s3Key
    });
    
    const content = await s3Object.Body?.transformToString();
    
    // Extract metadata
    const metadata = await this.extractMetadata(s3Key, content);
    
    // Store extraction record
    const extractionRecord = await this.supabaseClient
      .from('document_extractions')
      .insert({
        s3_key: s3Key,
        extracted_at: new Date().toISOString(),
        content_hash: this.calculateHash(content),
        metadata: metadata,
        status: 'extracted'
      })
      .select()
      .single();

    return {
      id: extractionRecord.data.id,
      s3Key,
      content,
      metadata,
      contentHash: this.calculateHash(content)
    };
  }

  private async extractMetadata(s3Key: string, content: string): Promise<DocumentMetadata> {
    // Parse S3 path for metadata
    const pathParts = s3Key.split('/');
    const [year, month, project, documentType] = pathParts.slice(1, 5);
    
    // Extract from content (front matter, headers, etc.)
    const frontMatter = this.parseFrontMatter(content);
    
    return {
      source: {
        s3_bucket: 'project_aeon_dt',
        s3_key: s3Key,
        upload_date: new Date().toISOString()
      },
      classification: {
        project: project,
        document_type: documentType,
        year: parseInt(year),
        month: parseInt(month)
      },
      content: {
        word_count: content.split(/\s+/).length,
        language: 'en',
        format: this.detectFormat(content)
      },
      ...frontMatter
    };
  }
}
```

### 2. Document Transformation Service
```typescript
class DocumentTransformationService {
  constructor(
    private jinaClient: JinaRateLimiter,
    private supabaseClient: SupabaseClient
  ) {}

  async transformDocument(extractedDoc: ExtractedDocument): Promise<TransformedDocument> {
    // 1. Intelligent chunking with citation support
    const chunks = await this.createChunksWithCitations(extractedDoc);
    
    // 2. Generate embeddings (rate limited)
    const embeddings = await this.generateEmbeddings(chunks);
    
    // 3. Classify content (rate limited)
    const classification = await this.classifyContent(extractedDoc.content);
    
    // 4. Store transformation record
    const transformationRecord = await this.supabaseClient
      .from('document_transformations')
      .insert({
        extraction_id: extractedDoc.id,
        transformed_at: new Date().toISOString(),
        chunk_count: chunks.length,
        classification: classification,
        status: 'transformed'
      })
      .select()
      .single();

    return {
      id: transformationRecord.data.id,
      extractionId: extractedDoc.id,
      chunks,
      embeddings,
      classification
    };
  }

  private async createChunksWithCitations(doc: ExtractedDocument): Promise<DocumentChunk[]> {
    const chunks: DocumentChunk[] = [];
    const content = doc.content;
    
    // Smart chunking: respect paragraphs, sections, and sentence boundaries
    const sections = this.splitIntoSections(content);
    
    for (let sectionIndex = 0; sectionIndex < sections.length; sectionIndex++) {
      const section = sections[sectionIndex];
      const paragraphs = section.split('\n\n');
      
      for (let paragraphIndex = 0; paragraphIndex < paragraphs.length; paragraphIndex++) {
        const paragraph = paragraphs[paragraphIndex];
        
        // Create chunks of ~500 tokens with overlap
        const sentences = this.splitIntoSentences(paragraph);
        let currentChunk = '';
        let sentenceStart = 0;
        
        for (let sentenceIndex = 0; sentenceIndex < sentences.length; sentenceIndex++) {
          const sentence = sentences[sentenceIndex];
          const testChunk = currentChunk + ' ' + sentence;
          
          if (this.getTokenCount(testChunk) > 500 && currentChunk.length > 0) {
            // Store current chunk
            chunks.push({
              chunk_id: `${doc.id}_${chunks.length}`,
              content: currentChunk.trim(),
              citation: {
                document_id: doc.id,
                s3_key: doc.s3Key,
                section_index: sectionIndex,
                paragraph_index: paragraphIndex,
                sentence_range: {
                  start: sentenceStart,
                  end: sentenceIndex - 1
                },
                character_range: {
                  start: this.getCharacterPosition(content, sectionIndex, paragraphIndex, sentenceStart),
                  end: this.getCharacterPosition(content, sectionIndex, paragraphIndex, sentenceIndex - 1)
                }
              },
              token_count: this.getTokenCount(currentChunk),
              chunk_index: chunks.length
            });
            
            // Start new chunk with overlap (last 2 sentences)
            currentChunk = sentences.slice(Math.max(0, sentenceIndex - 2), sentenceIndex).join(' ') + ' ' + sentence;
            sentenceStart = Math.max(0, sentenceIndex - 2);
          } else {
            currentChunk = testChunk;
          }
        }
        
        // Handle remaining content
        if (currentChunk.trim().length > 0) {
          chunks.push({
            chunk_id: `${doc.id}_${chunks.length}`,
            content: currentChunk.trim(),
            citation: {
              document_id: doc.id,
              s3_key: doc.s3Key,
              section_index: sectionIndex,
              paragraph_index: paragraphIndex,
              sentence_range: {
                start: sentenceStart,
                end: sentences.length - 1
              },
              character_range: {
                start: this.getCharacterPosition(content, sectionIndex, paragraphIndex, sentenceStart),
                end: this.getCharacterPosition(content, sectionIndex, paragraphIndex, sentences.length - 1)
              }
            },
            token_count: this.getTokenCount(currentChunk),
            chunk_index: chunks.length
          });
        }
      }
    }
    
    return chunks;
  }

  private async generateEmbeddings(chunks: DocumentChunk[]): Promise<ChunkEmbedding[]> {
    const embeddings: ChunkEmbedding[] = [];
    
    for (const chunk of chunks) {
      const embedding = await this.jinaClient.processWithLimit('embedding', async () => {
        const response = await fetch('https://api.jina.ai/v1/embeddings', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${process.env.JINA_API_KEY}`
          },
          body: JSON.stringify({
            model: 'jina-embeddings-v2-base-en',
            input: chunk.content,
            dimensions: 768
          })
        });
        
        const result = await response.json();
        return result.data[0].embedding;
      });
      
      embeddings.push({
        chunk_id: chunk.chunk_id,
        embedding: embedding,
        dimension_count: 768,
        generated_at: new Date().toISOString()
      });
    }
    
    return embeddings;
  }

  private async classifyContent(content: string): Promise<ContentClassification> {
    return this.jinaClient.processWithLimit('classifier', async () => {
      const response = await fetch('https://api.jina.ai/v1/classify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.JINA_API_KEY}`
        },
        body: JSON.stringify({
          model: 'jina-classifier-v1-base-en',
          input: content.substring(0, 2000), // Classifier input limit
          labels: [
            'threat_intelligence',
            'vulnerability_report',
            'executive_summary',
            'technical_analysis',
            'incident_report',
            'compliance_document',
            'risk_assessment'
          ]
        })
      });
      
      const result = await response.json();
      return {
        primary_label: result.prediction,
        confidence_scores: result.scores,
        classified_at: new Date().toISOString()
      };
    });
  }
}
```

### 3. Multi-Database Loading Service
```typescript
class DocumentLoadingService {
  constructor(
    private supabaseClient: SupabaseClient,
    private pineconeClient: Pinecone,
    private neo4jClient: Neo4jDriver
  ) {}

  async loadDocument(transformedDoc: TransformedDocument): Promise<LoadedDocument> {
    // Parallel loading to all databases
    const [supabaseResult, pineconeResult, neo4jResult] = await Promise.all([
      this.loadToSupabase(transformedDoc),
      this.loadToPinecone(transformedDoc),
      this.loadToNeo4j(transformedDoc)
    ]);

    // Create cross-database reference mapping
    await this.createCrossReferences(transformedDoc, {
      supabase: supabaseResult,
      pinecone: pineconeResult,
      neo4j: neo4jResult
    });

    return {
      transformation_id: transformedDoc.id,
      loaded_at: new Date().toISOString(),
      databases: {
        supabase: supabaseResult,
        pinecone: pineconeResult,
        neo4j: neo4jResult
      }
    };
  }

  private async loadToSupabase(doc: TransformedDocument): Promise<SupabaseLoadResult> {
    // Store document metadata with full traceability
    const documentRecord = await this.supabaseClient
      .from('documents')
      .insert({
        transformation_id: doc.id,
        document_type: doc.classification.primary_label,
        chunk_count: doc.chunks.length,
        created_at: new Date().toISOString(),
        status: 'loaded'
      })
      .select()
      .single();

    // Store all chunks with citations
    const chunkRecords = await this.supabaseClient
      .from('document_chunks')
      .insert(
        doc.chunks.map(chunk => ({
          document_id: documentRecord.data.id,
          chunk_id: chunk.chunk_id,
          content: chunk.content,
          citation: chunk.citation,
          token_count: chunk.token_count,
          chunk_index: chunk.chunk_index
        }))
      )
      .select();

    // Store embeddings with chunk references
    const embeddingRecords = await this.supabaseClient
      .from('chunk_embeddings')
      .insert(
        doc.embeddings.map(embedding => ({
          chunk_id: embedding.chunk_id,
          embedding: embedding.embedding,
          dimension_count: embedding.dimension_count,
          generated_at: embedding.generated_at
        }))
      )
      .select();

    return {
      document_id: documentRecord.data.id,
      chunk_ids: chunkRecords.data.map(r => r.id),
      embedding_ids: embeddingRecords.data.map(r => r.id)
    };
  }

  private async loadToPinecone(doc: TransformedDocument): Promise<PineconeLoadResult> {
    const vectors = doc.chunks.map((chunk, index) => {
      const embedding = doc.embeddings.find(e => e.chunk_id === chunk.chunk_id);
      if (!embedding) throw new Error(`No embedding found for chunk ${chunk.chunk_id}`);

      return {
        id: chunk.chunk_id,
        values: embedding.embedding,
        metadata: {
          // Full citation information in metadata
          document_id: chunk.citation.document_id,
          s3_key: chunk.citation.s3_key,
          chunk_index: chunk.chunk_index,
          content_preview: chunk.content.substring(0, 1000),
          
          // Citation details for precise source lookup
          section_index: chunk.citation.section_index,
          paragraph_index: chunk.citation.paragraph_index,
          sentence_range: JSON.stringify(chunk.citation.sentence_range),
          character_range: JSON.stringify(chunk.citation.character_range),
          
          // Classification and filtering
          document_type: doc.classification.primary_label,
          token_count: chunk.token_count,
          loaded_at: new Date().toISOString()
        }
      };
    });

    const index = this.pineconeClient.index('nightingale');
    await index.upsert(vectors);

    return {
      vector_count: vectors.length,
      index_name: 'nightingale',
      vector_ids: vectors.map(v => v.id)
    };
  }

  private async loadToNeo4j(doc: TransformedDocument): Promise<Neo4jLoadResult> {
    const session = this.neo4jClient.session();
    
    try {
      // Create document node
      const documentResult = await session.run(`
        CREATE (d:Document {
          id: $id,
          transformation_id: $transformation_id,
          document_type: $document_type,
          chunk_count: $chunk_count,
          created_at: datetime($created_at)
        })
        RETURN d.id as document_id
      `, {
        id: `doc_${doc.id}`,
        transformation_id: doc.id,
        document_type: doc.classification.primary_label,
        chunk_count: doc.chunks.length,
        created_at: new Date().toISOString()
      });

      // Create chunk nodes with citation relationships
      for (const chunk of doc.chunks) {
        await session.run(`
          MATCH (d:Document {id: $document_id})
          CREATE (c:Chunk {
            id: $chunk_id,
            content: $content,
            token_count: $token_count,
            chunk_index: $chunk_index
          })
          CREATE (cit:Citation {
            s3_key: $s3_key,
            section_index: $section_index,
            paragraph_index: $paragraph_index,
            sentence_range: $sentence_range,
            character_range: $character_range
          })
          CREATE (d)-[:HAS_CHUNK]->(c)
          CREATE (c)-[:HAS_CITATION]->(cit)
        `, {
          document_id: `doc_${doc.id}`,
          chunk_id: chunk.chunk_id,
          content: chunk.content,
          token_count: chunk.token_count,
          chunk_index: chunk.chunk_index,
          s3_key: chunk.citation.s3_key,
          section_index: chunk.citation.section_index,
          paragraph_index: chunk.citation.paragraph_index,
          sentence_range: JSON.stringify(chunk.citation.sentence_range),
          character_range: JSON.stringify(chunk.citation.character_range)
        });
      }

      return {
        document_node_id: `doc_${doc.id}`,
        chunk_node_count: doc.chunks.length,
        citation_node_count: doc.chunks.length
      };
    } finally {
      await session.close();
    }
  }
}
```

---

## 🔗 Cross-Database Referential Integrity

### Metadata Schema Design
```sql
-- Supabase: Central metadata store with full traceability
CREATE TABLE document_extractions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  s3_key TEXT NOT NULL UNIQUE,
  extracted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  content_hash TEXT NOT NULL,
  metadata JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'extracted'
);

CREATE TABLE document_transformations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  extraction_id UUID REFERENCES document_extractions(id),
  transformed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  chunk_count INTEGER NOT NULL,
  classification JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'transformed'
);

CREATE TABLE documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  transformation_id UUID REFERENCES document_transformations(id),
  document_type TEXT NOT NULL,
  chunk_count INTEGER NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  status TEXT NOT NULL DEFAULT 'loaded'
);

CREATE TABLE document_chunks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id UUID REFERENCES documents(id),
  chunk_id TEXT NOT NULL UNIQUE,
  content TEXT NOT NULL,
  citation JSONB NOT NULL,
  token_count INTEGER NOT NULL,
  chunk_index INTEGER NOT NULL
);

CREATE TABLE chunk_embeddings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  chunk_id TEXT REFERENCES document_chunks(chunk_id),
  embedding VECTOR(768),
  dimension_count INTEGER NOT NULL DEFAULT 768,
  generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE cross_database_references (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  chunk_id TEXT REFERENCES document_chunks(chunk_id),
  pinecone_vector_id TEXT NOT NULL,
  neo4j_chunk_node_id TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for fast lookup
CREATE INDEX idx_document_chunks_chunk_id ON document_chunks(chunk_id);
CREATE INDEX idx_chunk_embeddings_chunk_id ON chunk_embeddings(chunk_id);
CREATE INDEX idx_cross_refs_chunk_id ON cross_database_references(chunk_id);
CREATE INDEX idx_extractions_s3_key ON document_extractions(s3_key);
```

---

## 🔍 Citation Lookup System

### Vector-to-Source Resolution
```typescript
class CitationLookupService {
  constructor(
    private supabaseClient: SupabaseClient,
    private s3Client: S3Client
  ) {}

  async resolveVectorToSource(vectorId: string): Promise<SourceCitation> {
    // Get chunk information from Supabase
    const { data: chunk } = await this.supabaseClient
      .from('document_chunks')
      .select(`
        *,
        documents!inner (
          transformation_id,
          document_transformations!inner (
            extraction_id,
            document_extractions!inner (
              s3_key,
              metadata
            )
          )
        )
      `)
      .eq('chunk_id', vectorId)
      .single();

    if (!chunk) throw new Error(`Chunk not found: ${vectorId}`);

    const citation = chunk.citation;
    const s3Key = chunk.documents.document_transformations.document_extractions.s3_key;

    // Optional: Get original source excerpt
    const sourceExcerpt = await this.getSourceExcerpt(s3Key, citation);

    return {
      chunk_id: vectorId,
      s3_location: {
        bucket: 'project_aeon_dt',
        key: s3Key
      },
      citation: {
        section_index: citation.section_index,
        paragraph_index: citation.paragraph_index,
        sentence_range: citation.sentence_range,
        character_range: citation.character_range
      },
      source_excerpt: sourceExcerpt,
      document_metadata: chunk.documents.document_transformations.document_extractions.metadata
    };
  }

  private async getSourceExcerpt(s3Key: string, citation: any): Promise<string> {
    // Download original document
    const s3Object = await this.s3Client.getObject({
      Bucket: 'project_aeon_dt',
      Key: s3Key
    });
    
    const content = await s3Object.Body?.transformToString();
    if (!content) throw new Error(`Could not read S3 object: ${s3Key}`);

    // Extract the exact cited portion
    const startChar = citation.character_range.start;
    const endChar = citation.character_range.end;
    
    return content.substring(startChar, endChar + 1);
  }
}
```

---

## ⚙️ Pipeline Orchestration

### Main ETL Controller
```typescript
class ETLPipelineOrchestrator {
  constructor(
    private extractionService: DocumentExtractionService,
    private transformationService: DocumentTransformationService,
    private loadingService: DocumentLoadingService
  ) {}

  async processDocument(s3Key: string): Promise<ETLResult> {
    const startTime = Date.now();
    
    try {
      // Extract
      console.log(`Extracting document: ${s3Key}`);
      const extracted = await this.extractionService.extractDocument(s3Key);
      
      // Transform
      console.log(`Transforming document: ${extracted.id}`);
      const transformed = await this.transformationService.transformDocument(extracted);
      
      // Load
      console.log(`Loading document: ${transformed.id}`);
      const loaded = await this.loadingService.loadDocument(transformed);
      
      const processingTime = Date.now() - startTime;
      
      return {
        success: true,
        s3_key: s3Key,
        extraction_id: extracted.id,
        transformation_id: transformed.id,
        chunk_count: transformed.chunks.length,
        embedding_count: transformed.embeddings.length,
        processing_time_ms: processingTime,
        databases_loaded: Object.keys(loaded.databases)
      };
      
    } catch (error) {
      console.error(`ETL pipeline failed for ${s3Key}:`, error);
      
      // Move to failed folder for retry
      await this.moveToFailedFolder(s3Key, error.message);
      
      return {
        success: false,
        s3_key: s3Key,
        error: error.message,
        processing_time_ms: Date.now() - startTime
      };
    }
  }

  async processBatch(s3Keys: string[]): Promise<ETLBatchResult> {
    const results: ETLResult[] = [];
    const batchSize = 10; // Process in batches to respect rate limits
    
    for (let i = 0; i < s3Keys.length; i += batchSize) {
      const batch = s3Keys.slice(i, i + batchSize);
      
      const batchResults = await Promise.all(
        batch.map(s3Key => this.processDocument(s3Key))
      );
      
      results.push(...batchResults);
      
      // Small delay between batches to be respectful to Jina API
      if (i + batchSize < s3Keys.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    
    return {
      total_documents: s3Keys.length,
      successful_count: successful.length,
      failed_count: failed.length,
      total_chunks: successful.reduce((sum, r) => sum + (r.chunk_count || 0), 0),
      total_embeddings: successful.reduce((sum, r) => sum + (r.embedding_count || 0), 0),
      results: results
    };
  }
}
```

---

## 🚀 Implementation Roadmap

### Week 1: Core Pipeline Development
- [ ] **Day 1-2**: Implement DocumentExtractionService
- [ ] **Day 3-4**: Implement DocumentTransformationService with Jina integration
- [ ] **Day 5**: Implement rate limiting and error handling

### Week 2: Database Integration
- [ ] **Day 1-2**: Implement Supabase loading service
- [ ] **Day 3**: Implement Pinecone loading service  
- [ ] **Day 4**: Implement Neo4j loading service
- [ ] **Day 5**: Implement cross-database references

### Week 3: Citation System
- [ ] **Day 1-2**: Implement intelligent chunking with citations
- [ ] **Day 3-4**: Implement citation lookup service
- [ ] **Day 5**: Test full traceability from vector to source

### Week 4: Production Optimization
- [ ] **Day 1-2**: Pipeline orchestration and batch processing
- [ ] **Day 3**: Error handling and retry mechanisms
- [ ] **Day 4**: Performance optimization and monitoring
- [ ] **Day 5**: Full integration testing

---

## 📊 Success Metrics

### Technical Metrics
- **Processing Speed**: <30 seconds per document
- **Citation Accuracy**: 100% traceability from vector to source
- **Rate Limit Compliance**: 0 Jina API violations
- **Data Integrity**: 100% cross-database referential integrity

### Business Metrics
- **Document Coverage**: 670+ Project Nightingale artifacts processed
- **Search Precision**: Ability to find exact source passages
- **Knowledge Retrieval**: Sub-second citation resolution
- **Scalability**: Support for 10,000+ documents per day

---

## 🎯 Next Steps

1. **Update Jina API key** throughout codebase
2. **Create Supabase metadata schema** with proper relationships
3. **Implement S3 folder structure** optimization
4. **Begin Phase 1 development** with core services
5. **Test with sample documents** from Project Nightingale

The ETL pipeline will transform Project Seldon into the most advanced cybersecurity intelligence system ever built, with complete document traceability and citation support enabling "How did you know that?" moments at scale.

---

*"Knowledge without attribution is just speculation. True intelligence knows its sources."* - Project Seldon Philosophy