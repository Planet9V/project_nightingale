/**
 * JinaETLIntegration - ETL Pipeline Integration Example
 * Project Seldon - Advanced Intelligence Architecture
 * Generated: June 13, 2025
 */

import { JinaServiceManager, ProcessingOptions, DocumentChunk, ProcessedDocument } from './index';

/**
 * ETL Integration Service that demonstrates how to use Jina services
 * within the Project Seldon ETL pipeline
 */
export class JinaETLIntegration {
  private jinaManager: JinaServiceManager;
  private logger: Console;

  constructor(apiKey: string, logger: Console = console) {
    this.jinaManager = new JinaServiceManager({
      apiKey,
      logger,
      enableHealthChecks: true,
      healthCheckInterval: 300000 // 5 minutes
    });
    this.logger = logger;
  }

  /**
   * Process document chunks through the complete ETL pipeline
   * This method demonstrates the integration patterns from the ETL design
   */
  async processDocumentForETL(
    documentId: string,
    chunks: DocumentChunk[],
    options: {
      generateEmbeddings?: boolean;
      classifyContent?: boolean;
      rerankChunks?: boolean;
      performSearch?: boolean;
      searchQuery?: string;
    } = {}
  ): Promise<{
    documentId: string;
    processed: ProcessedDocument;
    metrics: {
      processingTimeMs: number;
      chunkCount: number;
      embeddingCount: number;
      classificationConfidence: number;
    };
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Processing document ${documentId} with ${chunks.length} chunks`);

    try {
      // Configure processing options based on requirements
      const processingOptions: ProcessingOptions = {};

      if (options.generateEmbeddings) {
        processingOptions.embedding = {
          model: 'jina-embeddings-v2-base-en',
          dimensions: 768,
          batchSize: 10
        };
      }

      if (options.classifyContent) {
        processingOptions.classification = {
          model: 'jina-classifier-v1-base-en',
          labels: [
            'threat_intelligence',
            'vulnerability_report',
            'executive_summary',
            'technical_analysis',
            'incident_report',
            'compliance_document',
            'risk_assessment'
          ],
          confidence_threshold: 0.7
        };
      }

      if (options.rerankChunks && options.searchQuery) {
        processingOptions.reranking = {
          model: 'jina-reranker-v1-base-en',
          top_k: Math.min(20, chunks.length),
          scoreThreshold: 0.5
        };
      }

      if (options.performSearch && options.searchQuery) {
        processingOptions.search = {
          model: 'jina-search-v1-base-en',
          top_k: Math.min(10, chunks.length),
          search_depth: 'advanced',
          relevance_threshold: 0.6
        };
      }

      // Process through Jina AI pipeline
      const processed = await this.jinaManager.processDocumentChunks(chunks, processingOptions);

      const processingTime = Date.now() - startTime;
      
      // Calculate metrics
      const metrics = {
        processingTimeMs: processingTime,
        chunkCount: chunks.length,
        embeddingCount: processed.embeddings.length,
        classificationConfidence: processed.classification.confidence_scores[0]?.score || 0
      };

      this.logger.log(`Document ${documentId} processed successfully in ${processingTime}ms`);

      return {
        documentId,
        processed,
        metrics
      };

    } catch (error) {
      const processingTime = Date.now() - startTime;
      this.logger.error(`Document ${documentId} processing failed after ${processingTime}ms:`, error);
      throw error;
    }
  }

  /**
   * Batch process multiple documents for ETL pipeline
   */
  async processBatchForETL(
    documents: Array<{
      documentId: string;
      chunks: DocumentChunk[];
    }>,
    options: {
      generateEmbeddings?: boolean;
      classifyContent?: boolean;
      batchSize?: number;
    } = {}
  ): Promise<Array<{
    documentId: string;
    processed: ProcessedDocument;
    success: boolean;
    error?: string;
    processingTimeMs: number;
  }>> {
    const batchSize = options.batchSize || 5;
    const results: any[] = [];

    this.logger.log(`Processing batch of ${documents.length} documents in batches of ${batchSize}`);

    for (let i = 0; i < documents.length; i += batchSize) {
      const batch = documents.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (doc) => {
        const startTime = Date.now();
        
        try {
          const result = await this.processDocumentForETL(doc.documentId, doc.chunks, {
            generateEmbeddings: options.generateEmbeddings,
            classifyContent: options.classifyContent
          });
          
          return {
            documentId: doc.documentId,
            processed: result.processed,
            success: true,
            processingTimeMs: Date.now() - startTime
          };
        } catch (error) {
          return {
            documentId: doc.documentId,
            processed: null,
            success: false,
            error: (error as Error).message,
            processingTimeMs: Date.now() - startTime
          };
        }
      });

      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      this.logger.log(`Processed batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(documents.length / batchSize)}`);
    }

    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;
    
    this.logger.log(`Batch processing completed: ${successful} successful, ${failed} failed`);

    return results;
  }

  /**
   * Perform semantic search across processed documents
   */
  async performSemanticSearch(
    query: string,
    chunks: DocumentChunk[],
    options: {
      useEmbeddings?: boolean;
      useReranking?: boolean;
      useDeepSearch?: boolean;
      topK?: number;
      relevanceThreshold?: number;
    } = {}
  ): Promise<{
    query: string;
    totalChunks: number;
    results: Array<{
      chunkId: string;
      score: number;
      method: 'embedding' | 'reranking' | 'deep_search';
      snippet?: string;
    }>;
    searchTimeMs: number;
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Performing semantic search for query: "${query.substring(0, 100)}..."`);

    const searchResults = await this.jinaManager.semanticSearch(query, chunks, {
      embedding_search: options.useEmbeddings,
      rerank_results: options.useReranking,
      deep_search: options.useDeepSearch,
      top_k: options.topK || 10,
      relevance_threshold: options.relevanceThreshold || 0.5
    });

    // Combine results from different methods
    const combinedResults: any[] = [];

    if (searchResults.embedding_results) {
      searchResults.embedding_results.forEach(result => {
        combinedResults.push({
          chunkId: result.chunk_id,
          score: result.similarity,
          method: 'embedding' as const
        });
      });
    }

    if (searchResults.rerank_results) {
      searchResults.rerank_results.forEach(result => {
        combinedResults.push({
          chunkId: result.chunk_id,
          score: result.relevance_score,
          method: 'reranking' as const
        });
      });
    }

    if (searchResults.deep_search_results) {
      searchResults.deep_search_results.forEach(result => {
        combinedResults.push({
          chunkId: result.chunk_id,
          score: result.relevance_score,
          method: 'deep_search' as const,
          snippet: result.snippet
        });
      });
    }

    // Deduplicate and sort by score
    const uniqueResults = new Map<string, any>();
    combinedResults.forEach(result => {
      const existing = uniqueResults.get(result.chunkId);
      if (!existing || result.score > existing.score) {
        uniqueResults.set(result.chunkId, result);
      }
    });

    const finalResults = Array.from(uniqueResults.values())
      .sort((a, b) => b.score - a.score)
      .slice(0, options.topK || 10);

    const searchTime = Date.now() - startTime;
    
    this.logger.log(`Search completed: ${finalResults.length} results in ${searchTime}ms`);

    return {
      query,
      totalChunks: chunks.length,
      results: finalResults,
      searchTimeMs: searchTime
    };
  }

  /**
   * Get comprehensive metrics for monitoring
   */
  getETLMetrics(): {
    service_metrics: any;
    health_status: any;
    error_summary: any;
  } {
    const serviceMetrics = this.jinaManager.getServiceMetrics();
    const healthStatus = this.jinaManager.getHealthStatus();
    
    // Generate error summary
    const errorSummary = {
      total_services: 4,
      healthy_services: Object.values(healthStatus).filter(status => status === 'healthy').length - 1, // -1 for overall
      degraded_services: Object.values(healthStatus).filter(status => status === 'degraded').length,
      unhealthy_services: Object.values(healthStatus).filter(status => status === 'unhealthy').length,
      overall_status: healthStatus.overall
    };

    return {
      service_metrics: serviceMetrics,
      health_status: healthStatus,
      error_summary: errorSummary
    };
  }

  /**
   * Test all service connections for ETL pipeline validation
   */
  async testETLConnections(): Promise<{
    all_services_ready: boolean;
    service_status: Record<string, boolean>;
    recommendations: string[];
  }> {
    this.logger.log('Testing ETL pipeline Jina AI service connections...');

    const connectionResults = await this.jinaManager.testAllConnections();
    const allReady = Object.values(connectionResults).every(status => status);
    
    const recommendations: string[] = [];
    
    if (!allReady) {
      recommendations.push('Some Jina AI services are not responding. Check API key and network connectivity.');
      
      Object.entries(connectionResults).forEach(([service, status]) => {
        if (!status) {
          recommendations.push(`${service} service is not responding - check service-specific configuration`);
        }
      });
    } else {
      recommendations.push('All Jina AI services are ready for ETL pipeline processing');
    }

    return {
      all_services_ready: allReady,
      service_status: connectionResults,
      recommendations
    };
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    this.logger.log('Cleaning up Jina ETL Integration...');
    await this.jinaManager.destroy();
  }
}

/**
 * Example usage for ETL pipeline integration
 */
export async function exampleETLUsage() {
  // Initialize with the provided API key
  const jinaETL = new JinaETLIntegration('jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q');

  try {
    // Test connections first
    const connectionStatus = await jinaETL.testETLConnections();
    console.log('Connection Status:', connectionStatus);

    if (!connectionStatus.all_services_ready) {
      console.error('Not all services are ready. Aborting.');
      return;
    }

    // Example document chunks (would come from S3 document extraction)
    const exampleChunks: DocumentChunk[] = [
      {
        chunk_id: 'chunk_001',
        content: 'This document discusses cybersecurity threats in critical infrastructure, focusing on energy sector vulnerabilities.',
        citation: {
          document_id: 'doc_001',
          s3_key: 'project_aeon_dt/raw_documents/2025/06/project_nightingale/prospects/A-012345_consumers_energy/executive_concierge_report.md',
          section_index: 0,
          paragraph_index: 0,
          sentence_range: { start: 0, end: 2 },
          character_range: { start: 0, end: 125 }
        },
        token_count: 25,
        chunk_index: 0
      },
      {
        chunk_id: 'chunk_002',
        content: 'Advanced persistent threats (APTs) targeting industrial control systems pose significant risks to operational technology.',
        citation: {
          document_id: 'doc_001',
          s3_key: 'project_aeon_dt/raw_documents/2025/06/project_nightingale/prospects/A-012345_consumers_energy/executive_concierge_report.md',
          section_index: 0,
          paragraph_index: 1,
          sentence_range: { start: 0, end: 1 },
          character_range: { start: 126, end: 246 }
        },
        token_count: 22,
        chunk_index: 1
      }
    ];

    // Process document through ETL pipeline
    const processed = await jinaETL.processDocumentForETL('doc_001', exampleChunks, {
      generateEmbeddings: true,
      classifyContent: true,
      rerankChunks: true,
      performSearch: true,
      searchQuery: 'cybersecurity threats energy sector'
    });

    console.log('Processing Results:', {
      documentId: processed.documentId,
      metrics: processed.metrics,
      embeddingCount: processed.processed.embeddings.length,
      classification: processed.processed.classification.primary_label
    });

    // Perform semantic search
    const searchResults = await jinaETL.performSemanticSearch(
      'industrial control system vulnerabilities',
      exampleChunks,
      {
        useEmbeddings: true,
        useReranking: true,
        useDeepSearch: true,
        topK: 5,
        relevanceThreshold: 0.3
      }
    );

    console.log('Search Results:', searchResults);

    // Get metrics
    const metrics = jinaETL.getETLMetrics();
    console.log('ETL Metrics:', metrics);

  } catch (error) {
    console.error('ETL Pipeline Error:', error);
  } finally {
    // Cleanup
    await jinaETL.cleanup();
  }
}

// Uncomment to run example
// exampleETLUsage().catch(console.error);