/**
 * JinaServiceManager - Unified Management for All Jina AI Services
 * Project Seldon - Advanced Intelligence Architecture
 * Generated: June 13, 2025
 */

import { JinaRateLimiter } from './JinaRateLimiter';
import { JinaEmbeddingService } from './JinaEmbeddingService';
import { JinaRerankingService } from './JinaRerankingService';
import { JinaClassifierService } from './JinaClassifierService';
import { JinaDeepSearchService } from './JinaDeepSearchService';
import {
  DocumentChunk,
  ProcessedDocument,
  ServiceMetrics,
  JinaServiceType
} from '../../types/jina';

export interface JinaServiceManagerConfig {
  apiKey: string;
  logger?: Console;
  enableHealthChecks?: boolean;
  healthCheckInterval?: number; // milliseconds
}

export interface ServiceHealth {
  embedding: 'healthy' | 'degraded' | 'unhealthy';
  reranking: 'healthy' | 'degraded' | 'unhealthy';
  classifier: 'healthy' | 'degraded' | 'unhealthy';
  deepSearch: 'healthy' | 'degraded' | 'unhealthy';
  overall: 'healthy' | 'degraded' | 'unhealthy';
  lastChecked: string;
}

export interface ProcessingOptions {
  embedding?: {
    model?: string;
    dimensions?: number;
    batchSize?: number;
  };
  reranking?: {
    model?: string;
    top_k?: number;
    scoreThreshold?: number;
  };
  classification?: {
    model?: string;
    labels?: string[];
    confidence_threshold?: number;
  };
  search?: {
    model?: string;
    top_k?: number;
    search_depth?: 'basic' | 'advanced';
    relevance_threshold?: number;
  };
}

export class JinaServiceManager {
  private rateLimiter: JinaRateLimiter;
  public embeddingService: JinaEmbeddingService;
  private rerankingService: JinaRerankingService;
  private classifierService: JinaClassifierService;
  private deepSearchService: JinaDeepSearchService;
  
  private logger: Console;
  private healthCheckInterval?: NodeJS.Timeout;
  private lastHealthCheck?: ServiceHealth;

  constructor(config: JinaServiceManagerConfig) {
    this.logger = config.logger || console;
    
    // Initialize rate limiter
    this.rateLimiter = new JinaRateLimiter(this.logger);
    
    // Initialize all services
    this.embeddingService = new JinaEmbeddingService(this.rateLimiter, config.apiKey, this.logger);
    this.rerankingService = new JinaRerankingService(this.rateLimiter, config.apiKey, this.logger);
    this.classifierService = new JinaClassifierService(this.rateLimiter, config.apiKey, this.logger);
    this.deepSearchService = new JinaDeepSearchService(this.rateLimiter, config.apiKey, this.logger);
    
    // Setup health monitoring
    if (config.enableHealthChecks) {
      this.startHealthChecks(config.healthCheckInterval || 300000); // 5 minutes default
    }
    
    this.logger.log('JinaServiceManager initialized with all services');
  }

  /**
   * Process document chunks through the complete Jina AI pipeline
   */
  async processDocumentChunks(
    chunks: DocumentChunk[],
    options: ProcessingOptions = {}
  ): Promise<ProcessedDocument> {
    if (chunks.length === 0) {
      throw new Error('No chunks provided for processing');
    }

    this.logger.log(`Processing ${chunks.length} document chunks through Jina AI pipeline`);

    const startTime = Date.now();

    try {
      // Step 1: Generate embeddings
      const embeddings = await this.embeddingService.generateChunkEmbeddings(chunks, {
        model: options.embedding?.model,
        dimensions: options.embedding?.dimensions,
        batchSize: options.embedding?.batchSize
      });

      // Step 2: Classify content (using first chunk as representative)
      const representativeText = chunks[0].content;
      const classification = await this.classifierService.classifyText(representativeText, {
        model: options.classification?.model,
        labels: options.classification?.labels,
        confidence_threshold: options.classification?.confidence_threshold
      });

      // Step 3: Optional reranking (if query provided)
      let reranking_scores;
      if (options.reranking && chunks.length > 1) {
        const rerankResults = await this.rerankingService.rerankChunks(
          representativeText, // Use as query
          chunks,
          {
            model: options.reranking.model,
            top_k: options.reranking.top_k,
            scoreThreshold: options.reranking.scoreThreshold
          }
        );
        
        reranking_scores = rerankResults.map(result => ({
          chunk_id: result.chunk_id,
          relevance_score: result.relevance_score
        }));
      }

      // Step 4: Optional search (if query provided)
      let search_results;
      if (options.search) {
        const searchResults = await this.deepSearchService.searchChunks(
          representativeText, // Use as query
          chunks,
          {
            model: options.search.model,
            top_k: options.search.top_k,
            search_depth: options.search.search_depth,
            relevance_threshold: options.search.relevance_threshold
          }
        );
        
        search_results = searchResults.map(result => ({
          chunk_id: result.chunk_id,
          relevance_score: result.relevance_score,
          snippet: result.snippet
        }));
      }

      const processingTime = Date.now() - startTime;
      this.logger.log(`Document processing completed in ${processingTime}ms`);

      return {
        chunks,
        embeddings,
        classification: {
          primary_label: classification.primary_label,
          confidence_scores: classification.all_scores,
          classified_at: new Date().toISOString()
        },
        reranking_scores,
        search_results
      };

    } catch (error) {
      const processingTime = Date.now() - startTime;
      this.logger.error(`Document processing failed after ${processingTime}ms:`, error);
      throw error;
    }
  }

  /**
   * Process documents in batch with optimal resource utilization
   */
  async processDocumentBatch(
    documentChunks: DocumentChunk[][],
    options: ProcessingOptions = {}
  ): Promise<ProcessedDocument[]> {
    this.logger.log(`Processing batch of ${documentChunks.length} documents`);

    const results: ProcessedDocument[] = [];
    const batchSize = 5; // Process 5 documents concurrently

    for (let i = 0; i < documentChunks.length; i += batchSize) {
      const batch = documentChunks.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (chunks, index) => {
        try {
          return await this.processDocumentChunks(chunks, options);
        } catch (error) {
          this.logger.error(`Failed to process document ${i + index}:`, error);
          throw error;
        }
      });

      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      this.logger.log(`Processed batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(documentChunks.length / batchSize)}`);
    }

    return results;
  }

  /**
   * Perform advanced semantic search across multiple documents
   */
  async semanticSearch(
    query: string,
    documentChunks: DocumentChunk[],
    options: {
      embedding_search?: boolean;
      rerank_results?: boolean;
      deep_search?: boolean;
      top_k?: number;
      relevance_threshold?: number;
    } = {}
  ): Promise<{
    embedding_results?: Array<{ chunk_id: string; similarity: number; chunk: DocumentChunk }>;
    rerank_results?: Array<{ chunk_id: string; relevance_score: number; chunk: DocumentChunk; rank: number }>;
    deep_search_results?: Array<{ chunk_id: string; relevance_score: number; snippet: string; chunk: DocumentChunk; rank: number }>;
    combined_results?: Array<{ chunk_id: string; combined_score: number; chunk: DocumentChunk; rank: number }>;
  }> {
    this.logger.log(`Performing semantic search for query: "${query.substring(0, 100)}..."`);

    const results: any = {};

    // Embedding-based similarity search
    if (options.embedding_search) {
      const queryEmbedding = await this.embeddingService.generateQueryEmbedding(query);
      const chunkEmbeddings = await this.embeddingService.generateBatchEmbeddings(
        documentChunks.map(chunk => chunk.content)
      );

      const similarities = chunkEmbeddings.map((embedding, index) => ({
        chunk_id: documentChunks[index].chunk_id,
        similarity: this.embeddingService.calculateCosineSimilarity(queryEmbedding, embedding),
        chunk: documentChunks[index]
      }))
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, options.top_k || 10)
      .filter(result => !options.relevance_threshold || result.similarity >= options.relevance_threshold);

      results.embedding_results = similarities;
    }

    // Reranking-based search
    if (options.rerank_results) {
      const rerankResults = await this.rerankingService.rerankChunks(query, documentChunks, {
        top_k: options.top_k,
        scoreThreshold: options.relevance_threshold
      });

      results.rerank_results = rerankResults;
    }

    // Deep search
    if (options.deep_search) {
      const searchResults = await this.deepSearchService.searchChunks(query, documentChunks, {
        top_k: options.top_k,
        relevance_threshold: options.relevance_threshold,
        search_depth: 'advanced'
      });

      results.deep_search_results = searchResults;
    }

    // Combine results if multiple methods were used
    if (Object.keys(results).length > 1) {
      const combinedScores = new Map<string, { chunk: DocumentChunk; scores: number[]; }>();

      // Normalize and combine scores
      Object.values(results).forEach((methodResults: any[]) => {
        methodResults.forEach((result, index) => {
          const normalizedScore = 1 - (index / methodResults.length); // Position-based normalization
          
          const existing = combinedScores.get(result.chunk_id);
          if (existing) {
            existing.scores.push(normalizedScore);
          } else {
            combinedScores.set(result.chunk_id, {
              chunk: result.chunk,
              scores: [normalizedScore]
            });
          }
        });
      });

      const combinedResults = Array.from(combinedScores.entries())
        .map(([chunk_id, data]) => ({
          chunk_id,
          combined_score: data.scores.reduce((sum, score) => sum + score, 0) / data.scores.length,
          chunk: data.chunk,
          rank: 0
        }))
        .sort((a, b) => b.combined_score - a.combined_score)
        .slice(0, options.top_k || 10)
        .map((result, index) => ({ ...result, rank: index + 1 }));

      results.combined_results = combinedResults;
    }

    return results;
  }

  /**
   * Get comprehensive metrics from all services
   */
  getServiceMetrics(): ServiceMetrics & {
    search_analytics: any;
    overall_health: ServiceHealth;
  } {
    const rateLimiterMetrics = this.rateLimiter.getMetrics();
    const searchAnalytics = this.deepSearchService.getAnalytics();
    const healthStatus = this.getHealthStatus();

    return {
      ...rateLimiterMetrics,
      search_analytics: searchAnalytics,
      overall_health: healthStatus
    };
  }

  /**
   * Get current health status of all services
   */
  getHealthStatus(): ServiceHealth {
    const rateLimiterHealth = this.rateLimiter.getHealthStatus();
    
    const healthCounts = Object.values(rateLimiterHealth).reduce((counts, status) => {
      counts[status]++;
      return counts;
    }, { healthy: 0, degraded: 0, unhealthy: 0 });

    let overall: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
    if (healthCounts.unhealthy > 0) {
      overall = 'unhealthy';
    } else if (healthCounts.degraded > 0) {
      overall = 'degraded';
    }

    const health: ServiceHealth = {
      ...rateLimiterHealth,
      overall,
      lastChecked: new Date().toISOString()
    };

    this.lastHealthCheck = health;
    return health;
  }

  /**
   * Test connectivity to all services
   */
  async testAllConnections(): Promise<Record<JinaServiceType, boolean>> {
    this.logger.log('Testing connectivity to all Jina AI services...');

    const [embeddingOk, rerankingOk, classifierOk, searchOk] = await Promise.all([
      this.embeddingService.testConnection(),
      this.rerankingService.testConnection(),
      this.classifierService.testConnection(),
      this.deepSearchService.testConnection()
    ]);

    const results = {
      embedding: embeddingOk,
      reranking: rerankingOk,
      classifier: classifierOk,
      deepSearch: searchOk
    };

    const allHealthy = Object.values(results).every(status => status);
    this.logger.log(allHealthy ? 'All services are healthy' : 'Some services have connectivity issues');

    return results;
  }

  /**
   * Start periodic health checks
   */
  private startHealthChecks(intervalMs: number): void {
    this.logger.log(`Starting health checks every ${intervalMs}ms`);
    
    this.healthCheckInterval = setInterval(async () => {
      try {
        const health = this.getHealthStatus();
        
        if (health.overall !== 'healthy') {
          this.logger.warn('Service health degraded:', health);
        }
        
        // Optionally run connection tests if severely degraded
        if (health.overall === 'unhealthy') {
          await this.testAllConnections();
        }
      } catch (error) {
        this.logger.error('Health check failed:', error);
      }
    }, intervalMs);
  }

  /**
   * Stop health checks
   */
  stopHealthChecks(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = undefined;
      this.logger.log('Health checks stopped');
    }
  }

  /**
   * Pause all services
   */
  pauseAllServices(): void {
    this.rateLimiter.pauseService('embedding');
    this.rateLimiter.pauseService('reranking');
    this.rateLimiter.pauseService('classifier');
    this.rateLimiter.pauseService('deepSearch');
    this.logger.log('All services paused');
  }

  /**
   * Resume all services
   */
  resumeAllServices(): void {
    this.rateLimiter.resumeService('embedding');
    this.rateLimiter.resumeService('reranking');
    this.rateLimiter.resumeService('classifier');
    this.rateLimiter.resumeService('deepSearch');
    this.logger.log('All services resumed');
  }

  /**
   * Clear all queues and reset metrics
   */
  async clearAllQueues(): Promise<void> {
    await this.rateLimiter.clearAll();
    this.deepSearchService.resetAnalytics();
    this.logger.log('All queues cleared and metrics reset');
  }

  /**
   * Get individual service instances for advanced usage
   */
  getServices() {
    return {
      rateLimiter: this.rateLimiter,
      embedding: this.embeddingService,
      reranking: this.rerankingService,
      classifier: this.classifierService,
      deepSearch: this.deepSearchService
    };
  }

  /**
   * Cleanup and destroy all services
   */
  async destroy(): Promise<void> {
    this.logger.log('Destroying JinaServiceManager...');
    
    this.stopHealthChecks();
    await this.rateLimiter.destroy();
    
    this.logger.log('JinaServiceManager destroyed');
  }
}