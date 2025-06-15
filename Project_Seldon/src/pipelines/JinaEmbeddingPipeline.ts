/**
 * Jina Embedding Pipeline for Project Seldon
 * Handles document embedding generation with rate limiting and error handling
 */

import { logger } from '../utils/logger';
import { JinaServiceManager } from '../services/jina/index';
import { 
  DocumentChunk, 
  VectorRecord,
  ProcessingStatus,
  ETLContext
} from '../types/index';
import { Configuration } from '../config/types';
import PQueue from 'p-queue';

export interface EmbeddingPipelineOptions {
  batchSize?: number;
  maxRetries?: number;
  retryDelay?: number;
  concurrency?: number;
}

export interface EmbeddingResult {
  vectorRecords: VectorRecord[];
  stats: EmbeddingStats;
  errors: EmbeddingError[];
}

export interface EmbeddingStats {
  totalChunks: number;
  successfulChunks: number;
  failedChunks: number;
  totalTokens: number;
  processingTime: number;
  averageEmbeddingTime: number;
}

export interface EmbeddingError {
  chunkId: string;
  error: Error;
  retryCount: number;
}

export class JinaEmbeddingPipeline {
  private jinaManager: JinaServiceManager;
  private config: Configuration;
  private queue: PQueue;

  constructor(config: Configuration) {
    this.config = config;
    this.jinaManager = new JinaServiceManager({
      apiKey: config.jina.apiKey,
      enableHealthChecks: true,
      healthCheckInterval: 60000
    });

    this.queue = new PQueue({ 
      concurrency: config.etl.concurrency,
      interval: 1000,
      intervalCap: config.jina.rateLimit.burstLimit
    });
  }

  /**
   * Process chunks to generate embeddings
   */
  public async processChunks(
    chunks: DocumentChunk[],
    context: ETLContext,
    options: EmbeddingPipelineOptions = {}
  ): Promise<EmbeddingResult> {
    const startTime = Date.now();
    const stats: EmbeddingStats = {
      totalChunks: chunks.length,
      successfulChunks: 0,
      failedChunks: 0,
      totalTokens: 0,
      processingTime: 0,
      averageEmbeddingTime: 0,
    };
    const errors: EmbeddingError[] = [];
    const vectorRecords: VectorRecord[] = [];

    context.logger.info(`Starting embedding pipeline for ${chunks.length} chunks`);

    try {
      // Process chunks in batches
      const batchSize = options.batchSize || this.config.etl.batchSize;
      const batches = this.createBatches(chunks, batchSize);

      context.logger.info(`Processing ${batches.length} batches of size ${batchSize}`);

      // Process each batch with concurrency control
      const batchResults = await Promise.all(
        batches.map((batch, index) => 
          this.queue.add(() => this.processBatch(batch, index, context, options))
        )
      );

      // Aggregate results
      for (const result of batchResults) {
        if (result) {
          vectorRecords.push(...result.vectorRecords);
          stats.successfulChunks += result.successful;
          stats.failedChunks += result.failed;
          stats.totalTokens += result.tokens;
          errors.push(...result.errors);
        }
      }

      stats.processingTime = Date.now() - startTime;
      stats.averageEmbeddingTime = stats.processingTime / stats.totalChunks;

      context.logger.info('Embedding pipeline completed', {
        ...stats,
        errorCount: errors.length,
      });

      return { vectorRecords, stats, errors };
    } catch (error) {
      context.logger.error('Embedding pipeline failed', error as Error);
      throw error;
    }
  }

  /**
   * Process a single batch of chunks
   */
  private async processBatch(
    chunks: DocumentChunk[],
    batchIndex: number,
    context: ETLContext,
    options: EmbeddingPipelineOptions
  ): Promise<{
    vectorRecords: VectorRecord[];
    successful: number;
    failed: number;
    tokens: number;
    errors: EmbeddingError[];
  }> {
    const vectorRecords: VectorRecord[] = [];
    const errors: EmbeddingError[] = [];
    let successful = 0;
    let failed = 0;
    let tokens = 0;

    context.logger.debug(`Processing batch ${batchIndex + 1} with ${chunks.length} chunks`);

    // Process each chunk in the batch
    for (const chunk of chunks) {
      try {
        const vectorRecord = await this.processChunk(chunk, context, options);
        vectorRecords.push(vectorRecord);
        successful++;
        tokens += chunk.metadata.tokenCount || 0;
      } catch (error) {
        failed++;
        errors.push({
          chunkId: chunk.id,
          error: error as Error,
          retryCount: 0,
        });
        context.logger.error(`Failed to process chunk ${chunk.id}`, error as Error);
      }
    }

    return { vectorRecords, successful, failed, tokens, errors };
  }

  /**
   * Process a single chunk
   */
  private async processChunk(
    chunk: DocumentChunk,
    context: ETLContext,
    options: EmbeddingPipelineOptions
  ): Promise<VectorRecord> {
    const maxRetries = options.maxRetries || this.config.etl.maxRetries;
    const retryDelay = options.retryDelay || this.config.etl.retryDelay;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        // Generate embedding using Jina
        const embedding = await this.jinaManager.embeddingService.generateEmbedding(
          chunk.content,
          {
            model: this.config.jina.embeddingModel,
            dimensions: 768
          }
        );

        // Create vector record
        const vectorRecord: VectorRecord = {
          id: chunk.id,
          documentId: chunk.documentId,
          chunkId: chunk.id,
          values: embedding,
          dimension: embedding.length,
          metadata: {
            ...chunk.metadata,
            model: this.config.jina.embeddingModel,
            // Convert metadata to VectorMetadata format
            chunk_id: chunk.id,
            document_id: chunk.documentId,
            content: chunk.content.substring(0, 1000),
            content_type: 'text',
            created_at: new Date().toISOString()
          },
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        // Update metrics
        context.metrics.increment('embeddings.generated', 1, {
          documentId: chunk.documentId,
          model: this.config.jina.embeddingModel,
        });

        return vectorRecord;
      } catch (error) {
        lastError = error as Error;
        
        if (attempt < maxRetries) {
          context.logger.warn(`Retrying chunk ${chunk.id} (attempt ${attempt + 1}/${maxRetries})`, {
            error: lastError.message,
          });
          
          // Exponential backoff
          await this.sleep(retryDelay * Math.pow(2, attempt));
        }
      }
    }

    // All retries failed
    context.metrics.increment('embeddings.failed', 1, {
      documentId: chunk.documentId,
      error: lastError?.message,
    });

    throw lastError || new Error('Unknown error during embedding generation');
  }

  /**
   * Create batches from chunks
   */
  private createBatches<T>(items: T[], batchSize: number): T[][] {
    const batches: T[][] = [];
    
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    
    return batches;
  }

  /**
   * Sleep helper for retry delays
   */
  private async sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Validate embeddings
   */
  public async validateEmbeddings(
    vectorRecords: VectorRecord[],
    context: ETLContext
  ): Promise<{ valid: VectorRecord[]; invalid: VectorRecord[] }> {
    const valid: VectorRecord[] = [];
    const invalid: VectorRecord[] = [];

    for (const record of vectorRecords) {
      if (this.isValidEmbedding(record)) {
        valid.push(record);
      } else {
        invalid.push(record);
        context.logger.warn(`Invalid embedding detected for chunk ${record.chunkId}`);
      }
    }

    context.logger.info(`Validated ${vectorRecords.length} embeddings`, {
      valid: valid.length,
      invalid: invalid.length,
    });

    return { valid, invalid };
  }

  /**
   * Check if embedding is valid
   */
  private isValidEmbedding(record: VectorRecord): boolean {
    // Check embedding exists and has correct dimension
    if (!record.embedding || !Array.isArray(record.embedding)) {
      return false;
    }

    if (record.embedding.length !== this.config.databases.pinecone.dimension) {
      return false;
    }

    // Check for NaN or invalid values
    for (const value of record.embedding) {
      if (typeof value !== 'number' || isNaN(value) || !isFinite(value)) {
        return false;
      }
    }

    // Check magnitude (should not be zero vector)
    const magnitude = Math.sqrt(
      record.embedding.reduce((sum, val) => sum + val * val, 0)
    );
    
    if (magnitude === 0) {
      return false;
    }

    return true;
  }

  /**
   * Retry failed embeddings
   */
  public async retryFailedEmbeddings(
    chunks: DocumentChunk[],
    errors: EmbeddingError[],
    context: ETLContext
  ): Promise<EmbeddingResult> {
    context.logger.info(`Retrying ${errors.length} failed embeddings`);

    // Get chunks that failed
    const failedChunkIds = new Set(errors.map(e => e.chunkId));
    const failedChunks = chunks.filter(chunk => failedChunkIds.has(chunk.id));

    // Process with increased retry count
    return this.processChunks(failedChunks, context, {
      maxRetries: this.config.etl.maxRetries * 2,
      retryDelay: this.config.etl.retryDelay * 2,
    });
  }

  /**
   * Get service health status
   */
  public async getHealth(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    details: Record<string, any>;
  }> {
    try {
      const health = this.jinaManager.getHealthStatus();
      
      return {
        status: health.embedding === 'healthy' ? 'healthy' : 'degraded',
        details: {
          embedding: health.embedding,
          queue: {
            size: this.queue.size,
            pending: this.queue.pending,
            isPaused: this.queue.isPaused,
          },
        },
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        details: {
          error: (error as Error).message,
        },
      };
    }
  }

  /**
   * Cleanup resources
   */
  public async cleanup(): Promise<void> {
    logger.info('Cleaning up Jina embedding pipeline');
    
    // Clear queue
    this.queue.clear();
    
    // Pause queue to prevent new items
    this.queue.pause();
    
    // Wait for pending items
    await this.queue.onIdle();
    
    logger.info('Jina embedding pipeline cleanup completed');
  }
}