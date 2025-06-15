import axios, { AxiosInstance, AxiosError } from 'axios';
import PQueue from 'p-queue';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import { logger } from '../utils/logger';
import { EventEmitter } from 'events';

export interface JinaEmbeddingRequest {
  input: string | string[];
  model?: string;
}

export interface JinaEmbeddingResponse {
  object: string;
  data: Array<{
    object: string;
    index: number;
    embedding: number[];
  }>;
  model: string;
  usage: {
    prompt_tokens: number;
    total_tokens: number;
  };
}

export interface JinaRerankRequest {
  query: string;
  documents: string[];
  model?: string;
  top_n?: number;
}

export interface JinaRerankResponse {
  model: string;
  usage: {
    total_tokens: number;
  };
  results: Array<{
    index: number;
    document: {
      text: string;
    };
    relevance_score: number;
  }>;
}

export interface BatchResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  retries: number;
  processingTime: number;
}

export interface JinaServiceConfig {
  apiKey: string;
  endpoints: {
    embedding: string;
    reranking: string;
    classifier: string;
    deepSearch: string;
  };
  models: {
    embedding: string;
    reranking: string;
    classifier: string;
    deepSearch: string;
  };
  rateLimits: {
    embedding: number;
    reranking: number;
    classifier: number;
    deepSearch: number;
  };
  maxRetries?: number;
  retryDelay?: number;
  batchSize?: number;
  timeout?: number;
}

export interface ServiceMetrics {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  totalTokens: number;
  totalCost: number;
  averageLatency: number;
  circuitBreakerState: 'closed' | 'open' | 'half-open';
}

export class EnhancedJinaService extends EventEmitter {
  private axiosInstance: AxiosInstance;
  private config: JinaServiceConfig;
  private queues: Map<string, PQueue>;
  private rateLimiters: Map<string, RateLimiterMemory>;
  private metrics: ServiceMetrics;
  private circuitBreaker: {
    failures: number;
    lastFailure: Date | null;
    state: 'closed' | 'open' | 'half-open';
    threshold: number;
    timeout: number;
  };

  constructor(config: JinaServiceConfig) {
    super();
    this.config = {
      maxRetries: 3,
      retryDelay: 1000,
      batchSize: 100,
      timeout: 30000,
      ...config,
    };

    // Initialize axios with defaults
    this.axiosInstance = axios.create({
      timeout: this.config.timeout,
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    });

    // Initialize queues and rate limiters
    this.queues = new Map();
    this.rateLimiters = new Map();
    this.initializeRateLimiting();

    // Initialize metrics
    this.metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      totalTokens: 0,
      totalCost: 0,
      averageLatency: 0,
      circuitBreakerState: 'closed',
    };

    // Initialize circuit breaker
    this.circuitBreaker = {
      failures: 0,
      lastFailure: null,
      state: 'closed',
      threshold: 5,
      timeout: 60000, // 1 minute
    };

    // Set up response interceptors
    this.setupInterceptors();
  }

  private initializeRateLimiting(): void {
    // Create queues for each service type
    for (const [service, rpm] of Object.entries(this.config.rateLimits)) {
      // Queue with concurrency based on rate limit
      const concurrency = Math.max(1, Math.floor(rpm / 60));
      this.queues.set(service, new PQueue({
        concurrency,
        interval: 1000,
        intervalCap: Math.ceil(rpm / 60),
      }));

      // Rate limiter as backup
      this.rateLimiters.set(service, new RateLimiterMemory({
        points: rpm,
        duration: 60, // Per minute
      }));
    }
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.axiosInstance.interceptors.request.use(
      (config) => {
        config.metadata = { startTime: Date.now() };
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.axiosInstance.interceptors.response.use(
      (response) => {
        const latency = Date.now() - response.config.metadata.startTime;
        this.updateMetrics(true, latency, response.data.usage?.total_tokens || 0);
        return response;
      },
      async (error: AxiosError) => {
        const latency = Date.now() - error.config?.metadata?.startTime || 0;
        this.updateMetrics(false, latency, 0);
        
        // Handle rate limiting
        if (error.response?.status === 429) {
          const retryAfter = parseInt(error.response.headers['retry-after'] || '60', 10);
          logger.warn(`Rate limited, retrying after ${retryAfter}s`);
          await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
          return this.axiosInstance.request(error.config!);
        }

        throw error;
      }
    );
  }

  private updateMetrics(success: boolean, latency: number, tokens: number): void {
    this.metrics.totalRequests++;
    if (success) {
      this.metrics.successfulRequests++;
      this.circuitBreaker.failures = 0;
    } else {
      this.metrics.failedRequests++;
      this.handleCircuitBreakerFailure();
    }
    
    this.metrics.totalTokens += tokens;
    this.metrics.averageLatency = 
      (this.metrics.averageLatency * (this.metrics.totalRequests - 1) + latency) / 
      this.metrics.totalRequests;

    // Estimate cost (example rates)
    const costPerToken = 0.000001; // Adjust based on actual pricing
    this.metrics.totalCost += tokens * costPerToken;

    // Emit metrics event
    this.emit('metrics', this.metrics);
  }

  private handleCircuitBreakerFailure(): void {
    this.circuitBreaker.failures++;
    this.circuitBreaker.lastFailure = new Date();

    if (this.circuitBreaker.failures >= this.circuitBreaker.threshold) {
      this.circuitBreaker.state = 'open';
      this.metrics.circuitBreakerState = 'open';
      logger.error('Circuit breaker opened due to excessive failures');

      // Schedule circuit breaker reset
      setTimeout(() => {
        this.circuitBreaker.state = 'half-open';
        this.metrics.circuitBreakerState = 'half-open';
        logger.info('Circuit breaker moved to half-open state');
      }, this.circuitBreaker.timeout);
    }
  }

  private async checkCircuitBreaker(): Promise<void> {
    if (this.circuitBreaker.state === 'open') {
      throw new Error('Circuit breaker is open - service temporarily unavailable');
    }
  }

  /**
   * Generate embeddings with smart batching
   */
  async generateEmbeddings(
    texts: string[],
    options?: { model?: string; batchSize?: number }
  ): Promise<BatchResult<number[][]>> {
    await this.checkCircuitBreaker();

    const startTime = Date.now();
    const batchSize = options?.batchSize || this.config.batchSize || 100;
    const model = options?.model || this.config.models.embedding;
    
    const results: number[][] = [];
    const errors: string[] = [];
    let totalRetries = 0;

    // Process in batches
    for (let i = 0; i < texts.length; i += batchSize) {
      const batch = texts.slice(i, i + batchSize);
      
      try {
        const batchResult = await this.queues.get('embedding')!.add(async () => {
          return await this.retryWithBackoff(async () => {
            // Check rate limiter
            await this.rateLimiters.get('embedding')!.consume(1);
            
            const response = await this.axiosInstance.post<JinaEmbeddingResponse>(
              this.config.endpoints.embedding,
              {
                model,
                input: batch.map(text => ({ text })),
              }
            );

            return response.data;
          });
        });

        if (batchResult) {
          const embeddings = batchResult.data.map(d => d.embedding);
          results.push(...embeddings);
        }

        // Progress update
        this.emit('progress', {
          processed: Math.min(i + batchSize, texts.length),
          total: texts.length,
          percentage: Math.min(100, ((i + batchSize) / texts.length) * 100),
        });

      } catch (error) {
        logger.error(`Batch ${i / batchSize + 1} failed:`, error);
        errors.push(`Batch ${i / batchSize + 1}: ${error.message}`);
        // Add empty embeddings for failed batch
        results.push(...new Array(batch.length).fill([]));
      }
    }

    const processingTime = Date.now() - startTime;

    return {
      success: errors.length === 0,
      data: results,
      error: errors.length > 0 ? errors.join('; ') : undefined,
      retries: totalRetries,
      processingTime,
    };
  }

  /**
   * Rerank documents
   */
  async rerankDocuments(
    query: string,
    documents: string[],
    options?: { model?: string; topN?: number }
  ): Promise<BatchResult<JinaRerankResponse>> {
    await this.checkCircuitBreaker();

    const startTime = Date.now();
    const model = options?.model || this.config.models.reranking;
    
    try {
      const result = await this.queues.get('reranking')!.add(async () => {
        return await this.retryWithBackoff(async () => {
          await this.rateLimiters.get('reranking')!.consume(1);
          
          const response = await this.axiosInstance.post<JinaRerankResponse>(
            this.config.endpoints.reranking,
            {
              query,
              documents,
              model,
              top_n: options?.topN,
            }
          );

          return response.data;
        });
      });

      return {
        success: true,
        data: result,
        retries: 0,
        processingTime: Date.now() - startTime,
      };

    } catch (error) {
      return {
        success: false,
        error: error.message,
        retries: this.config.maxRetries || 3,
        processingTime: Date.now() - startTime,
      };
    }
  }

  /**
   * Retry with exponential backoff
   */
  private async retryWithBackoff<T>(
    fn: () => Promise<T>,
    retries: number = 0
  ): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      if (retries >= (this.config.maxRetries || 3)) {
        throw error;
      }

      const delay = (this.config.retryDelay || 1000) * Math.pow(2, retries);
      logger.warn(`Retrying after ${delay}ms (attempt ${retries + 1})`);
      
      await new Promise(resolve => setTimeout(resolve, delay));
      return this.retryWithBackoff(fn, retries + 1);
    }
  }

  /**
   * Process embeddings in parallel with optimal batching
   */
  async processEmbeddingsOptimized(
    texts: string[],
    options?: {
      maxConcurrent?: number;
      onProgress?: (progress: number) => void;
    }
  ): Promise<Array<{ text: string; embedding: number[]; error?: string }>> {
    const maxConcurrent = options?.maxConcurrent || 5;
    const optimalBatchSize = this.calculateOptimalBatchSize(texts);
    
    const results: Array<{ text: string; embedding: number[]; error?: string }> = [];
    const queue = new PQueue({ concurrency: maxConcurrent });
    
    // Create batches
    const batches: string[][] = [];
    for (let i = 0; i < texts.length; i += optimalBatchSize) {
      batches.push(texts.slice(i, i + optimalBatchSize));
    }

    // Process batches in parallel
    const batchPromises = batches.map((batch, batchIndex) =>
      queue.add(async () => {
        try {
          const embeddings = await this.generateEmbeddings(batch, {
            batchSize: batch.length,
          });

          if (embeddings.success && embeddings.data) {
            batch.forEach((text, idx) => {
              results[batchIndex * optimalBatchSize + idx] = {
                text,
                embedding: embeddings.data![idx] || [],
              };
            });
          } else {
            // Handle partial failures
            batch.forEach((text, idx) => {
              results[batchIndex * optimalBatchSize + idx] = {
                text,
                embedding: [],
                error: embeddings.error,
              };
            });
          }

          // Progress callback
          if (options?.onProgress) {
            const progress = ((batchIndex + 1) / batches.length) * 100;
            options.onProgress(progress);
          }
        } catch (error) {
          logger.error(`Batch ${batchIndex} failed completely:`, error);
          batch.forEach((text, idx) => {
            results[batchIndex * optimalBatchSize + idx] = {
              text,
              embedding: [],
              error: error.message,
            };
          });
        }
      })
    );

    await Promise.all(batchPromises);
    return results;
  }

  /**
   * Calculate optimal batch size based on text lengths
   */
  private calculateOptimalBatchSize(texts: string[]): number {
    const avgLength = texts.reduce((sum, text) => sum + text.length, 0) / texts.length;
    
    // Adjust batch size based on average text length
    if (avgLength < 500) return 100;
    if (avgLength < 1000) return 50;
    if (avgLength < 2000) return 25;
    return 10;
  }

  /**
   * Get current service metrics
   */
  getMetrics(): ServiceMetrics {
    return { ...this.metrics };
  }

  /**
   * Reset circuit breaker
   */
  resetCircuitBreaker(): void {
    this.circuitBreaker.failures = 0;
    this.circuitBreaker.state = 'closed';
    this.circuitBreaker.lastFailure = null;
    this.metrics.circuitBreakerState = 'closed';
    logger.info('Circuit breaker reset');
  }

  /**
   * Get queue statistics
   */
  getQueueStats(): Record<string, { size: number; pending: number }> {
    const stats: Record<string, { size: number; pending: number }> = {};
    
    for (const [service, queue] of this.queues.entries()) {
      stats[service] = {
        size: queue.size,
        pending: queue.pending,
      };
    }
    
    return stats;
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    logger.info('Shutting down Jina service...');
    
    // Clear all queues
    for (const queue of this.queues.values()) {
      queue.clear();
    }
    
    // Wait for pending operations
    await Promise.all(
      Array.from(this.queues.values()).map(queue => queue.onIdle())
    );
    
    logger.info('Jina service shutdown complete');
  }
}