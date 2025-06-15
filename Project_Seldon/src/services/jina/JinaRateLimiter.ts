/**
 * JinaRateLimiter - Comprehensive Rate Limiting for Jina AI Services
 * Project Seldon - Advanced Intelligence Architecture
 * Generated: June 13, 2025
 */

import PQueue from 'p-queue';
import {
  JinaServiceType,
  JinaOperation,
  QueueMetrics,
  ServiceMetrics,
  RATE_LIMIT_CONFIGS,
  JinaRateLimitError
} from '../../types/jina.js';

export class JinaRateLimiter {
  private queues: Map<JinaServiceType, PQueue> = new Map();
  private metrics: ServiceMetrics;
  private logger: Console;

  constructor(logger: Console = console) {
    this.logger = logger;
    this.initializeQueues();
    this.initializeMetrics();
    this.setupEventListeners();
  }

  /**
   * Initialize rate-limited queues for each Jina service
   */
  private initializeQueues(): void {
    for (const [serviceType, config] of Object.entries(RATE_LIMIT_CONFIGS)) {
      const queue = new PQueue({
        concurrency: config.concurrency,
        intervalCap: config.intervalCap,
        interval: config.interval,
        timeout: 30000, // 30 second timeout per operation
        throwOnTimeout: true
      });

      this.queues.set(serviceType as JinaServiceType, queue);
      
      this.logger.log(`Initialized ${serviceType} queue: ${config.intervalCap} requests per ${config.interval}ms, concurrency: ${config.concurrency}`);
    }
  }

  /**
   * Initialize metrics tracking for all services
   */
  private initializeMetrics(): void {
    const defaultMetrics: QueueMetrics = {
      pending: 0,
      running: 0,
      completed: 0,
      failed: 0,
      totalProcessed: 0,
      averageProcessingTime: 0,
      rateLimitHits: 0
    };

    this.metrics = {
      embedding: { ...defaultMetrics },
      reranking: { ...defaultMetrics },
      classifier: { ...defaultMetrics },
      deepSearch: { ...defaultMetrics }
    };
  }

  /**
   * Setup event listeners for queue monitoring
   */
  private setupEventListeners(): void {
    for (const [serviceType, queue] of this.queues) {
      const metrics = this.metrics[serviceType as JinaServiceType];

      queue.on('add', () => {
        metrics.pending = queue.pending;
      });

      queue.on('active', () => {
        metrics.running = queue.pending;
        metrics.pending = queue.pending;
      });

      queue.on('completed', (result) => {
        metrics.completed++;
        metrics.totalProcessed++;
        this.updateAverageProcessingTime(serviceType as JinaServiceType, result?.processingTime || 0);
      });

      queue.on('error', (error) => {
        metrics.failed++;
        
        if (error.message.includes('rate limit') || error.message.includes('429')) {
          metrics.rateLimitHits++;
          this.logger.warn(`Rate limit hit for ${serviceType}: ${error.message}`);
        } else {
          this.logger.error(`Queue error for ${serviceType}:`, error);
        }
      });

      queue.on('idle', () => {
        this.logger.log(`${serviceType} queue is idle`);
      });
    }
  }

  /**
   * Process operation with rate limiting
   */
  async processWithLimit<T>(
    serviceType: JinaServiceType,
    operation: () => Promise<T>,
    options: {
      priority?: number;
      retryCount?: number;
      metadata?: Record<string, any>;
    } = {}
  ): Promise<T> {
    const queue = this.queues.get(serviceType);
    if (!queue) {
      throw new Error(`Unknown service type: ${serviceType}`);
    }

    const startTime = Date.now();
    const { priority = 0, retryCount = 3, metadata = {} } = options;

    const wrappedOperation = async (): Promise<T> => {
      let lastError: Error | null = null;
      
      for (let attempt = 1; attempt <= retryCount; attempt++) {
        try {
          this.logger.log(`${serviceType} operation attempt ${attempt}/${retryCount}`, metadata);
          
          const result = await operation();
          
          const processingTime = Date.now() - startTime;
          this.logger.log(`${serviceType} operation completed in ${processingTime}ms`);
          
          return result;
        } catch (error) {
          lastError = error as Error;
          
          // Handle rate limiting errors
          if (this.isRateLimitError(error)) {
            const waitTime = this.calculateBackoffTime(attempt);
            this.logger.warn(`Rate limit hit on ${serviceType}, waiting ${waitTime}ms before retry ${attempt}/${retryCount}`);
            
            if (attempt < retryCount) {
              await this.sleep(waitTime);
              continue;
            }
          }
          
          // Handle other retryable errors
          if (this.isRetryableError(error) && attempt < retryCount) {
            const waitTime = this.calculateExponentialBackoff(attempt);
            this.logger.warn(`Retryable error on ${serviceType}, waiting ${waitTime}ms before retry ${attempt}/${retryCount}:`, error.message);
            await this.sleep(waitTime);
            continue;
          }
          
          // Non-retryable error or max retries reached
          this.logger.error(`${serviceType} operation failed after ${attempt} attempts:`, error);
          throw error;
        }
      }
      
      throw lastError || new Error(`Operation failed after ${retryCount} attempts`);
    };

    return queue.add(wrappedOperation, { priority });
  }

  /**
   * Process multiple operations in batch with optimal distribution
   */
  async processBatch<T>(
    operations: Array<{
      serviceType: JinaServiceType;
      operation: () => Promise<T>;
      priority?: number;
      metadata?: Record<string, any>;
    }>
  ): Promise<Array<{ success: boolean; result?: T; error?: Error }>> {
    this.logger.log(`Processing batch of ${operations.length} operations`);
    
    const promises = operations.map(async (op, index) => {
      try {
        const result = await this.processWithLimit(
          op.serviceType,
          op.operation,
          {
            priority: op.priority,
            metadata: { ...op.metadata, batchIndex: index }
          }
        );
        return { success: true, result };
      } catch (error) {
        return { success: false, error: error as Error };
      }
    });

    return Promise.all(promises);
  }

  /**
   * Get current metrics for all services
   */
  getMetrics(): ServiceMetrics {
    // Update current queue states
    for (const [serviceType, queue] of this.queues) {
      const metrics = this.metrics[serviceType as JinaServiceType];
      metrics.pending = queue.pending;
      metrics.running = queue.size - queue.pending;
    }

    return { ...this.metrics };
  }

  /**
   * Get metrics for a specific service
   */
  getServiceMetrics(serviceType: JinaServiceType): QueueMetrics {
    return { ...this.metrics[serviceType] };
  }

  /**
   * Clear all queues and reset metrics
   */
  async clearAll(): Promise<void> {
    this.logger.log('Clearing all queues...');
    
    const clearPromises = Array.from(this.queues.values()).map(queue => queue.clear());
    await Promise.all(clearPromises);
    
    this.initializeMetrics();
    this.logger.log('All queues cleared and metrics reset');
  }

  /**
   * Pause a specific service queue
   */
  pauseService(serviceType: JinaServiceType): void {
    const queue = this.queues.get(serviceType);
    if (queue) {
      queue.pause();
      this.logger.log(`${serviceType} service paused`);
    }
  }

  /**
   * Resume a specific service queue
   */
  resumeService(serviceType: JinaServiceType): void {
    const queue = this.queues.get(serviceType);
    if (queue) {
      queue.start();
      this.logger.log(`${serviceType} service resumed`);
    }
  }

  /**
   * Check if error is rate limit related
   */
  private isRateLimitError(error: any): boolean {
    const message = error?.message?.toLowerCase() || '';
    const status = error?.response?.status || error?.status;
    
    return (
      status === 429 ||
      message.includes('rate limit') ||
      message.includes('too many requests') ||
      message.includes('quota exceeded')
    );
  }

  /**
   * Check if error is retryable
   */
  private isRetryableError(error: any): boolean {
    const status = error?.response?.status || error?.status;
    const message = error?.message?.toLowerCase() || '';
    
    // Network errors, timeouts, and 5xx errors are retryable
    return (
      status >= 500 ||
      message.includes('timeout') ||
      message.includes('network') ||
      message.includes('connection') ||
      message.includes('econnreset') ||
      message.includes('enotfound')
    );
  }

  /**
   * Calculate backoff time for rate limiting
   */
  private calculateBackoffTime(attempt: number): number {
    // Start with 1 minute, add jitter
    const baseWait = 60000; // 1 minute
    const jitter = Math.random() * 10000; // 0-10 seconds
    return baseWait + jitter;
  }

  /**
   * Calculate exponential backoff for retries
   */
  private calculateExponentialBackoff(attempt: number): number {
    const baseDelay = 1000; // 1 second
    const maxDelay = 30000; // 30 seconds
    const exponentialDelay = Math.min(baseDelay * Math.pow(2, attempt - 1), maxDelay);
    const jitter = Math.random() * 1000; // 0-1 second jitter
    return exponentialDelay + jitter;
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Update average processing time metric
   */
  private updateAverageProcessingTime(serviceType: JinaServiceType, processingTime: number): void {
    const metrics = this.metrics[serviceType];
    const total = metrics.averageProcessingTime * (metrics.totalProcessed - 1) + processingTime;
    metrics.averageProcessingTime = total / metrics.totalProcessed;
  }

  /**
   * Get health status of all services
   */
  getHealthStatus(): Record<JinaServiceType, 'healthy' | 'degraded' | 'unhealthy'> {
    const status: Record<JinaServiceType, 'healthy' | 'degraded' | 'unhealthy'> = {
      embedding: 'healthy',
      reranking: 'healthy',
      classifier: 'healthy',
      deepSearch: 'healthy'
    };

    for (const serviceType of Object.keys(this.metrics) as JinaServiceType[]) {
      const metrics = this.metrics[serviceType];
      const queue = this.queues.get(serviceType);
      
      if (!queue) {
        status[serviceType] = 'unhealthy';
        continue;
      }

      const failureRate = metrics.totalProcessed > 0 ? metrics.failed / metrics.totalProcessed : 0;
      const recentRateLimits = metrics.rateLimitHits;
      
      if (failureRate > 0.1 || recentRateLimits > 10) {
        status[serviceType] = 'unhealthy';
      } else if (failureRate > 0.05 || recentRateLimits > 5 || queue.pending > 100) {
        status[serviceType] = 'degraded';
      }
    }

    return status;
  }

  /**
   * Cleanup resources
   */
  async destroy(): Promise<void> {
    this.logger.log('Destroying JinaRateLimiter...');
    
    await this.clearAll();
    
    for (const queue of this.queues.values()) {
      queue.removeAllListeners();
    }
    
    this.queues.clear();
    this.logger.log('JinaRateLimiter destroyed');
  }
}