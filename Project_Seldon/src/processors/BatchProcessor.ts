/**
 * Batch Processor for Project Seldon ETL Pipeline
 * Handles parallel processing of documents with resource management
 */

import { logger } from '../utils/logger';
import PQueue from 'p-queue';
import { 
  ETLContext
} from '../types/index';
import { Configuration } from '../config/types';
import { EventEmitter } from 'events';

export interface BatchProcessorOptions {
  concurrency?: number;
  batchSize?: number;
  maxRetries?: number;
  retryDelay?: number;
  timeout?: number;
  onProgress?: (progress: BatchProgress) => void;
  onError?: (error: BatchError) => void;
}

export interface BatchProgress {
  totalItems: number;
  processedItems: number;
  successfulItems: number;
  failedItems: number;
  percentage: number;
  estimatedTimeRemaining: number;
  itemsPerSecond: number;
}

export interface BatchError {
  itemId: string;
  error: Error;
  retryCount: number;
  timestamp: Date;
}

export interface BatchResult<T> {
  successful: T[];
  failed: Array<{ item: any; error: Error }>;
  stats: BatchStats;
}

export interface BatchStats {
  totalItems: number;
  successfulItems: number;
  failedItems: number;
  totalDuration: number;
  averageItemDuration: number;
  itemsPerSecond: number;
  retryCount: number;
}

export type ProcessorFunction<TInput, TOutput> = (
  item: TInput,
  context: ETLContext
) => Promise<TOutput>;

export class BatchProcessor<TInput, TOutput> extends EventEmitter {
  private queue: PQueue;
  private config: Configuration;
  private startTime: number = 0;
  private processedCount: number = 0;
  private successCount: number = 0;
  private failedCount: number = 0;
  private retryCount: number = 0;

  constructor(config: Configuration) {
    super();
    this.config = config;
    this.queue = new PQueue({
      concurrency: config.etl.concurrency,
      timeout: config.etl.timeout,
      throwOnTimeout: true,
    });
  }

  /**
   * Process items in batch with parallel execution
   */
  public async processBatch(
    items: TInput[],
    processor: ProcessorFunction<TInput, TOutput>,
    context: ETLContext,
    options: BatchProcessorOptions = {}
  ): Promise<BatchResult<TOutput>> {
    this.resetCounters();
    this.startTime = Date.now();

    const batchSize = options.batchSize || this.config.etl.batchSize;
    const successful: TOutput[] = [];
    const failed: Array<{ item: TInput; error: Error }> = [];

    context.logger.info(`Starting batch processing of ${items.length} items`, {
      concurrency: options.concurrency || this.config.etl.concurrency,
      batchSize,
    });

    try {
      // Split items into batches
      const batches = this.createBatches(items, batchSize);
      
      // Process each batch
      for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
        const batch = batches[batchIndex];
        
        context.logger.debug(`Processing batch ${batchIndex + 1}/${batches.length}`, {
          batchSize: batch.length,
        });

        const batchPromises = batch.map(item => 
          this.queue.add(() => this.processItem(
            item,
            processor,
            context,
            options
          ))
        );

        const batchResults = await Promise.allSettled(batchPromises);

        // Collect results
        for (let i = 0; i < batchResults.length; i++) {
          const result = batchResults[i];
          const item = batch[i];

          if (result.status === 'fulfilled') {
            successful.push(result.value);
            this.successCount++;
          } else {
            failed.push({ item, error: result.reason });
            this.failedCount++;
            
            if (options.onError) {
              options.onError({
                itemId: this.getItemId(item),
                error: result.reason,
                retryCount: 0,
                timestamp: new Date(),
              });
            }
          }

          this.processedCount++;
          this.emitProgress(items.length, options.onProgress);
        }

        // Update metrics
        context.metrics.gauge('batch.progress', this.getProgress().percentage, {
          batchIndex: batchIndex.toString(),
        });
      }

      const stats = this.calculateStats();
      
      context.logger.info('Batch processing completed', stats);

      return { successful, failed, stats };
    } catch (error) {
      context.logger.error('Batch processing failed', error as Error);
      throw error;
    }
  }

  /**
   * Process items with streaming for large datasets
   */
  public async processStream<T extends AsyncIterable<TInput>>(
    stream: T,
    processor: ProcessorFunction<TInput, TOutput>,
    context: ETLContext,
    options: BatchProcessorOptions = {}
  ): Promise<BatchResult<TOutput>> {
    this.resetCounters();
    this.startTime = Date.now();

    const successful: TOutput[] = [];
    const failed: Array<{ item: TInput; error: Error }> = [];
    const buffer: TInput[] = [];
    const batchSize = options.batchSize || this.config.etl.batchSize;

    context.logger.info('Starting stream processing', {
      batchSize,
      concurrency: options.concurrency || this.config.etl.concurrency,
    });

    try {
      for await (const item of stream) {
        buffer.push(item);

        // Process when buffer reaches batch size
        if (buffer.length >= batchSize) {
          const batch = buffer.splice(0, batchSize);
          const result = await this.processBatch(batch, processor, context, options);
          
          successful.push(...result.successful);
          failed.push(...result.failed);
        }
      }

      // Process remaining items
      if (buffer.length > 0) {
        const result = await this.processBatch(buffer, processor, context, options);
        successful.push(...result.successful);
        failed.push(...result.failed);
      }

      const stats = this.calculateStats();
      
      context.logger.info('Stream processing completed', stats);

      return { successful, failed, stats };
    } catch (error) {
      context.logger.error('Stream processing failed', error as Error);
      throw error;
    }
  }

  /**
   * Process a single item with retry logic
   */
  private async processItem<T, R>(
    item: T,
    processor: ProcessorFunction<T, R>,
    context: ETLContext,
    options: BatchProcessorOptions
  ): Promise<R> {
    const maxRetries = options.maxRetries || this.config.etl.maxRetries;
    const retryDelay = options.retryDelay || this.config.etl.retryDelay;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const result = await processor(item, context);
        
        // Update metrics
        context.metrics.increment('batch.items.processed', 1, {
          status: 'success',
          attempt: attempt.toString(),
        });

        return result;
      } catch (error) {
        lastError = error as Error;
        
        if (attempt < maxRetries) {
          this.retryCount++;
          
          context.logger.warn(`Retrying item processing (attempt ${attempt + 1}/${maxRetries})`, {
            itemId: this.getItemId(item),
            error: lastError.message,
          });

          // Exponential backoff
          await this.sleep(retryDelay * Math.pow(2, attempt));
        } else {
          context.metrics.increment('batch.items.processed', 1, {
            status: 'failed',
            attempt: attempt.toString(),
          });
        }
      }
    }

    throw lastError || new Error('Unknown error during item processing');
  }

  /**
   * Create batches from items
   */
  private createBatches<T>(items: T[], batchSize: number): T[][] {
    const batches: T[][] = [];
    
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    
    return batches;
  }

  /**
   * Get progress information
   */
  private getProgress(): BatchProgress {
    const duration = (Date.now() - this.startTime) / 1000; // seconds
    const itemsPerSecond = this.processedCount / duration || 0;
    const remainingItems = this.queue.size + this.queue.pending;
    const estimatedTimeRemaining = remainingItems / itemsPerSecond || 0;

    return {
      totalItems: this.processedCount + remainingItems,
      processedItems: this.processedCount,
      successfulItems: this.successCount,
      failedItems: this.failedCount,
      percentage: (this.processedCount / (this.processedCount + remainingItems)) * 100,
      estimatedTimeRemaining,
      itemsPerSecond,
    };
  }

  /**
   * Emit progress update
   */
  private emitProgress(_totalItems: number, onProgress?: (progress: BatchProgress) => void): void {
    const progress = this.getProgress();
    
    this.emit('progress', progress);
    
    if (onProgress) {
      onProgress(progress);
    }
  }

  /**
   * Calculate final statistics
   */
  private calculateStats(): BatchStats {
    const totalDuration = Date.now() - this.startTime;
    const averageItemDuration = totalDuration / this.processedCount || 0;
    const itemsPerSecond = (this.processedCount / totalDuration) * 1000 || 0;

    return {
      totalItems: this.processedCount,
      successfulItems: this.successCount,
      failedItems: this.failedCount,
      totalDuration,
      averageItemDuration,
      itemsPerSecond,
      retryCount: this.retryCount,
    };
  }

  /**
   * Reset counters
   */
  private resetCounters(): void {
    this.startTime = Date.now();
    this.processedCount = 0;
    this.successCount = 0;
    this.failedCount = 0;
    this.retryCount = 0;
  }

  /**
   * Get item ID for logging
   */
  private getItemId(item: any): string {
    if (typeof item === 'string') return item;
    if (item?.id) return item.id;
    if (item?.name) return item.name;
    if (item?.path) return item.path;
    return JSON.stringify(item).substring(0, 50);
  }

  /**
   * Sleep helper
   */
  private async sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Pause processing
   */
  public pause(): void {
    this.queue.pause();
    logger.info('Batch processor paused');
  }

  /**
   * Resume processing
   */
  public resume(): void {
    this.queue.start();
    logger.info('Batch processor resumed');
  }

  /**
   * Clear queue
   */
  public clear(): void {
    this.queue.clear();
    logger.info('Batch processor queue cleared');
  }

  /**
   * Get queue statistics
   */
  public getQueueStats(): {
    size: number;
    pending: number;
    isPaused: boolean;
  } {
    return {
      size: this.queue.size,
      pending: this.queue.pending,
      isPaused: this.queue.isPaused,
    };
  }

  /**
   * Wait for all items to be processed
   */
  public async waitForCompletion(): Promise<void> {
    await this.queue.onIdle();
  }

  /**
   * Cleanup resources
   */
  public async cleanup(): Promise<void> {
    this.queue.clear();
    this.queue.pause();
    await this.queue.onIdle();
    this.removeAllListeners();
    logger.info('Batch processor cleaned up');
  }
}