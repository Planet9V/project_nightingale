import { S3Service } from '../storage/S3Service';
import { DocumentProcessor } from '../processing/DocumentProcessor';
import { VectorService } from '../vector/VectorService';
import { GraphService } from '../graph/GraphService';
import { MetadataService } from '../metadata/MetadataService';
import { ValidationService } from '../validation/ValidationService';
import { Logger } from '../../utils/logger';
import { Document, ProcessingStatus, PipelineStatus, ProcessingResult } from '../../types';
import * as path from 'path';

export interface PipelineConfig {
  batchSize: number;
  maxRetries: number;
  retryDelay: number;
  processTimeout: number;
  enableParallelProcessing: boolean;
  maxConcurrentBatches: number;
  quarantineThreshold: number;
}

export interface PipelineStatistics {
  totalDocuments: number;
  processedDocuments: number;
  failedDocuments: number;
  quarantinedDocuments: number;
  averageProcessingTime: number;
  startTime: Date;
  endTime?: Date;
  status: PipelineStatus;
  currentBatch: number;
  totalBatches: number;
}

export interface BatchResult {
  batchId: string;
  successful: string[];
  failed: string[];
  quarantined: string[];
  processingTime: number;
}

export class ETLPipelineOrchestrator {
  private logger: Logger;
  private statistics: PipelineStatistics;
  private isRunning: boolean = false;
  private currentPipelineId: string;
  private abortController: AbortController;

  constructor(
    private s3Service: S3Service,
    private documentProcessor: DocumentProcessor,
    private vectorService: VectorService,
    private graphService: GraphService,
    private metadataService: MetadataService,
    private validationService: ValidationService,
    private config: PipelineConfig = {
      batchSize: 10,
      maxRetries: 3,
      retryDelay: 5000,
      processTimeout: 300000, // 5 minutes
      enableParallelProcessing: true,
      maxConcurrentBatches: 3,
      quarantineThreshold: 5
    }
  ) {
    this.logger = new Logger('ETLPipelineOrchestrator');
    this.resetStatistics();
  }

  /**
   * Start the ETL pipeline
   */
  async startPipeline(sourcePrefix: string = 'incoming/'): Promise<PipelineStatistics> {
    if (this.isRunning) {
      throw new Error('Pipeline is already running');
    }

    this.isRunning = true;
    this.currentPipelineId = `pipeline-${Date.now()}`;
    this.abortController = new AbortController();
    this.resetStatistics();

    this.logger.info(`Starting ETL pipeline ${this.currentPipelineId}`, { sourcePrefix });

    try {
      // List all documents to process
      const documents = await this.s3Service.listDocuments(sourcePrefix);
      this.statistics.totalDocuments = documents.length;
      this.statistics.totalBatches = Math.ceil(documents.length / this.config.batchSize);

      if (documents.length === 0) {
        this.logger.info('No documents to process');
        return this.statistics;
      }

      // Process documents in batches
      const batches = this.createBatches(documents, this.config.batchSize);
      
      if (this.config.enableParallelProcessing) {
        await this.processParallelBatches(batches);
      } else {
        await this.processSequentialBatches(batches);
      }

      this.statistics.endTime = new Date();
      this.statistics.status = 'completed';

      // Generate pipeline report
      await this.generatePipelineReport();

      return this.statistics;

    } catch (error) {
      this.logger.error('Pipeline failed', error);
      this.statistics.status = 'failed';
      throw error;
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Stop the running pipeline
   */
  async stopPipeline(): Promise<void> {
    if (!this.isRunning) {
      throw new Error('No pipeline is running');
    }

    this.logger.info('Stopping pipeline...');
    this.abortController.abort();
    this.statistics.status = 'aborted';
    this.statistics.endTime = new Date();
    this.isRunning = false;
  }

  /**
   * Process a single document through the ETL pipeline
   */
  private async processDocument(documentKey: string, retryCount: number = 0): Promise<ProcessingResult> {
    const startTime = Date.now();
    const documentId = path.basename(documentKey, path.extname(documentKey));

    try {
      // Check if aborted
      if (this.abortController.signal.aborted) {
        throw new Error('Pipeline aborted');
      }

      this.logger.info(`Processing document: ${documentKey}`);

      // Step 1: Extract - Download and parse document
      const rawContent = await this.s3Service.downloadDocument(documentKey);
      const extractedDoc = await this.documentProcessor.extract(rawContent, documentKey);

      // Step 2: Validate
      const validationResult = await this.validationService.validateDocument(extractedDoc);
      if (!validationResult.isValid) {
        throw new Error(`Validation failed: ${validationResult.errors.join(', ')}`);
      }

      // Step 3: Transform - Clean and enhance
      const transformedDoc = await this.documentProcessor.transform(extractedDoc);

      // Step 4: Generate embeddings
      const embeddings = await this.vectorService.generateEmbeddings(transformedDoc.content);
      transformedDoc.embeddings = embeddings;

      // Step 5: Store in vector database
      await this.vectorService.storeDocument(transformedDoc);

      // Step 6: Update graph relationships
      await this.graphService.addDocument(transformedDoc);
      await this.graphService.updateRelationships(transformedDoc);

      // Step 7: Update metadata
      await this.metadataService.updateMetadata({
        documentId: transformedDoc.id,
        processedAt: new Date(),
        pipelineId: this.currentPipelineId,
        processingTime: Date.now() - startTime,
        status: 'processed'
      });

      // Step 8: Move to processed folder
      const processedKey = documentKey.replace('incoming/', 'processed/');
      await this.s3Service.moveDocument(documentKey, processedKey);

      this.statistics.processedDocuments++;
      this.updateAverageProcessingTime(Date.now() - startTime);

      return {
        documentId,
        status: 'success',
        processingTime: Date.now() - startTime
      };

    } catch (error) {
      this.logger.error(`Failed to process document ${documentKey}`, error);

      // Retry logic
      if (retryCount < this.config.maxRetries) {
        this.logger.info(`Retrying document ${documentKey} (attempt ${retryCount + 1}/${this.config.maxRetries})`);
        await this.delay(this.config.retryDelay);
        return this.processDocument(documentKey, retryCount + 1);
      }

      // Move to failed or quarantine folder
      const failureCount = await this.getDocumentFailureCount(documentId);
      const targetFolder = failureCount >= this.config.quarantineThreshold ? 'quarantine/' : 'failed/';
      const targetKey = documentKey.replace('incoming/', targetFolder);
      
      await this.s3Service.moveDocument(documentKey, targetKey);
      
      if (targetFolder === 'quarantine/') {
        this.statistics.quarantinedDocuments++;
      } else {
        this.statistics.failedDocuments++;
      }

      // Store failure metadata
      await this.metadataService.updateMetadata({
        documentId,
        failedAt: new Date(),
        pipelineId: this.currentPipelineId,
        error: error.message,
        retryCount,
        status: 'failed',
        quarantined: targetFolder === 'quarantine/'
      });

      return {
        documentId,
        status: 'failed',
        error: error.message,
        processingTime: Date.now() - startTime
      };
    }
  }

  /**
   * Process batches sequentially
   */
  private async processSequentialBatches(batches: string[][]): Promise<void> {
    for (let i = 0; i < batches.length; i++) {
      this.statistics.currentBatch = i + 1;
      await this.processBatch(batches[i], `batch-${i + 1}`);
    }
  }

  /**
   * Process batches in parallel
   */
  private async processParallelBatches(batches: string[][]): Promise<void> {
    const concurrentBatches = this.config.maxConcurrentBatches;
    
    for (let i = 0; i < batches.length; i += concurrentBatches) {
      const batchPromises = [];
      
      for (let j = 0; j < concurrentBatches && i + j < batches.length; j++) {
        const batchIndex = i + j;
        this.statistics.currentBatch = batchIndex + 1;
        batchPromises.push(this.processBatch(batches[batchIndex], `batch-${batchIndex + 1}`));
      }
      
      await Promise.all(batchPromises);
    }
  }

  /**
   * Process a single batch of documents
   */
  private async processBatch(documents: string[], batchId: string): Promise<BatchResult> {
    const startTime = Date.now();
    const results: BatchResult = {
      batchId,
      successful: [],
      failed: [],
      quarantined: [],
      processingTime: 0
    };

    this.logger.info(`Processing batch ${batchId} with ${documents.length} documents`);

    // Process documents with timeout
    const promises = documents.map(doc => 
      this.processWithTimeout(doc, this.config.processTimeout)
    );

    const batchResults = await Promise.allSettled(promises);

    // Categorize results
    batchResults.forEach((result, index) => {
      const documentKey = documents[index];
      
      if (result.status === 'fulfilled' && result.value.status === 'success') {
        results.successful.push(documentKey);
      } else {
        results.failed.push(documentKey);
      }
    });

    results.processingTime = Date.now() - startTime;

    this.logger.info(`Batch ${batchId} completed`, {
      successful: results.successful.length,
      failed: results.failed.length,
      processingTime: results.processingTime
    });

    return results;
  }

  /**
   * Process document with timeout
   */
  private async processWithTimeout(documentKey: string, timeout: number): Promise<ProcessingResult> {
    return Promise.race([
      this.processDocument(documentKey),
      new Promise<ProcessingResult>((_, reject) => 
        setTimeout(() => reject(new Error('Processing timeout')), timeout)
      )
    ]);
  }

  /**
   * Create batches from document list
   */
  private createBatches(documents: string[], batchSize: number): string[][] {
    const batches: string[][] = [];
    
    for (let i = 0; i < documents.length; i += batchSize) {
      batches.push(documents.slice(i, i + batchSize));
    }
    
    return batches;
  }

  /**
   * Get pipeline status
   */
  getStatus(): PipelineStatistics {
    return { ...this.statistics };
  }

  /**
   * Get document failure count
   */
  private async getDocumentFailureCount(documentId: string): Promise<number> {
    const metadata = await this.metadataService.getMetadata(documentId);
    return metadata?.failureCount || 0;
  }

  /**
   * Update average processing time
   */
  private updateAverageProcessingTime(processingTime: number): void {
    const total = this.statistics.processedDocuments + this.statistics.failedDocuments;
    const currentAverage = this.statistics.averageProcessingTime;
    
    this.statistics.averageProcessingTime = 
      (currentAverage * (total - 1) + processingTime) / total;
  }

  /**
   * Generate pipeline report
   */
  private async generatePipelineReport(): Promise<void> {
    const report = {
      pipelineId: this.currentPipelineId,
      statistics: this.statistics,
      timestamp: new Date(),
      config: this.config
    };

    const reportKey = `reports/pipeline-${this.currentPipelineId}.json`;
    await this.s3Service.uploadDocument(reportKey, Buffer.from(JSON.stringify(report, null, 2)));

    this.logger.info('Pipeline report generated', { reportKey });
  }

  /**
   * Reset statistics
   */
  private resetStatistics(): void {
    this.statistics = {
      totalDocuments: 0,
      processedDocuments: 0,
      failedDocuments: 0,
      quarantinedDocuments: 0,
      averageProcessingTime: 0,
      startTime: new Date(),
      status: 'initializing',
      currentBatch: 0,
      totalBatches: 0
    };
  }

  /**
   * Delay helper
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<{
    status: string;
    isRunning: boolean;
    currentPipeline?: string;
    statistics?: PipelineStatistics;
    services: Record<string, boolean>;
  }> {
    const services = {
      s3: await this.s3Service.healthCheck(),
      documentProcessor: await this.documentProcessor.healthCheck(),
      vectorService: await this.vectorService.healthCheck(),
      graphService: await this.graphService.healthCheck(),
      metadataService: await this.metadataService.healthCheck(),
      validationService: await this.validationService.healthCheck()
    };

    return {
      status: 'healthy',
      isRunning: this.isRunning,
      currentPipeline: this.currentPipelineId,
      statistics: this.isRunning ? this.statistics : undefined,
      services
    };
  }
}