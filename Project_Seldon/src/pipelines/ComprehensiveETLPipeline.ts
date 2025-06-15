import { EventEmitter } from 'events';
import path from 'path';
import fs from 'fs/promises';
import { createHash } from 'crypto';
import { logger } from '../utils/logger';
import { ConfigurationManager, Configuration } from '../config/ConfigurationManager';
import { DatabaseHealthChecker } from '../services/DatabaseHealthChecker';
import { ProgressTracker } from '../monitoring/ProgressTracker';
import { S3DocumentManager } from '../services/S3DocumentManager';
import { EnhancedJinaService } from '../services/EnhancedJinaService';
import { SupabaseManager } from '../database/SupabaseManager';
import { PineconeManager } from '../database/PineconeManager';
import { Neo4jManager } from '../database/Neo4jManager';
import { DocumentProcessor } from '../processors/DocumentProcessor';
import { v4 as uuidv4 } from 'uuid';

export interface ETLOptions {
  inputPath: string;
  batchSize?: number;
  maxFiles?: number;
  dryRun?: boolean;
  resume?: boolean;
  skipHealthCheck?: boolean;
  filePattern?: string;
}

export interface ETLResult {
  success: boolean;
  processedFiles: number;
  failedFiles: number;
  totalChunks: number;
  totalEmbeddings: number;
  totalCitations: number;
  duration: number;
  errors: Array<{ file: string; error: string }>;
}

export class ComprehensiveETLPipeline extends EventEmitter {
  private config: any;
  private healthChecker!: DatabaseHealthChecker;
  private progressTracker!: ProgressTracker;
  private s3Manager!: S3DocumentManager;
  private jinaService!: EnhancedJinaService;
  private supabaseManager!: SupabaseManager;
  private pineconeManager!: PineconeManager;
  private neo4jManager!: Neo4jManager;
  private documentProcessor!: DocumentProcessor;
  private batchId: string;
  private isInitialized: boolean = false;

  constructor() {
    super();
    this.batchId = uuidv4();
  }

  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    logger.info('Initializing Comprehensive ETL Pipeline', { batchId: this.batchId });

    try {
      // Load configuration
      this.config = await ConfigurationManager.getInstance().load();

      // Initialize services
      this.initializeServices();

      // Mark as initialized
      this.isInitialized = true;

      logger.info('ETL Pipeline initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize ETL Pipeline', error);
      throw error;
    }
  }

  private initializeServices(): void {
    // Health checker
    this.healthChecker = new DatabaseHealthChecker({
      supabaseUrl: this.config.databases.supabase.url,
      supabaseKey: this.config.databases.supabase.anonKey,
      pineconeApiKey: this.config.databases.pinecone.apiKey,
      neo4jUri: this.config.databases.neo4j.uri,
      neo4jUser: this.config.databases.neo4j.username,
      neo4jPassword: this.config.databases.neo4j.password,
      awsRegion: this.config.storage?.s3?.region,
      jinaApiKey: this.config.jina.apiKey,
    });

    // Progress tracker
    this.progressTracker = new ProgressTracker(
      this.config.databases.supabase.url,
      this.config.databases.supabase.anonKey,
      this.batchId
    );

    // S3 manager (if configured)
    if (this.config.storage?.s3) {
      this.s3Manager = new S3DocumentManager({
        bucket: this.config.storage.s3.bucketName,
        region: this.config.storage.s3.region,
        folders: this.config.storage.s3.folders,
      });
    }

    // Jina service
    this.jinaService = new EnhancedJinaService({
      apiKey: this.config.jina.apiKey,
      endpoints: {
        embedding: this.config.jina.endpoints?.embedding || 'https://api.jina.ai/v1/embeddings',
        reranking: this.config.jina.endpoints?.reranking || 'https://api.jina.ai/v1/rerank',
        classifier: this.config.jina.endpoints?.classifier || 'https://api.jina.ai/v1/classify',
        deepSearch: this.config.jina.endpoints?.deepSearch || 'https://api.jina.ai/v1/search',
      },
      models: {
        embedding: this.config.jina.models?.embedding || 'jina-embeddings-v2-base-en',
        reranking: this.config.jina.models?.reranking || 'jina-reranker-v1-base-en',
        classifier: this.config.jina.models?.classifier || 'jina-classifier-v1-base-en',
        deepSearch: this.config.jina.models?.deepSearch || 'jina-search-v1-base-en',
      },
      rateLimits: this.config.jina.rateLimits || {
        embedding: 2000,
        reranking: 2000,
        classifier: 60,
        deepSearch: 500,
      },
      batchSize: this.config.etl.batchSize,
      maxRetries: this.config.etl.maxRetries,
      retryDelay: this.config.etl.retryDelay,
    });

    // Database managers
    this.supabaseManager = new SupabaseManager(
      this.config.databases.supabase.url,
      this.config.databases.supabase.serviceKey
    );

    this.pineconeManager = new PineconeManager({
      apiKey: this.config.databases.pinecone.apiKey,
      indexName: this.config.databases.pinecone.indexName,
      namespace: 'annual-reports', // Can be configurable
    });

    this.neo4jManager = new Neo4jManager({
      uri: this.config.databases.neo4j.uri,
      username: this.config.databases.neo4j.username,
      password: this.config.databases.neo4j.password,
      database: this.config.databases.neo4j.database,
    });

    // Document processor
    this.documentProcessor = new DocumentProcessor(this.config);

    // Set up event listeners
    this.setupEventListeners();
  }

  private setupEventListeners(): void {
    // Jina service events
    this.jinaService.on('metrics', (metrics) => {
      logger.debug('Jina metrics update', metrics);
    });

    this.jinaService.on('progress', (progress) => {
      this.emit('embedding-progress', progress);
    });

    // Progress tracker events
    this.progressTracker.on('milestone', (milestone) => {
      this.emit('milestone', milestone);
    });
  }

  async runHealthCheck(): Promise<boolean> {
    logger.info('Running health check...');
    const report = await this.healthChecker.performFullHealthCheck();
    DatabaseHealthChecker.displayReport(report);

    if (report.overall === 'unhealthy') {
      logger.error('Health check failed - system unhealthy');
      return false;
    }

    if (report.overall === 'degraded') {
      logger.warn('System degraded but operational');
    }

    return true;
  }

  async process(options: ETLOptions): Promise<ETLResult> {
    const startTime = Date.now();
    const result: ETLResult = {
      success: false,
      processedFiles: 0,
      failedFiles: 0,
      totalChunks: 0,
      totalEmbeddings: 0,
      totalCitations: 0,
      duration: 0,
      errors: [],
    };

    try {
      // Initialize if needed
      if (!this.isInitialized) {
        await this.initialize();
      }

      // Run health check unless skipped
      if (!options.skipHealthCheck) {
        const isHealthy = await this.runHealthCheck();
        if (!isHealthy && !options.dryRun) {
          throw new Error('System health check failed');
        }
      }

      // Get files to process
      const files = await this.getFilesToProcess(options);
      logger.info(`Found ${files.length} files to process`);

      if (files.length === 0) {
        result.success = true;
        return result;
      }

      // Initialize progress tracker
      await this.progressTracker.initialize(files.length);

      // Check for resume
      if (options.resume) {
        const failedFiles = await this.progressTracker.getFailedFiles();
        logger.info(`Resuming processing, skipping ${failedFiles.length} previously failed files`);
      }

      // Process files in batches
      const batchSize = options.batchSize || this.config.etl.batchSize || 5;
      for (let i = 0; i < files.length; i += batchSize) {
        const batch = files.slice(i, i + batchSize);
        await this.processBatch(batch, result, options.dryRun || false);
      }

      result.success = result.failedFiles === 0;
      result.duration = Date.now() - startTime;

      // Generate final report
      const report = await this.progressTracker.generateReport();
      logger.info('ETL Pipeline completed', { report });

      return result;

    } catch (error) {
      logger.error('ETL Pipeline failed', error);
      result.duration = Date.now() - startTime;
      throw error;
    } finally {
      await this.cleanup();
    }
  }

  private async getFilesToProcess(options: ETLOptions): Promise<string[]> {
    const stats = await fs.stat(options.inputPath);
    let files: string[] = [];

    if (stats.isDirectory()) {
      const entries = await fs.readdir(options.inputPath, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isFile()) {
          const filePath = path.join(options.inputPath, entry.name);
          if (this.shouldProcessFile(filePath, options.filePattern)) {
            files.push(filePath);
          }
        }
      }
    } else {
      files = [options.inputPath];
    }

    // Apply max files limit
    if (options.maxFiles && files.length > options.maxFiles) {
      files = files.slice(0, options.maxFiles);
    }

    return files;
  }

  private shouldProcessFile(filePath: string, pattern?: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    const supportedFormats = this.config.processing.supportedFormats || ['.md', '.txt', '.pdf'];
    
    if (!supportedFormats.includes(ext)) {
      return false;
    }

    if (pattern) {
      const regex = new RegExp(pattern);
      return regex.test(path.basename(filePath));
    }

    return true;
  }

  private async processBatch(
    files: string[],
    result: ETLResult,
    dryRun: boolean
  ): Promise<void> {
    const batchPromises = files.map(file => this.processFile(file, result, dryRun));
    await Promise.all(batchPromises);
  }

  private async processFile(
    filePath: string,
    result: ETLResult,
    dryRun: boolean
  ): Promise<void> {
    const fileId = uuidv4();
    const fileName = path.basename(filePath);

    try {
      this.progressTracker.startFile(fileId, fileName);
      logger.info(`Processing file: ${fileName}`);

      // Read and hash file
      const content = await fs.readFile(filePath, 'utf-8');
      const hash = createHash('sha256').update(content).digest('hex');

      // Check if already processed
      if (!dryRun) {
        const exists = await this.supabaseManager.documentExists(hash);
        if (exists) {
          logger.info(`File already processed: ${fileName}`);
          this.progressTracker.completeFile(fileId, true);
          result.processedFiles++;
          return;
        }
      }

      // Upload to S3 if configured
      let s3Result;
      if (this.s3Manager && !dryRun) {
        s3Result = await this.s3Manager.uploadDocument(filePath, fileId);
      }

      // Process document
      const processedDoc = await this.documentProcessor.process({
        id: fileId,
        content,
        metadata: {
          title: fileName,
          source: filePath,
          hash,
        },
      });

      // Update progress
      this.progressTracker.updateFileChunks(fileId, processedDoc.chunks.length);

      // Generate embeddings
      const embeddings = await this.generateEmbeddings(
        processedDoc.chunks.map(c => c.content),
        fileId
      );

      // Store in databases (if not dry run)
      if (!dryRun) {
        await this.storeInDatabases(
          processedDoc,
          embeddings,
          s3Result,
          fileId
        );
      }

      // Complete file processing
      this.progressTracker.completeFile(fileId, true);
      result.processedFiles++;
      result.totalChunks += processedDoc.chunks.length;
      result.totalEmbeddings += embeddings.length;
      result.totalCitations += processedDoc.citations?.length || 0;

    } catch (error) {
      logger.error(`Failed to process file: ${fileName}`, error);
      this.progressTracker.completeFile(fileId, false, error.message);
      result.failedFiles++;
      result.errors.push({
        file: fileName,
        error: error.message,
      });
    }
  }

  private async generateEmbeddings(
    texts: string[],
    fileId: string
  ): Promise<number[][]> {
    const embedResult = await this.jinaService.processEmbeddingsOptimized(
      texts,
      {
        onProgress: (progress) => {
          const processed = Math.floor((progress / 100) * texts.length);
          this.progressTracker.updateFileProgress(fileId, processed, processed);
        },
      }
    );

    return embedResult.map(r => r.embedding || []);
  }

  private async storeInDatabases(
    processedDoc: any,
    embeddings: number[][],
    s3Result: any,
    _fileId: string
  ): Promise<void> {
    // Store in Supabase
    const documentId = await this.supabaseManager.storeDocument({
      id: processedDoc.id,
      title: processedDoc.metadata.title,
      content: processedDoc.content,
      source_path: processedDoc.metadata.source,
      s3_bucket: s3Result?.bucket,
      s3_key: s3Result?.key,
      file_type: path.extname(processedDoc.metadata.source).substring(1),
      file_size: processedDoc.content.length,
      hash: processedDoc.metadata.hash,
      metadata: processedDoc.metadata,
    });

    // Store chunks with embeddings
    const chunkIds = await this.supabaseManager.storeChunks(
      processedDoc.chunks.map((chunk: any, index: number) => ({
        document_id: documentId,
        chunk_index: index,
        content: chunk.content,
        start_char: chunk.startChar,
        end_char: chunk.endChar,
        embedding: embeddings[index],
        metadata: chunk.metadata || {},
      }))
    );

    // Store in Pinecone
    await this.pineconeManager.insertVectors(
      embeddings.map((embedding, index) => ({
        id: chunkIds[index],
        values: embedding,
        metadata: {
          document_id: documentId,
          chunk_index: index,
          file_type: processedDoc.metadata.fileType,
          title: processedDoc.metadata.title,
        },
      }))
    );

    // Store in Neo4j
    await this.neo4jManager.createDocument({
      id: documentId,
      title: processedDoc.metadata.title,
      type: 'report',
      source: processedDoc.metadata.source,
      date: new Date(),
    });

    // Extract and store entities
    const entities = await this.extractEntities(processedDoc);
    for (const entity of entities) {
      await this.neo4jManager.createEntity(entity);
      await this.neo4jManager.createRelationship(
        documentId,
        entity.id,
        'MENTIONS',
        { count: entity.mentions }
      );
    }
  }

  private async extractEntities(doc: any): Promise<any[]> {
    // Simple entity extraction - can be enhanced with NER
    const entities: any[] = [];
    const content = doc.content.toLowerCase();

    // Extract vendor names (simple pattern matching)
    const vendors = [
      'microsoft', 'crowdstrike', 'cisco', 'palo alto', 'fortinet',
      'checkpoint', 'ibm', 'accenture', 'mandiant', 'fireeye'
    ];

    for (const vendor of vendors) {
      const regex = new RegExp(`\\b${vendor}\\b`, 'gi');
      const matches = content.match(regex);
      if (matches && matches.length > 0) {
        entities.push({
          id: `entity-${vendor}`,
          name: vendor,
          type: 'organization',
          mentions: matches.length,
        });
      }
    }

    return entities;
  }

  private async cleanup(): Promise<void> {
    logger.info('Cleaning up ETL Pipeline...');

    try {
      await this.progressTracker.cleanup();
      await this.jinaService.shutdown();
      await this.neo4jManager.close();
      await this.healthChecker.cleanup();
    } catch (error) {
      logger.error('Error during cleanup', error);
    }
  }
}

// Export for use
export default ComprehensiveETLPipeline;