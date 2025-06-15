/**
 * Project Seldon ETL Pipeline - Main Entry Point
 * Production-ready ETL system for processing Project Nightingale artifacts
 */

import { logger } from './utils/logger';
import { configManager, Configuration } from './config/ConfigurationManager';
import { DocumentProcessor } from './processors/DocumentProcessor';
import { BatchProcessor } from './processors/BatchProcessor';
import { JinaEmbeddingPipeline } from './pipelines/JinaEmbeddingPipeline';
import { SupabaseConnector } from './connectors/SupabaseConnector';
import { PineconeConnector } from './connectors/PineconeConnector';
import { Neo4jConnector } from './connectors/Neo4jConnector';
import { CitationTracker } from './services/CitationTracker';
// import { JinaServiceManager } from './services/jina/index';
import { 
  ETLContext,
  ETLLogger,
  MetricsCollector,
  CacheManager,
  ExtractedDocument,
  VectorRecord,
  ProcessingResult
} from './types/index';
import path from 'path';
import { readdir } from 'fs/promises';

// Graceful shutdown handling
let isShuttingDown = false;

class ProjectSeldonETL {
  private config?: Configuration;
  private documentProcessor?: DocumentProcessor;
  private batchProcessor?: BatchProcessor<string, ProcessingResult>;
  private embeddingPipeline?: JinaEmbeddingPipeline;
  private supabaseConnector?: SupabaseConnector;
  private pineconeConnector?: PineconeConnector;
  private neo4jConnector?: Neo4jConnector;
  private citationTracker?: CitationTracker;
  private context?: ETLContext;
  private initialized: boolean = false;

  constructor() {
    // Context will be created after configuration is loaded
  }

  /**
   * Initialize all components
   */
  async initialize(): Promise<void> {
    try {
      logger.info('Initializing Project Seldon ETL Pipeline');

      // Load configuration
      this.config = await configManager.load();
      await configManager.validate();

      // Create context after configuration is loaded
      this.context = this.createContext();

      // Initialize processors
      this.documentProcessor = new DocumentProcessor(this.config);
      this.batchProcessor = new BatchProcessor(this.config);
      this.embeddingPipeline = new JinaEmbeddingPipeline(this.config);

      // Initialize database connectors
      this.supabaseConnector = new SupabaseConnector(this.config);
      this.pineconeConnector = new PineconeConnector(this.config);
      this.neo4jConnector = new Neo4jConnector(this.config);

      // Initialize services
      this.citationTracker = new CitationTracker();

      // Test connections
      await this.testConnections();

      // Mark as initialized
      this.initialized = true;

      logger.info('Project Seldon ETL Pipeline initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize ETL pipeline', error as Error);
      throw error;
    }
  }

  /**
   * Test all database connections
   */
  private async testConnections(): Promise<void> {
    logger.info('Testing database connections');

    if (!this.supabaseConnector || !this.pineconeConnector || !this.neo4jConnector || !this.context) {
      throw new Error('Connectors not initialized');
    }

    const connections = await Promise.allSettled([
      this.supabaseConnector.testConnection(),
      this.pineconeConnector.initialize(this.context),
      this.neo4jConnector.testConnection(),
    ]);

    const failed = connections.filter(c => c.status === 'rejected');
    if (failed.length > 0) {
      throw new Error(`Failed to connect to ${failed.length} database(s)`);
    }

    logger.info('All database connections successful');
  }

  /**
   * Process documents from a directory
   */
  async processDirectory(directoryPath: string): Promise<void> {
    if (!this.initialized || !this.batchProcessor || !this.context) {
      throw new Error('ETL pipeline not initialized. Call initialize() first.');
    }

    try {
      logger.info(`Processing documents from directory: ${directoryPath}`);

      // Get all markdown files
      const files = await this.getMarkdownFiles(directoryPath);
      logger.info(`Found ${files.length} markdown files to process`);

      // Process files in batches
      const processor = async (filePath: string) => {
        return await this.processDocument(filePath);
      };

      const result = await this.batchProcessor.processBatch(
        files,
        processor,
        this.context,
        {
          onProgress: (progress) => {
            logger.info('Processing progress', {
              processed: progress.processedItems,
              total: progress.totalItems,
              percentage: progress.percentage.toFixed(2),
              itemsPerSecond: progress.itemsPerSecond.toFixed(2),
            });
          },
          onError: (error) => {
            logger.error('Processing error', error.error, {
              itemId: error.itemId,
              retryCount: error.retryCount,
            });
          },
        }
      );

      logger.info('Directory processing completed', {
        successful: result.successful.length,
        failed: result.failed.length,
        duration: result.stats.totalDuration,
      });

      // Generate summary report
      await this.generateReport(result);
    } catch (error) {
      logger.error('Failed to process directory', error as Error);
      throw error;
    }
  }

  /**
   * Process a single document
   */
  private async processDocument(filePath: string): Promise<ProcessingResult> {
    if (!this.documentProcessor || !this.embeddingPipeline || !this.citationTracker || !this.context) {
      throw new Error('Required services not initialized');
    }

    const startTime = Date.now();

    try {
      // 1. Extract and parse document
      const processingResult = await this.documentProcessor.processFile(filePath);
      const { document, chunks, metadata, stats } = processingResult;

      // 2. Generate embeddings
      const embeddingResult = await this.embeddingPipeline.processChunks(
        chunks,
        this.context
      );

      // 3. Create citations
      const citations = chunks.flatMap(chunk => 
        this.citationTracker.createChunkCitations(chunk, document, {
          includeLineNumbers: true,
          includeContext: true,
          contextLength: 100,
        })
      );

      // 4. Store in databases
      await this.storeResults(document, embeddingResult.vectorRecords, citations);

      // 5. Extract and store relationships
      await this.extractRelationships(document);

      const processingTime = Date.now() - startTime;

      logger.info('Document processed successfully', {
        documentId: document.id,
        chunks: chunks.length,
        embeddings: embeddingResult.vectorRecords.length,
        citations: citations.length,
        processingTime,
      });

      return {
        success: true,
        documentsProcessed: 1,
        documentsTotal: 1,
        errors: [],
        warnings: [],
        startTime: new Date(startTime),
        endTime: new Date(),
        duration: processingTime,
        metadata: {
          documentId: document.id,
          chunks: chunks.length,
          embeddings: embeddingResult.vectorRecords.length,
          citations: citations.length,
          ...metadata,
        },
      };
    } catch (error) {
      logger.error('Failed to process document', error as Error, { filePath });
      throw error;
    }
  }

  /**
   * Store results in databases
   */
  private async storeResults(
    document: ExtractedDocument,
    vectorRecords: VectorRecord[],
    citations: any[]
  ): Promise<void> {
    if (!this.supabaseConnector || !this.pineconeConnector || !this.neo4jConnector || !this.context) {
      throw new Error('Database connectors not initialized');
    }

    // Store document in Supabase
    await this.supabaseConnector.insertDocument(document, this.context);

    // Store vectors in Pinecone
    await this.pineconeConnector.insertVectors(vectorRecords, 'documents', this.context);

    // Store document node in Neo4j
    await this.neo4jConnector.upsertNode({
      id: document.id,
      labels: ['Document', document.metadata.category || 'Unknown'],
      properties: {
        title: document.metadata.title,
        author: document.metadata.author,
        source: document.metadata.source,
        createdAt: document.metadata.createdAt ? document.metadata.createdAt.toISOString() : new Date().toISOString(),
        checksum: document.checksum,
        chunkCount: vectorRecords.length,
        citationCount: citations.length,
      },
    }, this.context);

    // Store citations in Supabase
    for (const citation of citations) {
      await this.supabaseConnector.executeRawQuery(
        'INSERT INTO citations (id, document_id, type, start_offset, end_offset, text, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [citation.id, citation.documentId, citation.type, citation.startOffset, citation.endOffset, citation.text, citation.metadata]
      );
    }
  }

  /**
   * Extract relationships from document
   */
  private async extractRelationships(document: ExtractedDocument): Promise<void> {
    if (!this.documentProcessor || !this.neo4jConnector || !this.context) {
      throw new Error('Required services not initialized');
    }

    // Extract entities (simplified for demo)
    const entities = await this.documentProcessor.extractEntities(document.content.raw);

    // Create entity nodes
    for (const entity of entities) {
      await this.neo4jConnector.upsertNode({
        id: `entity-${entity.value}`,
        labels: ['Entity', entity.type],
        properties: {
          value: entity.value,
          confidence: entity.confidence,
          documentId: document.id,
        },
      }, this.context);

      // Create relationship
      await this.neo4jConnector.upsertRelationship({
        id: `rel-${document.id}-${entity.value}`,
        type: 'MENTIONS',
        startNodeId: document.id,
        endNodeId: `entity-${entity.value}`,
        properties: {
          confidence: entity.confidence,
        },
      }, this.context);
    }
  }

  /**
   * Get markdown files from directory
   */
  private async getMarkdownFiles(directoryPath: string): Promise<string[]> {
    const files: string[] = [];
    const entries = await readdir(directoryPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(directoryPath, entry.name);
      
      if (entry.isDirectory()) {
        // Recursively search subdirectories
        const subFiles = await this.getMarkdownFiles(fullPath);
        files.push(...subFiles);
      } else if (entry.isFile() && entry.name.endsWith('.md')) {
        files.push(fullPath);
      }
    }

    return files;
  }

  /**
   * Generate processing report
   */
  private async generateReport(result: any): Promise<void> {
    if (!this.supabaseConnector || !this.pineconeConnector || !this.neo4jConnector || !this.citationTracker || !this.context) {
      throw new Error('Required services not initialized');
    }

    const stats = await Promise.all([
      this.supabaseConnector.getStatistics(this.context),
      this.pineconeConnector.getStatistics(this.context),
      this.neo4jConnector.getStatistics(this.context),
    ]);

    const report = {
      processingResult: {
        successful: result.successful.length,
        failed: result.failed.length,
        stats: result.stats,
      },
      databaseStats: {
        supabase: stats[0],
        pinecone: stats[1],
        neo4j: stats[2],
      },
      citationStats: this.citationTracker.getCacheStats(),
      timestamp: new Date().toISOString(),
    };

    logger.info('Processing report', report);
  }

  /**
   * Create ETL context
   */
  private createContext(): ETLContext {
    const etlLogger: ETLLogger = {
      debug: (message: string, context?: any) => logger.debug(message, context),
      info: (message: string, context?: any) => logger.info(message, context),
      warn: (message: string, context?: any) => logger.warn(message, context),
      error: (message: string, error?: Error, context?: any) => logger.error(message, error, context),
    };

    const metrics: MetricsCollector = {
      increment: (metric: string, value?: number, tags?: Record<string, string>) => {
        logger.debug('Metric increment', { metric, value, tags });
      },
      gauge: (metric: string, value: number, tags?: Record<string, string>) => {
        logger.debug('Metric gauge', { metric, value, tags });
      },
      histogram: (metric: string, value: number, tags?: Record<string, string>) => {
        logger.debug('Metric histogram', { metric, value, tags });
      },
      timing: (metric: string, value: number, tags?: Record<string, string>) => {
        logger.debug('Metric timing', { metric, value, tags });
      },
    };

    const cache: CacheManager = {
      get: async <T>(key: string): Promise<T | null> => null,
      set: async <T>(key: string, value: T, ttl?: number): Promise<void> => {},
      delete: async (key: string): Promise<void> => {},
      clear: async (): Promise<void> => {},
    };

    return {
      jobId: `job-${Date.now()}`,
      pipelineId: 'project-seldon-etl',
      stageId: 'main',
      config: {
        environment: (this.config?.environment || 'development') as 'development' | 'staging' | 'production',
        batchSize: this.config?.etl?.batchSize || 50,
        maxRetries: this.config?.etl?.maxRetries || 3,
        retryDelay: this.config?.etl?.retryDelay || 5000,
        concurrency: this.config?.etl?.concurrency || 5,
        timeout: this.config?.etl?.timeout || 300000,
        enableMetrics: this.config?.etl?.enableMetrics ?? true,
        enableTracing: this.config?.etl?.enableTracing ?? true,
      },
      logger: etlLogger,
      metrics,
      cache,
    };
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    logger.info('Cleaning up Project Seldon ETL Pipeline');

    const cleanupTasks = [];

    // Only cleanup initialized services
    if (this.batchProcessor) cleanupTasks.push(this.batchProcessor.cleanup());
    if (this.embeddingPipeline) cleanupTasks.push(this.embeddingPipeline.cleanup());
    if (this.supabaseConnector) cleanupTasks.push(this.supabaseConnector.cleanup());
    if (this.pineconeConnector) cleanupTasks.push(this.pineconeConnector.cleanup());
    if (this.neo4jConnector) cleanupTasks.push(this.neo4jConnector.cleanup());

    // Wait for all cleanup tasks
    if (cleanupTasks.length > 0) {
      await Promise.allSettled(cleanupTasks);
    }

    // Clear citation cache if initialized
    if (this.citationTracker) {
      this.citationTracker.clearCache();
    }

    this.initialized = false;
    logger.info('Cleanup completed');
  }
}

// Main execution
async function main() {
  const etl = new ProjectSeldonETL();

  try {
    // Initialize
    await etl.initialize();

    // Get directory from command line or use default
    const directory = process.argv[2] || path.join(process.cwd(), 'Annual_cyber_reports');
    
    // Process documents
    await etl.processDirectory(directory);

    logger.info('ETL pipeline completed successfully');
  } catch (error) {
    logger.error('ETL pipeline failed', error as Error);
    process.exit(1);
  } finally {
    if (!isShuttingDown) {
      await etl.cleanup();
    }
  }
}

// Graceful shutdown handlers
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', error);
  shutdown();
});
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled rejection', reason as Error, { promise });
  shutdown();
});

async function shutdown() {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.info('Shutting down gracefully...');
  
  setTimeout(() => {
    logger.error('Forced shutdown due to timeout');
    process.exit(1);
  }, 30000); // 30 second timeout

  process.exit(0);
}

// Export for module usage
export { ProjectSeldonETL };

// Run if called directly
if (require.main === module) {
  main();
}