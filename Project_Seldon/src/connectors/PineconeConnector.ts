/**
 * Pinecone Vector Database Connector for Project Seldon
 * Handles vector storage and similarity search operations
 */

import { Pinecone, PineconeRecord, QueryResponse } from '@pinecone-database/pinecone';
import { logger } from '../utils/logger';
import { Configuration } from '../config/types';
import { 
  VectorRecord,
  VectorMetadata,
  ETLContext
} from '../types/index';

export interface PineconeSearchResult {
  id: string;
  score: number;
  metadata: Record<string, any>;
  embedding?: number[];
}

export interface PineconeStats {
  totalVectors: number;
  dimension: number;
  indexFullness: number;
  namespaces: string[];
}

export class PineconeConnector {
  private client: Pinecone;
  private config: Configuration;
  private indexName: string;
  private isInitialized: boolean = false;

  constructor(config: Configuration) {
    this.config = config;
    this.indexName = config.databases.pinecone.indexName;
    this.client = new Pinecone({
      apiKey: config.databases.pinecone.apiKey,
    });
  }

  /**
   * Initialize Pinecone connection and index
   */
  public async initialize(context: ETLContext): Promise<void> {
    try {
      context.logger.info('Initializing Pinecone connector', {
        indexName: this.indexName,
      });

      // Check if index exists
      const indexes = await this.client.listIndexes();
      const indexExists = indexes.indexes?.some(idx => idx.name === this.indexName);

      if (!indexExists) {
        context.logger.info('Creating Pinecone index', {
          indexName: this.indexName,
          dimension: this.config.databases.pinecone.dimension,
          metric: this.config.databases.pinecone.metric,
        });

        await this.client.createIndex({
          name: this.indexName,
          dimension: this.config.databases.pinecone.dimension,
          metric: this.config.databases.pinecone.metric,
          spec: {
            serverless: {
              cloud: 'aws',
              region: 'us-east-1',
            },
          },
        });

        // Wait for index to be ready
        await this.waitForIndexReady(context);
      }

      this.isInitialized = true;
      context.logger.info('Pinecone connector initialized successfully');
    } catch (error) {
      context.logger.error('Failed to initialize Pinecone connector', error as Error);
      throw error;
    }
  }

  /**
   * Wait for index to be ready
   */
  private async waitForIndexReady(context: ETLContext): Promise<void> {
    const maxAttempts = 60; // 5 minutes with 5-second intervals
    let attempts = 0;

    while (attempts < maxAttempts) {
      try {
        const description = await this.client.describeIndex(this.indexName);
        if (description.status?.ready) {
          return;
        }
      } catch (error) {
        context.logger.debug('Index not ready yet', { attempt: attempts });
      }

      await new Promise(resolve => setTimeout(resolve, 5000));
      attempts++;
    }

    throw new Error('Pinecone index creation timeout');
  }

  /**
   * Insert vector records
   */
  public async insertVectors(
    vectors: VectorRecord[],
    namespace: string = 'default',
    context: ETLContext
  ): Promise<void> {
    try {
      if (!this.isInitialized) {
        await this.initialize(context);
      }

      context.logger.info(`Inserting ${vectors.length} vectors into namespace ${namespace}`);

      const index = this.client.index(this.indexName);
      
      // Convert to Pinecone format
      const records: PineconeRecord[] = vectors.map(vector => ({
        id: vector.id,
        values: vector.values,
        metadata: vector.metadata,
      }));

      // Batch upsert for better performance
      const batchSize = 100;
      for (let i = 0; i < records.length; i += batchSize) {
        const batch = records.slice(i, i + batchSize);
        await index.namespace(namespace).upsert(batch);
        
        context.metrics.increment('pinecone.vectors.upserted', batch.length, {
          namespace,
        });
      }

      context.logger.info('Vectors inserted successfully', {
        count: vectors.length,
        namespace,
      });
    } catch (error) {
      context.logger.error('Failed to insert vectors', error as Error);
      throw error;
    }
  }

  /**
   * Search similar vectors
   */
  public async search(
    query: number[],
    options: {
      namespace?: string;
      filter?: Record<string, any>;
      includeValues?: boolean;
      limit?: number;
      scoreThreshold?: number;
    } = {},
    context: ETLContext
  ): Promise<PineconeSearchResult[]> {
    try {
      if (!this.isInitialized) {
        await this.initialize(context);
      }

      const index = this.client.index(this.indexName);
      const namespace = options.namespace || 'default';
      const topK = options.limit || 10;

      context.logger.debug('Searching vectors', {
        namespace,
        topK,
        filterKeys: options.filter ? Object.keys(options.filter) : [],
      });

      const response: QueryResponse = await index.namespace(namespace).query({
        vector: query,
        topK,
        filter: options.filter,
        includeValues: options.includeValues || false,
        includeMetadata: true,
      });

      context.metrics.increment('pinecone.searches.performed', 1, {
        namespace,
        resultsCount: String(response.matches?.length || 0),
      });

      return (response.matches || []).map(match => ({
        id: String(match.id),
        score: match.score || 0,
        metadata: match.metadata || {},
        embedding: match.values,
      }));
    } catch (error) {
      context.logger.error('Failed to search vectors', error as Error);
      throw error;
    }
  }

  /**
   * Update vector metadata
   */
  public async updateMetadata(
    vectorId: string,
    metadata: Record<string, any>,
    namespace: string = 'default',
    context: ETLContext
  ): Promise<void> {
    try {
      if (!this.isInitialized) {
        await this.initialize(context);
      }

      const index = this.client.index(this.indexName);
      
      await index.namespace(namespace).update({
        id: vectorId,
        metadata: {
          ...metadata,
          updatedAt: new Date().toISOString(),
        },
      });

      context.metrics.increment('pinecone.vectors.updated', 1, {
        namespace,
      });
    } catch (error) {
      context.logger.error('Failed to update vector metadata', error as Error, {
        vectorId,
      });
      throw error;
    }
  }

  /**
   * Delete vectors
   */
  public async deleteVectors(
    vectorIds: string[],
    namespace: string = 'default',
    context: ETLContext
  ): Promise<void> {
    try {
      if (!this.isInitialized) {
        await this.initialize(context);
      }

      context.logger.info(`Deleting ${vectorIds.length} vectors from namespace ${namespace}`);

      const index = this.client.index(this.indexName);
      
      await index.namespace(namespace).deleteMany(vectorIds);

      context.metrics.increment('pinecone.vectors.deleted', vectorIds.length, {
        namespace,
      });
    } catch (error) {
      context.logger.error('Failed to delete vectors', error as Error);
      throw error;
    }
  }

  /**
   * Delete all vectors in a namespace
   */
  public async deleteNamespace(
    namespace: string,
    context: ETLContext
  ): Promise<void> {
    try {
      if (!this.isInitialized) {
        await this.initialize(context);
      }

      context.logger.warn(`Deleting all vectors in namespace ${namespace}`);

      const index = this.client.index(this.indexName);
      
      await index.namespace(namespace).deleteAll();

      context.metrics.increment('pinecone.namespaces.deleted', 1, {
        namespace,
      });
    } catch (error) {
      context.logger.error('Failed to delete namespace', error as Error, {
        namespace,
      });
      throw error;
    }
  }

  /**
   * Get index statistics
   */
  public async getStatistics(context: ETLContext): Promise<PineconeStats> {
    try {
      if (!this.isInitialized) {
        await this.initialize(context);
      }

      const index = this.client.index(this.indexName);
      const stats = await index.describeIndexStats();

      const namespaces = Object.keys(stats.namespaces || {});
      const totalVectors = namespaces.reduce(
        (sum, ns) => sum + (stats.namespaces?.[ns]?.recordCount || 0),
        0
      );

      return {
        totalVectors,
        dimension: stats.dimension || this.config.databases.pinecone.dimension,
        indexFullness: stats.indexFullness || 0,
        namespaces,
      };
    } catch (error) {
      context.logger.error('Failed to get Pinecone statistics', error as Error);
      throw error;
    }
  }

  /**
   * Fetch vectors by IDs
   */
  public async fetchVectors(
    vectorIds: string[],
    namespace: string = 'default',
    context: ETLContext
  ): Promise<VectorRecord[]> {
    try {
      if (!this.isInitialized) {
        await this.initialize(context);
      }

      const index = this.client.index(this.indexName);
      const response = await index.namespace(namespace).fetch(vectorIds);

      const vectors: VectorRecord[] = [];
      
      for (const [id, record] of Object.entries(response.records || {})) {
        if (record) {
          vectors.push({
            id,
            values: record.values || [],
            metadata: record.metadata as VectorMetadata || {
              chunk_id: '',
              document_id: '',
              content: '',
              language: 'en',
              content_type: 'text',
              created_at: Date.now()
            },
          });
        }
      }

      return vectors;
    } catch (error) {
      context.logger.error('Failed to fetch vectors', error as Error);
      throw error;
    }
  }

  /**
   * Perform hybrid search (combining vector similarity with metadata filtering)
   */
  public async hybridSearch(
    query: number[],
    metadataFilters: Record<string, any>,
    options: {
      namespace?: string;
      topK?: number;
      scoreThreshold?: number;
    } = {},
    context: ETLContext
  ): Promise<PineconeSearchResult[]> {
    try {
      const results = await this.search(
        query,
        {
          namespace: options.namespace,
          filter: metadataFilters,
          limit: options.topK || 20,
        },
        context
      );

      // Apply score threshold if provided
      if (options.scoreThreshold !== undefined) {
        return results.filter(result => result.score >= options.scoreThreshold!);
      }

      return results;
    } catch (error) {
      context.logger.error('Failed to perform hybrid search', error as Error);
      throw error;
    }
  }

  /**
   * Check if vector exists
   */
  public async vectorExists(
    vectorId: string,
    namespace: string = 'default',
    context: ETLContext
  ): Promise<boolean> {
    try {
      const vectors = await this.fetchVectors([vectorId], namespace, context);
      return vectors.length > 0;
    } catch (error) {
      context.logger.error('Failed to check vector existence', error as Error, {
        vectorId,
      });
      return false;
    }
  }

  /**
   * Cleanup and close connections
   */
  public async cleanup(): Promise<void> {
    logger.info('Cleaning up Pinecone connector');
    this.isInitialized = false;
    // Pinecone client doesn't require explicit cleanup
  }

  /**
   * Get initialization status
   */
  public getInitializationStatus(): boolean {
    return this.isInitialized;
  }
}