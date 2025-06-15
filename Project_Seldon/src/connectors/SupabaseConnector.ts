/**
 * Supabase Database Connector for Project Seldon
 * Handles all interactions with Supabase PostgreSQL database
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { logger } from '../utils/logger';
import { Configuration } from '../config/types';
import { 
  ExtractedDocument, 
  DatabaseRecord,
  ETLContext 
} from '../types/index';

export interface SupabaseConnectionOptions {
  maxRetries?: number;
  retryDelay?: number;
  timeout?: number;
}

export interface SupabaseQueryResult<T> {
  data: T[] | null;
  error: Error | null;
  count: number | null;
}

export class SupabaseConnector {
  private client: SupabaseClient;
  private isConnected: boolean = false;
  private clientPool: SupabaseClient[] = [];
  private maxPoolSize: number = 5;
  private pooledClients: Map<SupabaseClient, boolean> = new Map();

  constructor(private config: Configuration) {
    this.client = this.createClient();
  }

  /**
   * Create a Supabase client with optimized settings for ETL
   */
  private createClient(): SupabaseClient {
    const options = {
      auth: {
        persistSession: false,
        autoRefreshToken: false, // Disable auto-refresh for ETL
      },
      realtime: {
        enabled: false, // Disable realtime for ETL
      },
      global: {
        headers: {
          'x-connection-timeout': '30000', // 30 second timeout
        },
      },
      db: {
        schema: 'public',
      },
    };
    
    return createClient(
      this.config.databases.supabase.url,
      this.config.databases.supabase.serviceKey,
      options
    );
  }

  /**
   * Get a pooled client connection
   */
  private async getPooledClient(): Promise<SupabaseClient> {
    // Find an available client from the pool
    for (const [client, inUse] of this.pooledClients.entries()) {
      if (!inUse) {
        this.pooledClients.set(client, true);
        return client;
      }
    }

    // If no available clients and pool not full, create a new one
    if (this.clientPool.length < this.maxPoolSize) {
      const newClient = this.createClient();
      this.clientPool.push(newClient);
      this.pooledClients.set(newClient, true);
      return newClient;
    }

    // If pool is full, wait and retry
    await new Promise(resolve => setTimeout(resolve, 100));
    return this.getPooledClient();
  }

  /**
   * Release a client back to the pool
   */
  private releaseClient(client: SupabaseClient): void {
    this.pooledClients.set(client, false);
  }

  /**
   * Execute an operation with connection pooling and retry logic
   */
  private async withConnection<T>(
    operation: (client: SupabaseClient) => Promise<T>,
    options: SupabaseConnectionOptions = {}
  ): Promise<T> {
    const maxRetries = options.maxRetries || 3;
    const retryDelay = options.retryDelay || 1000;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const client = await this.getPooledClient();
      try {
        return await operation(client);
      } catch (error) {
        lastError = error as Error;
        
        if (attempt < maxRetries) {
          logger.warn(`Retrying Supabase operation (attempt ${attempt + 1}/${maxRetries})`, {
            error: lastError.message,
          });
          
          await new Promise(resolve => setTimeout(resolve, retryDelay * Math.pow(2, attempt)));
        }
      } finally {
        this.releaseClient(client);
      }
    }

    throw lastError || new Error('Unknown error in Supabase operation');
  }

  /**
   * Test database connection
   */
  public async testConnection(): Promise<boolean> {
    try {
      logger.info('Testing Supabase connection');
      
      const result = await this.withConnection(async (client) => {
        const { error } = await client
          .from('documents')
          .select('id')
          .limit(1);

        if (error) {
          logger.error('Supabase connection test failed', error);
          return false;
        }

        return true;
      });

      if (result) {
        this.isConnected = true;
        logger.info('Supabase connection successful');
      }
      
      return result;
    } catch (error) {
      logger.error('Supabase connection test error', error as Error);
      return false;
    }
  }

  /**
   * Insert document
   */
  public async insertDocument(
    document: ExtractedDocument,
    context: ETLContext
  ): Promise<DatabaseRecord> {
    try {
      context.logger.debug('Inserting document', { documentId: document.id });

      const record = this.mapToDbRecord(document);
      
      const result = await this.withConnection(async (client) => {
        const { data, error } = await client
          .from('documents')
          .insert(record)
          .select()
          .single();

        if (error) {
          throw new Error(`Failed to insert document: ${error.message}`);
        }

        return data as DatabaseRecord;
      });

      context.metrics.increment('database.documents.inserted', 1);
      
      return result;
    } catch (error) {
      context.logger.error('Failed to insert document', error as Error, {
        documentId: document.id,
      });
      throw error;
    }
  }

  /**
   * Insert multiple documents in batch
   */
  public async insertDocumentsBatch(
    documents: ExtractedDocument[],
    context: ETLContext
  ): Promise<DatabaseRecord[]> {
    try {
      context.logger.info(`Inserting ${documents.length} documents in batch`);

      const records = documents.map(doc => this.mapToDbRecord(doc));
      
      const result = await this.withConnection(async (client) => {
        const { data, error } = await client
          .from('documents')
          .insert(records)
          .select();

        if (error) {
          throw new Error(`Failed to insert documents batch: ${error.message}`);
        }

        return data as DatabaseRecord[];
      });

      context.metrics.increment('database.documents.inserted', documents.length);
      
      return result;
    } catch (error) {
      context.logger.error('Failed to insert documents batch', error as Error);
      throw error;
    }
  }

  /**
   * Update document
   */
  public async updateDocument(
    documentId: string,
    updates: Partial<ExtractedDocument>,
    context: ETLContext
  ): Promise<DatabaseRecord> {
    try {
      context.logger.debug('Updating document', { documentId });

      const { data, error } = await this.client
        .from('documents')
        .update({
          ...updates,
          updated_at: new Date().toISOString(),
        })
        .eq('id', documentId)
        .select()
        .single();

      if (error) {
        throw new Error(`Failed to update document: ${error.message}`);
      }

      context.metrics.increment('database.documents.updated', 1);
      
      return data as DatabaseRecord;
    } catch (error) {
      context.logger.error('Failed to update document', error as Error, {
        documentId,
      });
      throw error;
    }
  }

  /**
   * Get document by ID
   */
  public async getDocument(
    documentId: string,
    context: ETLContext
  ): Promise<DatabaseRecord | null> {
    try {
      const { data, error } = await this.client
        .from('documents')
        .select('*')
        .eq('id', documentId)
        .single();

      if (error) {
        if (error.code === 'PGRST116') {
          // No rows returned
          return null;
        }
        throw new Error(`Failed to get document: ${error.message}`);
      }

      return data as DatabaseRecord;
    } catch (error) {
      context.logger.error('Failed to get document', error as Error, {
        documentId,
      });
      throw error;
    }
  }

  /**
   * Query documents
   */
  public async queryDocuments(
    filters: Record<string, any>,
    options: {
      limit?: number;
      offset?: number;
      orderBy?: string;
      ascending?: boolean;
    } = {},
    context: ETLContext
  ): Promise<SupabaseQueryResult<DatabaseRecord>> {
    try {
      const result = await this.withConnection(async (client) => {
        let query = client.from('documents').select('*', { count: 'exact' });

        // Apply filters
        for (const [key, value] of Object.entries(filters)) {
          if (value !== undefined && value !== null) {
            query = query.eq(key, value);
          }
        }

        // Apply pagination
        if (options.limit) {
          query = query.limit(options.limit);
        }
        if (options.offset) {
          query = query.range(options.offset, options.offset + (options.limit || 10) - 1);
        }

        // Apply ordering
        if (options.orderBy) {
          query = query.order(options.orderBy, { ascending: options.ascending ?? true });
        }

        const { data, error, count } = await query;

        if (error) {
          throw new Error(`Failed to query documents: ${error.message}`);
        }

        return {
          data: data as DatabaseRecord[],
          error: null,
          count,
        };
      });

      return result;
    } catch (error) {
      context.logger.error('Failed to query documents', error as Error);
      return {
        data: null,
        error: error as Error,
        count: null,
      };
    }
  }

  /**
   * Delete document
   */
  public async deleteDocument(
    documentId: string,
    context: ETLContext
  ): Promise<boolean> {
    try {
      context.logger.debug('Deleting document', { documentId });

      const { error } = await this.client
        .from('documents')
        .delete()
        .eq('id', documentId);

      if (error) {
        throw new Error(`Failed to delete document: ${error.message}`);
      }

      context.metrics.increment('database.documents.deleted', 1);
      
      return true;
    } catch (error) {
      context.logger.error('Failed to delete document', error as Error, {
        documentId,
      });
      throw error;
    }
  }

  /**
   * Insert chunk metadata
   */
  public async insertChunkMetadata(
    chunkId: string,
    documentId: string,
    metadata: Record<string, any>,
    context: ETLContext
  ): Promise<void> {
    try {
      const { error } = await this.client
        .from('chunk_metadata')
        .insert({
          chunk_id: chunkId,
          document_id: documentId,
          metadata,
          created_at: new Date().toISOString(),
        });

      if (error) {
        throw new Error(`Failed to insert chunk metadata: ${error.message}`);
      }

      context.metrics.increment('database.chunks.inserted', 1);
    } catch (error) {
      context.logger.error('Failed to insert chunk metadata', error as Error, {
        chunkId,
        documentId,
      });
      throw error;
    }
  }

  /**
   * Execute raw SQL query (for complex operations)
   */
  public async executeRawQuery<T>(
    query: string,
    params: any[] = []
  ): Promise<T[]> {
    try {
      const { data, error } = await this.client.rpc('execute_raw_sql', {
        query_text: query,
        query_params: params,
      });

      if (error) {
        throw new Error(`Failed to execute raw query: ${error.message}`);
      }

      return data as T[];
    } catch (error) {
      logger.error('Failed to execute raw query', error as Error, { query });
      throw error;
    }
  }

  /**
   * Begin transaction
   */
  public async beginTransaction(): Promise<string> {
    const { data, error } = await this.client.rpc('begin_transaction');
    
    if (error) {
      throw new Error(`Failed to begin transaction: ${error.message}`);
    }
    
    return data as string;
  }

  /**
   * Commit transaction
   */
  public async commitTransaction(transactionId: string): Promise<void> {
    const { error } = await this.client.rpc('commit_transaction', {
      transaction_id: transactionId,
    });
    
    if (error) {
      throw new Error(`Failed to commit transaction: ${error.message}`);
    }
  }

  /**
   * Rollback transaction
   */
  public async rollbackTransaction(transactionId: string): Promise<void> {
    const { error } = await this.client.rpc('rollback_transaction', {
      transaction_id: transactionId,
    });
    
    if (error) {
      throw new Error(`Failed to rollback transaction: ${error.message}`);
    }
  }

  /**
   * Get database statistics
   */
  public async getStatistics(context: ETLContext): Promise<{
    totalDocuments: number;
    totalChunks: number;
    totalSize: number;
    lastUpdated: Date;
  }> {
    try {
      const { data, error } = await this.client.rpc('get_database_statistics');
      
      if (error) {
        throw new Error(`Failed to get statistics: ${error.message}`);
      }

      return data as any;
    } catch (error) {
      context.logger.error('Failed to get database statistics', error as Error);
      throw error;
    }
  }

  /**
   * Map document to database record
   */
  private mapToDbRecord(document: ExtractedDocument): any {
    return {
      id: document.id,
      content: document.content,
      metadata: document.metadata,
      checksum: document.checksum,
      status: document.status,
      extracted_at: document.extractedAt ? document.extractedAt.toISOString() : new Date().toISOString(),
      processing_time: document.processingTime,
      error: document.error,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
  }

  /**
   * Cleanup and close connections
   */
  public async cleanup(): Promise<void> {
    logger.info('Cleaning up Supabase connector');
    this.isConnected = false;
    
    // Clear the connection pool
    this.clientPool = [];
    this.pooledClients.clear();
    
    logger.info(`Closed ${this.clientPool.length} pooled connections`);
  }

  /**
   * Get connection status
   */
  public getConnectionStatus(): boolean {
    return this.isConnected;
  }

  /**
   * Handle connection retry
   */
  // Unused for now, but keeping for future implementation
  // private async withRetry<T>(
  //   operation: () => Promise<T>,
  //   options: SupabaseConnectionOptions = {}
  // ): Promise<T> {
  //   const maxRetries = options.maxRetries || this.config.databases.supabase.maxRetries;
  //   const retryDelay = options.retryDelay || this.config.databases.supabase.retryDelay;
  //   let lastError: Error | null = null;
  //
  //   for (let attempt = 0; attempt <= maxRetries; attempt++) {
  //     try {
  //       return await operation();
  //     } catch (error) {
  //       lastError = error as Error;
  //       
  //       if (attempt < maxRetries) {
  //         logger.warn(`Retrying Supabase operation (attempt ${attempt + 1}/${maxRetries})`, {
  //           error: lastError.message,
  //         });
  //         
  //         await new Promise(resolve => setTimeout(resolve, retryDelay * Math.pow(2, attempt)));
  //       }
  //     }
  //   }
  //
  //   throw lastError || new Error('Unknown error in Supabase operation');
  // }
}