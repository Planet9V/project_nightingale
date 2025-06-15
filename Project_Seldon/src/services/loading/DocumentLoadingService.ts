import { Pool } from 'pg';
import { Pinecone } from '@pinecone-database/pinecone';
import neo4j, { Driver, Session } from 'neo4j-driver';
import { v4 as uuidv4 } from 'uuid';
import pLimit from 'p-limit';
import { TransformedDocument, TransformedChunk } from '../transformation/types';
import { logger } from '../../utils/logger';

interface LoadingConfig {
  supabase: {
    connectionString: string;
    schema?: string;
  };
  pinecone: {
    apiKey: string;
    environment: string;
    indexName: string;
    namespace?: string;
  };
  neo4j: {
    uri: string;
    username: string;
    password: string;
    database?: string;
  };
  batchSize?: number;
  maxConcurrency?: number;
}

interface LoadingResult {
  documentId: string;
  supabaseId?: string;
  pineconeIds?: string[];
  neo4jNodeId?: string;
  status: 'success' | 'partial' | 'failed';
  errors?: Array<{
    database: 'supabase' | 'pinecone' | 'neo4j';
    error: string;
  }>;
}

interface CrossDatabaseReference {
  documentId: string;
  supabaseId: string;
  pineconeNamespace: string;
  neo4jNodeId: string;
  createdAt: Date;
}

export class DocumentLoadingService {
  private supabasePool: Pool;
  private pinecone: Pinecone;
  private neo4jDriver: Driver;
  private config: LoadingConfig;
  private concurrencyLimit: pLimit.Limit;

  constructor(config: LoadingConfig) {
    this.config = {
      ...config,
      batchSize: config.batchSize || 100,
      maxConcurrency: config.maxConcurrency || 5,
    };

    // Initialize database connections
    this.supabasePool = new Pool({
      connectionString: config.supabase.connectionString,
    });

    this.pinecone = new Pinecone({
      apiKey: config.pinecone.apiKey,
    });

    this.neo4jDriver = neo4j.driver(
      config.neo4j.uri,
      neo4j.auth.basic(config.neo4j.username, config.neo4j.password)
    );

    this.concurrencyLimit = pLimit(this.config.maxConcurrency!);
  }

  /**
   * Load documents to all databases in parallel with rollback support
   */
  async loadDocuments(documents: TransformedDocument[]): Promise<LoadingResult[]> {
    const results: LoadingResult[] = [];
    const batches = this.createBatches(documents, this.config.batchSize!);

    for (const batch of batches) {
      const batchResults = await Promise.all(
        batch.map(doc => this.concurrencyLimit(() => this.loadSingleDocument(doc)))
      );
      results.push(...batchResults);
    }

    // Create cross-database references for successful loads
    const successfulResults = results.filter(r => r.status === 'success');
    if (successfulResults.length > 0) {
      await this.createCrossReferences(successfulResults);
    }

    return results;
  }

  /**
   * Load a single document to all databases
   */
  private async loadSingleDocument(document: TransformedDocument): Promise<LoadingResult> {
    const result: LoadingResult = {
      documentId: document.id,
      status: 'success',
      errors: [],
    };

    const rollbackActions: Array<() => Promise<void>> = [];

    try {
      // Load to Supabase
      const supabaseResult = await this.loadToSupabase(document);
      result.supabaseId = supabaseResult.id;
      rollbackActions.push(async () => {
        await this.rollbackSupabase(supabaseResult.id);
      });

      // Load to Pinecone
      const pineconeResult = await this.loadToPinecone(document);
      result.pineconeIds = pineconeResult.ids;
      rollbackActions.push(async () => {
        await this.rollbackPinecone(pineconeResult.ids);
      });

      // Load to Neo4j
      const neo4jResult = await this.loadToNeo4j(document);
      result.neo4jNodeId = neo4jResult.nodeId;
      rollbackActions.push(async () => {
        await this.rollbackNeo4j(neo4jResult.nodeId);
      });

      logger.info(`Successfully loaded document ${document.id} to all databases`);
      return result;

    } catch (error) {
      logger.error(`Failed to load document ${document.id}:`, error);
      
      // Rollback all successful operations
      for (const rollback of rollbackActions.reverse()) {
        try {
          await rollback();
        } catch (rollbackError) {
          logger.error('Rollback failed:', rollbackError);
        }
      }

      result.status = 'failed';
      result.errors!.push({
        database: this.getFailedDatabase(error),
        error: error instanceof Error ? error.message : String(error),
      });

      return result;
    }
  }

  /**
   * Load document to Supabase
   */
  private async loadToSupabase(document: TransformedDocument): Promise<{ id: string }> {
    const client = await this.supabasePool.connect();
    
    try {
      await client.query('BEGIN');

      // Insert main document
      const docResult = await client.query(
        `INSERT INTO documents (
          id, collection_id, type, source_url, title, authors, 
          publication_date, abstract, keywords, methodology, 
          key_findings, limitations, future_work, metadata,
          processing_status, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
        RETURNING id`,
        [
          document.id,
          document.metadata.collectionId,
          document.metadata.documentType,
          document.metadata.sourceUrl,
          document.title,
          JSON.stringify(document.authors),
          document.publicationDate,
          document.abstract,
          document.keywords,
          document.methodology,
          document.keyFindings,
          document.limitations,
          document.futureWork,
          JSON.stringify(document.metadata),
          'completed',
          new Date(),
          new Date(),
        ]
      );

      // Insert chunks
      for (const chunk of document.chunks) {
        await client.query(
          `INSERT INTO chunks (
            id, document_id, chunk_index, content, start_page, end_page,
            section_title, chunk_type, metadata, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
          [
            chunk.id,
            document.id,
            chunk.index,
            chunk.content,
            chunk.metadata.startPage,
            chunk.metadata.endPage,
            chunk.metadata.sectionTitle,
            chunk.metadata.chunkType,
            JSON.stringify(chunk.metadata),
            new Date(),
          ]
        );

        // Insert citations for this chunk
        for (const citation of chunk.citations) {
          await client.query(
            `INSERT INTO citations (
              id, chunk_id, text, authors, year, title, journal,
              doi, url, citation_type, confidence_score, metadata, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
            [
              uuidv4(),
              chunk.id,
              citation.text,
              JSON.stringify(citation.authors),
              citation.year,
              citation.title,
              citation.journal,
              citation.doi,
              citation.url,
              citation.type,
              citation.confidenceScore,
              JSON.stringify(citation.metadata || {}),
              new Date(),
            ]
          );
        }
      }

      await client.query('COMMIT');
      return { id: docResult.rows[0].id };

    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Load document chunks to Pinecone
   */
  private async loadToPinecone(document: TransformedDocument): Promise<{ ids: string[] }> {
    const index = this.pinecone.index(this.config.pinecone.indexName);
    const namespace = this.config.pinecone.namespace || 'default';
    const vectors = [];

    for (const chunk of document.chunks) {
      if (chunk.embedding && chunk.embedding.length > 0) {
        vectors.push({
          id: chunk.id,
          values: chunk.embedding,
          metadata: {
            documentId: document.id,
            documentTitle: document.title,
            chunkIndex: chunk.index,
            content: chunk.content.substring(0, 1000), // Truncate for metadata limits
            sectionTitle: chunk.metadata.sectionTitle,
            chunkType: chunk.metadata.chunkType,
            startPage: chunk.metadata.startPage,
            endPage: chunk.metadata.endPage,
            authors: document.authors.join(', '),
            publicationDate: document.publicationDate?.toISOString(),
            documentType: document.metadata.documentType,
            keywords: document.keywords.join(', '),
            citationCount: chunk.citations.length,
          },
        });
      }
    }

    if (vectors.length > 0) {
      await index.namespace(namespace).upsert(vectors);
    }

    return { ids: vectors.map(v => v.id) };
  }

  /**
   * Load document to Neo4j graph
   */
  private async loadToNeo4j(document: TransformedDocument): Promise<{ nodeId: string }> {
    const session = this.neo4jDriver.session({
      database: this.config.neo4j.database,
    });

    try {
      const result = await session.executeWrite(async (tx) => {
        // Create Document node
        const docResult = await tx.run(
          `CREATE (d:Document {
            id: $id,
            title: $title,
            authors: $authors,
            publicationDate: $publicationDate,
            abstract: $abstract,
            keywords: $keywords,
            documentType: $documentType,
            sourceUrl: $sourceUrl,
            methodology: $methodology,
            keyFindings: $keyFindings,
            createdAt: datetime()
          })
          RETURN d.id as nodeId`,
          {
            id: document.id,
            title: document.title,
            authors: document.authors,
            publicationDate: document.publicationDate?.toISOString(),
            abstract: document.abstract,
            keywords: document.keywords,
            documentType: document.metadata.documentType,
            sourceUrl: document.metadata.sourceUrl,
            methodology: document.methodology,
            keyFindings: document.keyFindings,
          }
        );

        const documentNodeId = docResult.records[0].get('nodeId');

        // Create Chunk nodes and relationships
        for (const chunk of document.chunks) {
          const chunkResult = await tx.run(
            `CREATE (c:Chunk {
              id: $id,
              index: $index,
              content: $content,
              sectionTitle: $sectionTitle,
              chunkType: $chunkType,
              startPage: $startPage,
              endPage: $endPage
            })
            WITH c
            MATCH (d:Document {id: $documentId})
            CREATE (d)-[:HAS_CHUNK {index: $index}]->(c)
            RETURN c.id as chunkId`,
            {
              id: chunk.id,
              index: chunk.index,
              content: chunk.content,
              sectionTitle: chunk.metadata.sectionTitle,
              chunkType: chunk.metadata.chunkType,
              startPage: chunk.metadata.startPage,
              endPage: chunk.metadata.endPage,
              documentId: document.id,
            }
          );

          const chunkNodeId = chunkResult.records[0].get('chunkId');

          // Create Citation nodes and relationships
          for (const citation of chunk.citations) {
            await tx.run(
              `CREATE (cit:Citation {
                id: $id,
                text: $text,
                authors: $authors,
                year: $year,
                title: $title,
                journal: $journal,
                doi: $doi,
                url: $url,
                type: $type,
                confidenceScore: $confidenceScore
              })
              WITH cit
              MATCH (c:Chunk {id: $chunkId})
              CREATE (c)-[:CITES]->(cit)`,
              {
                id: uuidv4(),
                text: citation.text,
                authors: citation.authors,
                year: citation.year,
                title: citation.title,
                journal: citation.journal,
                doi: citation.doi,
                url: citation.url,
                type: citation.type,
                confidenceScore: citation.confidenceScore,
                chunkId: chunk.id,
              }
            );
          }
        }

        // Create relationships between chunks
        await tx.run(
          `MATCH (c1:Chunk)-[:HAS_CHUNK]-(d:Document {id: $documentId})-[:HAS_CHUNK]-(c2:Chunk)
           WHERE c1.index = c2.index - 1
           CREATE (c1)-[:NEXT]->(c2)`,
          { documentId: document.id }
        );

        return documentNodeId;
      });

      return { nodeId: result };

    } finally {
      await session.close();
    }
  }

  /**
   * Create cross-database references
   */
  private async createCrossReferences(results: LoadingResult[]): Promise<void> {
    const client = await this.supabasePool.connect();

    try {
      await client.query('BEGIN');

      for (const result of results) {
        if (result.supabaseId && result.neo4jNodeId) {
          await client.query(
            `INSERT INTO cross_database_references (
              document_id, supabase_id, pinecone_namespace, 
              neo4j_node_id, created_at
            ) VALUES ($1, $2, $3, $4, $5)`,
            [
              result.documentId,
              result.supabaseId,
              this.config.pinecone.namespace || 'default',
              result.neo4jNodeId,
              new Date(),
            ]
          );
        }
      }

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error('Failed to create cross-database references:', error);
    } finally {
      client.release();
    }
  }

  /**
   * Rollback operations
   */
  private async rollbackSupabase(documentId: string): Promise<void> {
    const client = await this.supabasePool.connect();
    try {
      await client.query('DELETE FROM documents WHERE id = $1', [documentId]);
    } finally {
      client.release();
    }
  }

  private async rollbackPinecone(ids: string[]): Promise<void> {
    if (ids.length > 0) {
      const index = this.pinecone.index(this.config.pinecone.indexName);
      const namespace = this.config.pinecone.namespace || 'default';
      await index.namespace(namespace).deleteMany(ids);
    }
  }

  private async rollbackNeo4j(nodeId: string): Promise<void> {
    const session = this.neo4jDriver.session({
      database: this.config.neo4j.database,
    });

    try {
      await session.executeWrite(async (tx) => {
        await tx.run(
          `MATCH (d:Document {id: $nodeId})
           OPTIONAL MATCH (d)-[:HAS_CHUNK]->(c:Chunk)
           OPTIONAL MATCH (c)-[:CITES]->(cit:Citation)
           DETACH DELETE d, c, cit`,
          { nodeId }
        );
      });
    } finally {
      await session.close();
    }
  }

  /**
   * Batch processing utilities
   */
  private createBatches<T>(items: T[], batchSize: number): T[][] {
    const batches: T[][] = [];
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    return batches;
  }

  private getFailedDatabase(error: any): 'supabase' | 'pinecone' | 'neo4j' {
    // Simple heuristic to determine which database failed
    const errorStr = error.toString().toLowerCase();
    if (errorStr.includes('supabase') || errorStr.includes('postgres')) {
      return 'supabase';
    } else if (errorStr.includes('pinecone')) {
      return 'pinecone';
    } else if (errorStr.includes('neo4j') || errorStr.includes('cypher')) {
      return 'neo4j';
    }
    return 'supabase'; // Default
  }

  /**
   * Health check for all database connections
   */
  async healthCheck(): Promise<{
    supabase: boolean;
    pinecone: boolean;
    neo4j: boolean;
  }> {
    const results = {
      supabase: false,
      pinecone: false,
      neo4j: false,
    };

    // Check Supabase
    try {
      const client = await this.supabasePool.connect();
      await client.query('SELECT 1');
      client.release();
      results.supabase = true;
    } catch (error) {
      logger.error('Supabase health check failed:', error);
    }

    // Check Pinecone
    try {
      const index = this.pinecone.index(this.config.pinecone.indexName);
      await index.describeIndexStats();
      results.pinecone = true;
    } catch (error) {
      logger.error('Pinecone health check failed:', error);
    }

    // Check Neo4j
    try {
      const session = this.neo4jDriver.session();
      await session.run('RETURN 1');
      await session.close();
      results.neo4j = true;
    } catch (error) {
      logger.error('Neo4j health check failed:', error);
    }

    return results;
  }

  /**
   * Cleanup resources
   */
  async close(): Promise<void> {
    await this.supabasePool.end();
    await this.neo4jDriver.close();
  }
}