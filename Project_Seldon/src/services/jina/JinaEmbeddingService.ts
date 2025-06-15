/**
 * JinaEmbeddingService - High-Performance Embedding Generation
 * Project Seldon - Advanced Intelligence Architecture
 * Generated: June 13, 2025
 */

import {
  JinaEmbeddingRequest,
  JinaEmbeddingResponse,
  JinaAPIError,
  ChunkEmbedding,
  DocumentChunk,
  JINA_SERVICE_CONFIGS
} from '../../types/jina';
import { JinaRateLimiter } from './JinaRateLimiter';

export class JinaEmbeddingService {
  private rateLimiter: JinaRateLimiter;
  private apiKey: string;
  private config = JINA_SERVICE_CONFIGS.embedding;
  private logger: Console;

  constructor(
    rateLimiter: JinaRateLimiter,
    apiKey: string,
    logger: Console = console
  ) {
    this.rateLimiter = rateLimiter;
    this.apiKey = apiKey;
    this.logger = logger;
  }

  /**
   * Generate embeddings for a single text input
   */
  async generateEmbedding(
    text: string,
    options: {
      model?: string;
      dimensions?: number;
      task?: string;
      encoding_format?: 'float' | 'base64';
    } = {}
  ): Promise<number[]> {
    const request: JinaEmbeddingRequest = {
      model: options.model || this.config.model,
      input: text,
      dimensions: options.dimensions || this.config.dimensions,
      encoding_format: options.encoding_format || 'float',
      task: options.task
    };

    const response = await this.rateLimiter.processWithLimit(
      'embedding',
      () => this.makeEmbeddingRequest(request),
      {
        metadata: {
          textLength: text.length,
          model: request.model,
          dimensions: request.dimensions
        }
      }
    );

    return response.data[0].embedding;
  }

  /**
   * Generate embeddings for multiple text inputs in batch
   */
  async generateBatchEmbeddings(
    texts: string[],
    options: {
      model?: string;
      dimensions?: number;
      task?: string;
      encoding_format?: 'float' | 'base64';
      batchSize?: number;
    } = {}
  ): Promise<number[][]> {
    const batchSize = options.batchSize || 10; // Process in smaller batches to avoid token limits
    const embeddings: number[][] = [];

    this.logger.log(`Generating embeddings for ${texts.length} texts in batches of ${batchSize}`);

    for (let i = 0; i < texts.length; i += batchSize) {
      const batch = texts.slice(i, i + batchSize);
      
      const request: JinaEmbeddingRequest = {
        model: options.model || this.config.model,
        input: batch,
        dimensions: options.dimensions || this.config.dimensions,
        encoding_format: options.encoding_format || 'float',
        task: options.task
      };

      const response = await this.rateLimiter.processWithLimit(
        'embedding',
        () => this.makeEmbeddingRequest(request),
        {
          metadata: {
            batchIndex: Math.floor(i / batchSize),
            batchSize: batch.length,
            totalTexts: texts.length,
            averageTextLength: Math.round(batch.reduce((sum, text) => sum + text.length, 0) / batch.length)
          }
        }
      );

      embeddings.push(...response.data.map(item => item.embedding));
      
      this.logger.log(`Processed batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(texts.length / batchSize)}`);
    }

    return embeddings;
  }

  /**
   * Generate embeddings for document chunks with full metadata
   */
  async generateChunkEmbeddings(
    chunks: DocumentChunk[],
    options: {
      model?: string;
      dimensions?: number;
      task?: string;
      batchSize?: number;
    } = {}
  ): Promise<ChunkEmbedding[]> {
    this.logger.log(`Generating embeddings for ${chunks.length} document chunks`);

    const texts = chunks.map(chunk => chunk.content);
    const embeddings = await this.generateBatchEmbeddings(texts, options);

    return chunks.map((chunk, index): ChunkEmbedding => ({
      chunk_id: chunk.chunk_id,
      embedding: embeddings[index],
      dimension_count: options.dimensions || this.config.dimensions,
      generated_at: new Date().toISOString()
    }));
  }

  /**
   * Generate query embeddings optimized for similarity search
   */
  async generateQueryEmbedding(
    query: string,
    options: {
      model?: string;
      dimensions?: number;
    } = {}
  ): Promise<number[]> {
    return this.generateEmbedding(query, {
      ...options,
      task: 'search_query'
    });
  }

  /**
   * Generate document embeddings optimized for storage and retrieval
   */
  async generateDocumentEmbedding(
    text: string,
    options: {
      model?: string;
      dimensions?: number;
    } = {}
  ): Promise<number[]> {
    return this.generateEmbedding(text, {
      ...options,
      task: 'search_document'
    });
  }

  /**
   * Calculate similarity between two embeddings
   */
  calculateCosineSimilarity(embedding1: number[], embedding2: number[]): number {
    if (embedding1.length !== embedding2.length) {
      throw new Error('Embeddings must have the same dimension');
    }

    let dotProduct = 0;
    let norm1 = 0;
    let norm2 = 0;

    for (let i = 0; i < embedding1.length; i++) {
      dotProduct += embedding1[i] * embedding2[i];
      norm1 += embedding1[i] * embedding1[i];
      norm2 += embedding2[i] * embedding2[i];
    }

    return dotProduct / (Math.sqrt(norm1) * Math.sqrt(norm2));
  }

  /**
   * Find most similar embeddings from a set
   */
  findMostSimilar(
    queryEmbedding: number[],
    candidateEmbeddings: Array<{ id: string; embedding: number[] }>,
    topK: number = 10
  ): Array<{ id: string; similarity: number }> {
    const similarities = candidateEmbeddings.map(candidate => ({
      id: candidate.id,
      similarity: this.calculateCosineSimilarity(queryEmbedding, candidate.embedding)
    }));

    return similarities
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, topK);
  }

  /**
   * Validate embedding dimensions
   */
  validateEmbedding(embedding: number[], expectedDimensions?: number): boolean {
    const dims = expectedDimensions || this.config.dimensions;
    
    if (embedding.length !== dims) {
      this.logger.warn(`Embedding dimension mismatch: expected ${dims}, got ${embedding.length}`);
      return false;
    }

    // Check for NaN or infinite values
    const hasInvalidValues = embedding.some(value => !isFinite(value));
    if (hasInvalidValues) {
      this.logger.warn('Embedding contains NaN or infinite values');
      return false;
    }

    return true;
  }

  /**
   * Normalize embedding vector to unit length
   */
  normalizeEmbedding(embedding: number[]): number[] {
    const norm = Math.sqrt(embedding.reduce((sum, val) => sum + val * val, 0));
    
    if (norm === 0) {
      this.logger.warn('Cannot normalize zero vector');
      return embedding;
    }

    return embedding.map(val => val / norm);
  }

  /**
   * Get embedding statistics
   */
  getEmbeddingStats(embedding: number[]): {
    mean: number;
    std: number;
    min: number;
    max: number;
    norm: number;
  } {
    const mean = embedding.reduce((sum, val) => sum + val, 0) / embedding.length;
    const variance = embedding.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / embedding.length;
    const std = Math.sqrt(variance);
    const min = Math.min(...embedding);
    const max = Math.max(...embedding);
    const norm = Math.sqrt(embedding.reduce((sum, val) => sum + val * val, 0));

    return { mean, std, min, max, norm };
  }

  /**
   * Make HTTP request to Jina Embedding API
   */
  private async makeEmbeddingRequest(request: JinaEmbeddingRequest): Promise<JinaEmbeddingResponse> {
    const startTime = Date.now();

    try {
      const response = await fetch(this.config.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
          'User-Agent': 'Project-Seldon/1.0'
        },
        body: JSON.stringify(request)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new JinaAPIError(data);
      }

      const processingTime = Date.now() - startTime;
      this.logger.log(`Embedding request completed in ${processingTime}ms`);

      // Validate response structure
      if (!data.data || !Array.isArray(data.data)) {
        throw new Error('Invalid embedding response structure');
      }

      // Validate embeddings
      for (const item of data.data) {
        if (!this.validateEmbedding(item.embedding, request.dimensions)) {
          throw new Error(`Invalid embedding at index ${item.index}`);
        }
      }

      return data;
    } catch (error) {
      const processingTime = Date.now() - startTime;
      this.logger.error(`Embedding request failed after ${processingTime}ms:`, error);
      throw error;
    }
  }

  /**
   * Get service configuration
   */
  getConfig() {
    return {
      ...this.config,
      apiKeyConfigured: !!this.apiKey
    };
  }

  /**
   * Test service connectivity
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.generateEmbedding('test connection', { dimensions: 768 });
      this.logger.log('Jina Embedding Service connection test successful');
      return true;
    } catch (error) {
      this.logger.error('Jina Embedding Service connection test failed:', error);
      return false;
    }
  }
}