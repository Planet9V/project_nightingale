/**
 * JinaRerankingService - Advanced Relevance Scoring and Ranking
 * Project Seldon - Advanced Intelligence Architecture
 * Generated: June 13, 2025
 */

import {
  JinaRerankingRequest,
  JinaRerankingResponse,
  JinaAPIError,
  DocumentChunk,
  JINA_SERVICE_CONFIGS
} from '../../types/jina';
import { JinaRateLimiter } from './JinaRateLimiter';

export interface RerankResult {
  document_index: number;
  relevance_score: number;
  document?: {
    text: string;
  };
}

export interface ChunkRerankResult {
  chunk_id: string;
  relevance_score: number;
  chunk: DocumentChunk;
  rank: number;
}

export class JinaRerankingService {
  private rateLimiter: JinaRateLimiter;
  private apiKey: string;
  private config = JINA_SERVICE_CONFIGS.reranking;
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
   * Rerank documents based on query relevance
   */
  async rerankDocuments(
    query: string,
    documents: string[],
    options: {
      model?: string;
      top_k?: number;
      return_documents?: boolean;
    } = {}
  ): Promise<RerankResult[]> {
    if (documents.length === 0) {
      return [];
    }

    const request: JinaRerankingRequest = {
      model: options.model || this.config.model,
      query,
      documents,
      top_k: options.top_k,
      return_documents: options.return_documents ?? true
    };

    const response = await this.rateLimiter.processWithLimit(
      'reranking',
      () => this.makeRerankingRequest(request),
      {
        metadata: {
          queryLength: query.length,
          documentCount: documents.length,
          averageDocLength: Math.round(documents.reduce((sum, doc) => sum + doc.length, 0) / documents.length),
          topK: options.top_k || documents.length
        }
      }
    );

    return response.data.map(item => ({
      document_index: item.index,
      relevance_score: item.relevance_score,
      document: item.document
    }));
  }

  /**
   * Rerank document chunks with full metadata preservation
   */
  async rerankChunks(
    query: string,
    chunks: DocumentChunk[],
    options: {
      model?: string;
      top_k?: number;
      scoreThreshold?: number;
    } = {}
  ): Promise<ChunkRerankResult[]> {
    if (chunks.length === 0) {
      return [];
    }

    this.logger.log(`Reranking ${chunks.length} chunks for query: "${query.substring(0, 100)}..."`);

    const documents = chunks.map(chunk => chunk.content);
    const rerankResults = await this.rerankDocuments(query, documents, {
      model: options.model,
      top_k: options.top_k,
      return_documents: false // We already have the chunks
    });

    // Combine rerank results with original chunk metadata
    const results: ChunkRerankResult[] = rerankResults
      .map((result, rank) => ({
        chunk_id: chunks[result.document_index].chunk_id,
        relevance_score: result.relevance_score,
        chunk: chunks[result.document_index],
        rank: rank + 1
      }))
      .filter(result => !options.scoreThreshold || result.relevance_score >= options.scoreThreshold);

    this.logger.log(`Reranking completed: ${results.length} chunks above threshold (${options.scoreThreshold || 0})`);

    return results;
  }

  /**
   * Rerank chunks in batches for large datasets
   */
  async rerankChunksBatch(
    query: string,
    chunks: DocumentChunk[],
    options: {
      model?: string;
      top_k?: number;
      scoreThreshold?: number;
      batchSize?: number;
      globalTopK?: number;
    } = {}
  ): Promise<ChunkRerankResult[]> {
    const batchSize = options.batchSize || 50; // Jina reranking API limit
    const globalTopK = options.globalTopK || options.top_k;
    
    if (chunks.length <= batchSize) {
      return this.rerankChunks(query, chunks, options);
    }

    this.logger.log(`Processing ${chunks.length} chunks in batches of ${batchSize}`);

    const allResults: ChunkRerankResult[] = [];

    // Process in batches
    for (let i = 0; i < chunks.length; i += batchSize) {
      const batch = chunks.slice(i, i + batchSize);
      
      const batchResults = await this.rerankChunks(query, batch, {
        model: options.model,
        top_k: Math.min(batchSize, options.top_k || batchSize),
        scoreThreshold: options.scoreThreshold
      });

      allResults.push(...batchResults);
      
      this.logger.log(`Processed batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(chunks.length / batchSize)}`);
    }

    // Global reranking of top results from all batches
    if (globalTopK && allResults.length > globalTopK) {
      this.logger.log(`Performing global reranking of top ${globalTopK} results`);
      
      // Sort by current scores and take top candidates
      const topCandidates = allResults
        .sort((a, b) => b.relevance_score - a.relevance_score)
        .slice(0, Math.min(batchSize, allResults.length)); // Respect API limits

      const globalResults = await this.rerankChunks(
        query,
        topCandidates.map(r => r.chunk),
        {
          model: options.model,
          top_k: globalTopK,
          scoreThreshold: options.scoreThreshold
        }
      );

      return globalResults;
    }

    // Sort final results by relevance score
    return allResults
      .sort((a, b) => b.relevance_score - a.relevance_score)
      .slice(0, globalTopK)
      .map((result, index) => ({
        ...result,
        rank: index + 1
      }));
  }

  /**
   * Get relevance scores for documents without reordering
   */
  async getRelevanceScores(
    query: string,
    documents: string[],
    options: {
      model?: string;
    } = {}
  ): Promise<number[]> {
    const results = await this.rerankDocuments(query, documents, {
      model: options.model,
      return_documents: false
    });

    // Create array with scores in original order
    const scores = new Array(documents.length).fill(0);
    results.forEach(result => {
      scores[result.document_index] = result.relevance_score;
    });

    return scores;
  }

  /**
   * Compare relevance of two documents for a query
   */
  async compareDocuments(
    query: string,
    document1: string,
    document2: string,
    options: {
      model?: string;
    } = {}
  ): Promise<{
    document1_score: number;
    document2_score: number;
    preferred_document: 1 | 2;
    score_difference: number;
  }> {
    const results = await this.rerankDocuments(query, [document1, document2], {
      model: options.model,
      return_documents: false
    });

    const scores = [0, 0];
    results.forEach(result => {
      scores[result.document_index] = result.relevance_score;
    });

    return {
      document1_score: scores[0],
      document2_score: scores[1],
      preferred_document: scores[0] > scores[1] ? 1 : 2,
      score_difference: Math.abs(scores[0] - scores[1])
    };
  }

  /**
   * Find best matching chunks for multiple queries
   */
  async multiQueryRerank(
    queries: string[],
    chunks: DocumentChunk[],
    options: {
      model?: string;
      top_k_per_query?: number;
      scoreThreshold?: number;
      deduplicate?: boolean;
    } = {}
  ): Promise<Record<string, ChunkRerankResult[]>> {
    const results: Record<string, ChunkRerankResult[]> = {};
    const seenChunkIds = new Set<string>();

    for (const query of queries) {
      const queryResults = await this.rerankChunks(query, chunks, {
        model: options.model,
        top_k: options.top_k_per_query,
        scoreThreshold: options.scoreThreshold
      });

      if (options.deduplicate) {
        // Remove chunks already seen in previous queries
        const uniqueResults = queryResults.filter(result => {
          if (seenChunkIds.has(result.chunk_id)) {
            return false;
          }
          seenChunkIds.add(result.chunk_id);
          return true;
        });
        results[query] = uniqueResults;
      } else {
        results[query] = queryResults;
      }
    }

    return results;
  }

  /**
   * Calculate relevance distribution statistics
   */
  calculateRelevanceStats(results: RerankResult[] | ChunkRerankResult[]): {
    mean: number;
    median: number;
    std: number;
    min: number;
    max: number;
    q25: number;
    q75: number;
  } {
    const scores = results.map(r => r.relevance_score).sort((a, b) => a - b);
    
    if (scores.length === 0) {
      return { mean: 0, median: 0, std: 0, min: 0, max: 0, q25: 0, q75: 0 };
    }

    const mean = scores.reduce((sum, score) => sum + score, 0) / scores.length;
    const median = scores[Math.floor(scores.length / 2)];
    const variance = scores.reduce((sum, score) => sum + Math.pow(score - mean, 2), 0) / scores.length;
    const std = Math.sqrt(variance);
    const min = scores[0];
    const max = scores[scores.length - 1];
    const q25 = scores[Math.floor(scores.length * 0.25)];
    const q75 = scores[Math.floor(scores.length * 0.75)];

    return { mean, median, std, min, max, q25, q75 };
  }

  /**
   * Filter chunks by relevance threshold with statistics
   */
  filterByRelevance(
    results: ChunkRerankResult[],
    threshold: number
  ): {
    filtered: ChunkRerankResult[];
    statistics: {
      total: number;
      passed: number;
      failed: number;
      passRate: number;
    };
  } {
    const filtered = results.filter(result => result.relevance_score >= threshold);
    
    return {
      filtered,
      statistics: {
        total: results.length,
        passed: filtered.length,
        failed: results.length - filtered.length,
        passRate: results.length > 0 ? filtered.length / results.length : 0
      }
    };
  }

  /**
   * Make HTTP request to Jina Reranking API
   */
  private async makeRerankingRequest(request: JinaRerankingRequest): Promise<JinaRerankingResponse> {
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
      this.logger.log(`Reranking request completed in ${processingTime}ms`);

      // Validate response structure
      if (!data.data || !Array.isArray(data.data)) {
        throw new Error('Invalid reranking response structure');
      }

      return data;
    } catch (error) {
      const processingTime = Date.now() - startTime;
      this.logger.error(`Reranking request failed after ${processingTime}ms:`, error);
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
      await this.rerankDocuments('test query', ['test document 1', 'test document 2'], {
        top_k: 2,
        return_documents: false
      });
      this.logger.log('Jina Reranking Service connection test successful');
      return true;
    } catch (error) {
      this.logger.error('Jina Reranking Service connection test failed:', error);
      return false;
    }
  }
}