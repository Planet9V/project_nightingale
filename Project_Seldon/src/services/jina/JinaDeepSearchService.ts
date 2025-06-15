/**
 * JinaDeepSearchService - Advanced Semantic Search and Discovery
 * Project Seldon - Advanced Intelligence Architecture
 * Generated: June 13, 2025
 */

import {
  JinaDeepSearchRequest,
  JinaDeepSearchResponse,
  JinaAPIError,
  DocumentChunk,
  JINA_SERVICE_CONFIGS
} from '../../types/jina';
import { JinaRateLimiter } from './JinaRateLimiter';

export interface SearchResult {
  document_index: number;
  relevance_score: number;
  snippet: string;
  document: {
    text: string;
    metadata?: Record<string, any>;
  };
}

export interface ChunkSearchResult {
  chunk_id: string;
  relevance_score: number;
  snippet: string;
  chunk: DocumentChunk;
  rank: number;
}

export interface MultiQuerySearchResult {
  query: string;
  results: ChunkSearchResult[];
  total_results: number;
  search_time_ms: number;
}

export interface SearchAnalytics {
  total_queries: number;
  total_documents_searched: number;
  average_results_per_query: number;
  average_relevance_score: number;
  search_time_stats: {
    min: number;
    max: number;
    average: number;
  };
}

export class JinaDeepSearchService {
  private rateLimiter: JinaRateLimiter;
  private apiKey: string;
  private config = JINA_SERVICE_CONFIGS.deepSearch;
  private logger: Console;
  private searchAnalytics: SearchAnalytics;

  constructor(
    rateLimiter: JinaRateLimiter,
    apiKey: string,
    logger: Console = console
  ) {
    this.rateLimiter = rateLimiter;
    this.apiKey = apiKey;
    this.logger = logger;
    this.initializeAnalytics();
  }

  /**
   * Initialize search analytics tracking
   */
  private initializeAnalytics(): void {
    this.searchAnalytics = {
      total_queries: 0,
      total_documents_searched: 0,
      average_results_per_query: 0,
      average_relevance_score: 0,
      search_time_stats: {
        min: 0,
        max: 0,
        average: 0
      }
    };
  }

  /**
   * Perform deep semantic search on documents
   */
  async searchDocuments(
    query: string,
    documents: string[],
    options: {
      model?: string;
      top_k?: number;
      search_depth?: 'basic' | 'advanced';
      relevance_threshold?: number;
    } = {}
  ): Promise<SearchResult[]> {
    if (documents.length === 0) {
      return [];
    }

    const startTime = Date.now();

    const request: JinaDeepSearchRequest = {
      model: options.model || this.config.model,
      query,
      documents,
      top_k: options.top_k,
      search_depth: options.search_depth || 'basic'
    };

    const response = await this.rateLimiter.processWithLimit(
      'deepSearch',
      () => this.makeDeepSearchRequest(request),
      {
        metadata: {
          queryLength: query.length,
          documentCount: documents.length,
          averageDocLength: Math.round(documents.reduce((sum, doc) => sum + doc.length, 0) / documents.length),
          searchDepth: options.search_depth || 'basic',
          topK: options.top_k || documents.length
        }
      }
    );

    const searchTime = Date.now() - startTime;
    
    const results = response.data
      .filter(item => !options.relevance_threshold || item.relevance_score >= options.relevance_threshold)
      .map(item => ({
        document_index: item.index,
        relevance_score: item.relevance_score,
        snippet: item.snippet,
        document: item.document
      }));

    this.updateAnalytics(query, documents.length, results.length, searchTime, results);

    return results;
  }

  /**
   * Search through document chunks with full metadata preservation
   */
  async searchChunks(
    query: string,
    chunks: DocumentChunk[],
    options: {
      model?: string;
      top_k?: number;
      search_depth?: 'basic' | 'advanced';
      relevance_threshold?: number;
      include_metadata?: boolean;
    } = {}
  ): Promise<ChunkSearchResult[]> {
    if (chunks.length === 0) {
      return [];
    }

    this.logger.log(`Searching ${chunks.length} chunks for query: "${query.substring(0, 100)}..."`);

    const documents = chunks.map(chunk => chunk.content);
    const searchResults = await this.searchDocuments(query, documents, {
      model: options.model,
      top_k: options.top_k,
      search_depth: options.search_depth,
      relevance_threshold: options.relevance_threshold
    });

    // Combine search results with original chunk metadata
    const results: ChunkSearchResult[] = searchResults
      .map((result, rank) => ({
        chunk_id: chunks[result.document_index].chunk_id,
        relevance_score: result.relevance_score,
        snippet: result.snippet,
        chunk: chunks[result.document_index],
        rank: rank + 1
      }));

    this.logger.log(`Search completed: ${results.length} relevant chunks found`);

    return results;
  }

  /**
   * Search chunks in batches for large datasets
   */
  async searchChunksBatch(
    query: string,
    chunks: DocumentChunk[],
    options: {
      model?: string;
      top_k?: number;
      search_depth?: 'basic' | 'advanced';
      relevance_threshold?: number;
      batchSize?: number;
      globalTopK?: number;
    } = {}
  ): Promise<ChunkSearchResult[]> {
    const batchSize = options.batchSize || 50; // Jina search API limit
    const globalTopK = options.globalTopK || options.top_k;
    
    if (chunks.length <= batchSize) {
      return this.searchChunks(query, chunks, options);
    }

    this.logger.log(`Searching ${chunks.length} chunks in batches of ${batchSize}`);

    const allResults: ChunkSearchResult[] = [];

    // Process in batches
    for (let i = 0; i < chunks.length; i += batchSize) {
      const batch = chunks.slice(i, i + batchSize);
      
      const batchResults = await this.searchChunks(query, batch, {
        model: options.model,
        top_k: Math.min(batchSize, options.top_k || batchSize),
        search_depth: options.search_depth,
        relevance_threshold: options.relevance_threshold
      });

      allResults.push(...batchResults);
      
      this.logger.log(`Processed batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(chunks.length / batchSize)}`);
    }

    // Sort final results by relevance score and apply global top_k
    const finalResults = allResults
      .sort((a, b) => b.relevance_score - a.relevance_score)
      .slice(0, globalTopK)
      .map((result, index) => ({
        ...result,
        rank: index + 1
      }));

    return finalResults;
  }

  /**
   * Perform multiple searches with different queries
   */
  async multiQuerySearch(
    queries: string[],
    chunks: DocumentChunk[],
    options: {
      model?: string;
      top_k_per_query?: number;
      search_depth?: 'basic' | 'advanced';
      relevance_threshold?: number;
      deduplicate?: boolean;
      batchSize?: number;
    } = {}
  ): Promise<MultiQuerySearchResult[]> {
    const results: MultiQuerySearchResult[] = [];
    const seenChunkIds = new Set<string>();

    for (const query of queries) {
      const startTime = Date.now();
      
      let queryResults = await this.searchChunks(query, chunks, {
        model: options.model,
        top_k: options.top_k_per_query,
        search_depth: options.search_depth,
        relevance_threshold: options.relevance_threshold
      });

      if (options.deduplicate) {
        // Remove chunks already seen in previous queries
        queryResults = queryResults.filter(result => {
          if (seenChunkIds.has(result.chunk_id)) {
            return false;
          }
          seenChunkIds.add(result.chunk_id);
          return true;
        });
      }

      const searchTime = Date.now() - startTime;
      
      results.push({
        query,
        results: queryResults,
        total_results: queryResults.length,
        search_time_ms: searchTime
      });

      this.logger.log(`Query "${query.substring(0, 50)}..." completed: ${queryResults.length} results in ${searchTime}ms`);
    }

    return results;
  }

  /**
   * Advanced semantic search with query expansion
   */
  async expandedSearch(
    originalQuery: string,
    chunks: DocumentChunk[],
    options: {
      model?: string;
      top_k?: number;
      search_depth?: 'basic' | 'advanced';
      relevance_threshold?: number;
      expansion_terms?: string[];
      combine_results?: boolean;
    } = {}
  ): Promise<{
    original_results: ChunkSearchResult[];
    expanded_results: Record<string, ChunkSearchResult[]>;
    combined_results?: ChunkSearchResult[];
  }> {
    // Search with original query
    const originalResults = await this.searchChunks(originalQuery, chunks, options);

    // Search with expanded terms
    const expandedResults: Record<string, ChunkSearchResult[]> = {};
    const expansionTerms = options.expansion_terms || this.generateExpansionTerms(originalQuery);

    for (const term of expansionTerms) {
      const expandedQuery = `${originalQuery} ${term}`;
      expandedResults[term] = await this.searchChunks(expandedQuery, chunks, {
        ...options,
        top_k: Math.min(options.top_k || 10, 5) // Smaller top_k for expansion
      });
    }

    let combinedResults: ChunkSearchResult[] | undefined;
    
    if (options.combine_results) {
      // Combine and deduplicate results
      const allResults = new Map<string, ChunkSearchResult>();
      
      // Add original results with full weight
      originalResults.forEach(result => {
        allResults.set(result.chunk_id, result);
      });
      
      // Add expanded results with reduced weight
      Object.values(expandedResults).forEach(results => {
        results.forEach(result => {
          const existing = allResults.get(result.chunk_id);
          if (existing) {
            // Combine scores (weighted average)
            existing.relevance_score = (existing.relevance_score * 0.7) + (result.relevance_score * 0.3);
          } else {
            // New result with reduced score
            allResults.set(result.chunk_id, {
              ...result,
              relevance_score: result.relevance_score * 0.6
            });
          }
        });
      });
      
      combinedResults = Array.from(allResults.values())
        .sort((a, b) => b.relevance_score - a.relevance_score)
        .slice(0, options.top_k || 10)
        .map((result, index) => ({
          ...result,
          rank: index + 1
        }));
    }

    return {
      original_results: originalResults,
      expanded_results: expandedResults,
      combined_results: combinedResults
    };
  }

  /**
   * Find similar chunks to a given chunk
   */
  async findSimilarChunks(
    referenceChunk: DocumentChunk,
    candidateChunks: DocumentChunk[],
    options: {
      model?: string;
      top_k?: number;
      search_depth?: 'basic' | 'advanced';
      relevance_threshold?: number;
      exclude_self?: boolean;
    } = {}
  ): Promise<ChunkSearchResult[]> {
    let chunks = candidateChunks;
    
    if (options.exclude_self) {
      chunks = candidateChunks.filter(chunk => chunk.chunk_id !== referenceChunk.chunk_id);
    }

    // Use the reference chunk content as the search query
    const query = referenceChunk.content.substring(0, 1000); // Limit query length
    
    return this.searchChunks(query, chunks, {
      model: options.model,
      top_k: options.top_k,
      search_depth: options.search_depth,
      relevance_threshold: options.relevance_threshold
    });
  }

  /**
   * Search with advanced filtering and faceting
   */
  async searchWithFilters(
    query: string,
    chunks: DocumentChunk[],
    filters: {
      document_types?: string[];
      min_token_count?: number;
      max_token_count?: number;
      section_indices?: number[];
      s3_key_patterns?: string[];
    },
    options: {
      model?: string;
      top_k?: number;
      search_depth?: 'basic' | 'advanced';
      relevance_threshold?: number;
    } = {}
  ): Promise<{
    results: ChunkSearchResult[];
    filtered_count: number;
    original_count: number;
    filter_stats: Record<string, number>;
  }> {
    const originalCount = chunks.length;
    
    // Apply filters
    let filteredChunks = chunks;
    const filterStats: Record<string, number> = {};

    if (filters.min_token_count !== undefined) {
      filteredChunks = filteredChunks.filter(chunk => chunk.token_count >= filters.min_token_count!);
      filterStats.min_token_filter = filteredChunks.length;
    }

    if (filters.max_token_count !== undefined) {
      filteredChunks = filteredChunks.filter(chunk => chunk.token_count <= filters.max_token_count!);
      filterStats.max_token_filter = filteredChunks.length;
    }

    if (filters.section_indices?.length) {
      filteredChunks = filteredChunks.filter(chunk => 
        filters.section_indices!.includes(chunk.citation.section_index)
      );
      filterStats.section_filter = filteredChunks.length;
    }

    if (filters.s3_key_patterns?.length) {
      filteredChunks = filteredChunks.filter(chunk =>
        filters.s3_key_patterns!.some(pattern => chunk.citation.s3_key.includes(pattern))
      );
      filterStats.s3_key_filter = filteredChunks.length;
    }

    const results = await this.searchChunks(query, filteredChunks, options);

    return {
      results,
      filtered_count: filteredChunks.length,
      original_count,
      filter_stats: filterStats
    };
  }

  /**
   * Generate expansion terms for query expansion
   */
  private generateExpansionTerms(query: string): string[] {
    // Simple expansion terms based on cybersecurity context
    const cybersecurityTerms = [
      'security', 'threat', 'vulnerability', 'attack', 'malware',
      'incident', 'breach', 'risk', 'compliance', 'audit'
    ];
    
    const queryLower = query.toLowerCase();
    return cybersecurityTerms.filter(term => !queryLower.includes(term)).slice(0, 3);
  }

  /**
   * Update search analytics
   */
  private updateAnalytics(
    query: string,
    documentCount: number,
    resultCount: number,
    searchTime: number,
    results: SearchResult[]
  ): void {
    this.searchAnalytics.total_queries++;
    this.searchAnalytics.total_documents_searched += documentCount;
    
    // Update average results per query
    const totalResults = (this.searchAnalytics.average_results_per_query * (this.searchAnalytics.total_queries - 1)) + resultCount;
    this.searchAnalytics.average_results_per_query = totalResults / this.searchAnalytics.total_queries;
    
    // Update average relevance score
    if (results.length > 0) {
      const avgRelevance = results.reduce((sum, r) => sum + r.relevance_score, 0) / results.length;
      const totalRelevance = (this.searchAnalytics.average_relevance_score * (this.searchAnalytics.total_queries - 1)) + avgRelevance;
      this.searchAnalytics.average_relevance_score = totalRelevance / this.searchAnalytics.total_queries;
    }
    
    // Update search time stats
    if (this.searchAnalytics.total_queries === 1) {
      this.searchAnalytics.search_time_stats.min = searchTime;
      this.searchAnalytics.search_time_stats.max = searchTime;
      this.searchAnalytics.search_time_stats.average = searchTime;
    } else {
      this.searchAnalytics.search_time_stats.min = Math.min(this.searchAnalytics.search_time_stats.min, searchTime);
      this.searchAnalytics.search_time_stats.max = Math.max(this.searchAnalytics.search_time_stats.max, searchTime);
      
      const totalTime = (this.searchAnalytics.search_time_stats.average * (this.searchAnalytics.total_queries - 1)) + searchTime;
      this.searchAnalytics.search_time_stats.average = totalTime / this.searchAnalytics.total_queries;
    }
  }

  /**
   * Get search analytics
   */
  getAnalytics(): SearchAnalytics {
    return { ...this.searchAnalytics };
  }

  /**
   * Reset search analytics
   */
  resetAnalytics(): void {
    this.initializeAnalytics();
  }

  /**
   * Make HTTP request to Jina Deep Search API
   */
  private async makeDeepSearchRequest(request: JinaDeepSearchRequest): Promise<JinaDeepSearchResponse> {
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
      this.logger.log(`Deep search request completed in ${processingTime}ms`);

      // Validate response structure
      if (!data.data || !Array.isArray(data.data)) {
        throw new Error('Invalid deep search response structure');
      }

      return data;
    } catch (error) {
      const processingTime = Date.now() - startTime;
      this.logger.error(`Deep search request failed after ${processingTime}ms:`, error);
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
      await this.searchDocuments('test query', ['test document 1', 'test document 2'], {
        top_k: 2,
        search_depth: 'basic'
      });
      this.logger.log('Jina Deep Search Service connection test successful');
      return true;
    } catch (error) {
      this.logger.error('Jina Deep Search Service connection test failed:', error);
      return false;
    }
  }
}