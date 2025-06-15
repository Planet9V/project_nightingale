import { PineconeService } from '../pinecone/PineconeService';
import { SupabaseService } from '../database/SupabaseService';
import { S3DocumentService } from '../s3/S3DocumentService';
import { Redis } from 'ioredis';
import { logger } from '../../utils/logger';
import { 
  Citation,
  CitationLookupOptions,
  CitationSource,
  DocumentChunk,
  VectorMetadata,
  CitationCache
} from '../../types';

export class CitationLookupService {
  private pineconeService: PineconeService;
  private supabaseService: SupabaseService;
  private s3Service: S3DocumentService;
  private redis: Redis;
  private cachePrefix = 'citation:';
  private cacheTTL = 3600; // 1 hour

  constructor(
    pineconeService: PineconeService,
    supabaseService: SupabaseService,
    s3Service: S3DocumentService,
    redis: Redis
  ) {
    this.pineconeService = pineconeService;
    this.supabaseService = supabaseService;
    this.s3Service = s3Service;
    this.redis = redis;
  }

  /**
   * Lookup citation by vector ID
   */
  async lookupByVectorId(
    vectorId: string,
    options: CitationLookupOptions = {}
  ): Promise<Citation | null> {
    try {
      // Check cache first
      const cached = await this.getCachedCitation(vectorId);
      if (cached && !options.bypassCache) {
        return cached;
      }

      // Fetch vector metadata from Pinecone
      const vectorData = await this.pineconeService.fetchVector(vectorId);
      if (!vectorData || !vectorData.metadata) {
        logger.warn(`No vector found for ID: ${vectorId}`);
        return null;
      }

      const metadata = vectorData.metadata as VectorMetadata;
      
      // Resolve to full citation
      const citation = await this.resolveVectorToCitation(metadata, options);
      
      // Cache the result
      if (citation) {
        await this.cacheCitation(vectorId, citation);
      }

      return citation;
    } catch (error) {
      logger.error('Error looking up citation by vector ID:', error);
      throw error;
    }
  }

  /**
   * Lookup citation by chunk ID
   */
  async lookupByChunkId(
    chunkId: string,
    options: CitationLookupOptions = {}
  ): Promise<Citation | null> {
    try {
      // Check cache
      const cacheKey = `chunk:${chunkId}`;
      const cached = await this.getCachedCitation(cacheKey);
      if (cached && !options.bypassCache) {
        return cached;
      }

      // Query Supabase for chunk metadata
      const { data: chunk, error } = await this.supabaseService.client
        .from('document_chunks')
        .select(`
          *,
          documents:document_id (
            id,
            title,
            type,
            source_url,
            s3_key,
            metadata
          )
        `)
        .eq('id', chunkId)
        .single();

      if (error || !chunk) {
        logger.warn(`No chunk found for ID: ${chunkId}`);
        return null;
      }

      // Build citation from chunk data
      const citation = await this.buildCitationFromChunk(chunk, options);
      
      // Cache the result
      if (citation) {
        await this.cacheCitation(cacheKey, citation);
      }

      return citation;
    } catch (error) {
      logger.error('Error looking up citation by chunk ID:', error);
      throw error;
    }
  }

  /**
   * Lookup multiple citations in batch
   */
  async lookupBatch(
    ids: string[],
    idType: 'vector' | 'chunk' | 'citation' = 'vector',
    options: CitationLookupOptions = {}
  ): Promise<Map<string, Citation>> {
    const results = new Map<string, Citation>();
    
    try {
      // Process in parallel with rate limiting
      const batchSize = 10;
      for (let i = 0; i < ids.length; i += batchSize) {
        const batch = ids.slice(i, i + batchSize);
        const promises = batch.map(async (id) => {
          let citation: Citation | null = null;
          
          switch (idType) {
            case 'vector':
              citation = await this.lookupByVectorId(id, options);
              break;
            case 'chunk':
              citation = await this.lookupByChunkId(id, options);
              break;
            case 'citation':
              citation = await this.lookupByCitationId(id, options);
              break;
          }
          
          if (citation) {
            results.set(id, citation);
          }
        });
        
        await Promise.all(promises);
      }
      
      return results;
    } catch (error) {
      logger.error('Error in batch citation lookup:', error);
      throw error;
    }
  }

  /**
   * Extract exact text from source document
   */
  async extractSourceText(
    s3Key: string,
    startChar: number,
    endChar: number
  ): Promise<string> {
    try {
      // Download document from S3
      const document = await this.s3Service.downloadDocument(s3Key);
      
      // Extract text based on document type
      let fullText: string;
      const fileType = s3Key.split('.').pop()?.toLowerCase();
      
      switch (fileType) {
        case 'txt':
        case 'md':
          fullText = document.toString('utf-8');
          break;
        case 'pdf':
          // Use PDF extraction service
          fullText = await this.extractPdfText(document);
          break;
        case 'html':
          // Strip HTML and extract text
          fullText = await this.extractHtmlText(document);
          break;
        default:
          throw new Error(`Unsupported file type: ${fileType}`);
      }
      
      // Extract the specific range
      return fullText.substring(startChar, endChar);
    } catch (error) {
      logger.error('Error extracting source text:', error);
      throw error;
    }
  }

  /**
   * Resolve vector metadata to full citation
   */
  private async resolveVectorToCitation(
    metadata: VectorMetadata,
    options: CitationLookupOptions
  ): Promise<Citation | null> {
    try {
      // Get chunk data from Supabase
      const { data: chunk, error } = await this.supabaseService.client
        .from('document_chunks')
        .select(`
          *,
          documents:document_id (
            id,
            title,
            type,
            source_url,
            s3_key,
            metadata,
            created_at
          )
        `)
        .eq('id', metadata.chunk_id)
        .single();

      if (error || !chunk) {
        return null;
      }

      // Extract exact text if requested
      let exactText: string | undefined;
      if (options.includeExactText && chunk.documents?.s3_key) {
        exactText = await this.extractSourceText(
          chunk.documents.s3_key,
          chunk.start_char,
          chunk.end_char
        );
      }

      // Build citation object
      const citation: Citation = {
        id: `cite_${metadata.chunk_id}_${Date.now()}`,
        vectorId: metadata.vector_id,
        chunkId: metadata.chunk_id,
        documentId: chunk.document_id,
        source: {
          title: chunk.documents?.title || 'Unknown',
          type: chunk.documents?.type || 'document',
          url: chunk.documents?.source_url,
          s3Key: chunk.documents?.s3_key,
          publishedDate: chunk.documents?.created_at,
          metadata: chunk.documents?.metadata || {}
        },
        text: exactText || chunk.text,
        startChar: chunk.start_char,
        endChar: chunk.end_char,
        pageNumber: chunk.page_number,
        confidence: metadata.score || 1.0,
        retrievedAt: new Date().toISOString()
      };

      return citation;
    } catch (error) {
      logger.error('Error resolving vector to citation:', error);
      return null;
    }
  }

  /**
   * Build citation from chunk data
   */
  private async buildCitationFromChunk(
    chunk: DocumentChunk & { documents: any },
    options: CitationLookupOptions
  ): Promise<Citation> {
    // Extract exact text if requested
    let exactText: string | undefined;
    if (options.includeExactText && chunk.documents?.s3_key) {
      exactText = await this.extractSourceText(
        chunk.documents.s3_key,
        chunk.start_char,
        chunk.end_char
      );
    }

    const citation: Citation = {
      id: `cite_${chunk.id}_${Date.now()}`,
      chunkId: chunk.id,
      documentId: chunk.document_id,
      source: {
        title: chunk.documents?.title || 'Unknown',
        type: chunk.documents?.type || 'document',
        url: chunk.documents?.source_url,
        s3Key: chunk.documents?.s3_key,
        publishedDate: chunk.documents?.created_at,
        metadata: chunk.documents?.metadata || {}
      },
      text: exactText || chunk.text,
      startChar: chunk.start_char,
      endChar: chunk.end_char,
      pageNumber: chunk.page_number,
      confidence: 1.0,
      retrievedAt: new Date().toISOString()
    };

    return citation;
  }

  /**
   * Lookup by citation ID
   */
  private async lookupByCitationId(
    citationId: string,
    options: CitationLookupOptions
  ): Promise<Citation | null> {
    // Parse citation ID to extract chunk ID
    const parts = citationId.split('_');
    if (parts.length < 3 || parts[0] !== 'cite') {
      return null;
    }
    
    const chunkId = parts[1];
    return this.lookupByChunkId(chunkId, options);
  }

  /**
   * Cache management
   */
  private async getCachedCitation(key: string): Promise<Citation | null> {
    try {
      const cached = await this.redis.get(`${this.cachePrefix}${key}`);
      if (cached) {
        return JSON.parse(cached);
      }
      return null;
    } catch (error) {
      logger.error('Error getting cached citation:', error);
      return null;
    }
  }

  private async cacheCitation(key: string, citation: Citation): Promise<void> {
    try {
      await this.redis.setex(
        `${this.cachePrefix}${key}`,
        this.cacheTTL,
        JSON.stringify(citation)
      );
    } catch (error) {
      logger.error('Error caching citation:', error);
    }
  }

  /**
   * Clear citation cache
   */
  async clearCache(pattern?: string): Promise<void> {
    try {
      const keys = await this.redis.keys(
        `${this.cachePrefix}${pattern || '*'}`
      );
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
      logger.info(`Cleared ${keys.length} citation cache entries`);
    } catch (error) {
      logger.error('Error clearing citation cache:', error);
    }
  }

  /**
   * Helper methods for text extraction
   */
  private async extractPdfText(buffer: Buffer): Promise<string> {
    // Implement PDF text extraction
    // You can use libraries like pdf-parse or pdf2json
    throw new Error('PDF extraction not implemented');
  }

  private async extractHtmlText(buffer: Buffer): Promise<string> {
    // Strip HTML tags and extract text
    const html = buffer.toString('utf-8');
    return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  }

  /**
   * Get citation statistics
   */
  async getStats(): Promise<{
    cachedCitations: number;
    lookupLatency: number;
    hitRate: number;
  }> {
    const keys = await this.redis.keys(`${this.cachePrefix}*`);
    
    return {
      cachedCitations: keys.length,
      lookupLatency: 0, // Implement latency tracking
      hitRate: 0 // Implement hit rate tracking
    };
  }
}

// Export types
export interface Citation {
  id: string;
  vectorId?: string;
  chunkId: string;
  documentId: string;
  source: CitationSource;
  text: string;
  startChar: number;
  endChar: number;
  pageNumber?: number;
  confidence: number;
  retrievedAt: string;
}

export interface CitationSource {
  title: string;
  type: string;
  url?: string;
  s3Key?: string;
  publishedDate?: string;
  metadata: Record<string, any>;
}

export interface CitationLookupOptions {
  includeExactText?: boolean;
  bypassCache?: boolean;
  includeMetadata?: boolean;
}

export interface VectorMetadata {
  vector_id: string;
  chunk_id: string;
  document_id: string;
  score?: number;
  [key: string]: any;
}

export interface DocumentChunk {
  id: string;
  document_id: string;
  text: string;
  start_char: number;
  end_char: number;
  page_number?: number;
  chunk_index: number;
  embedding?: number[];
  metadata?: Record<string, any>;
}