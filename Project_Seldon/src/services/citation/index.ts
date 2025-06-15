import { CitationLookupService } from './CitationLookupService';
import { PineconeService } from '../pinecone/PineconeService';
import { SupabaseService } from '../database/SupabaseService';
import { S3DocumentService } from '../s3/S3DocumentService';
import { Redis } from 'ioredis';
import { config } from '../../config';
import { logger } from '../../utils/logger';

let citationService: CitationLookupService | null = null;

/**
 * Initialize and return singleton CitationLookupService instance
 */
export async function getCitationService(): Promise<CitationLookupService> {
  if (!citationService) {
    try {
      // Initialize dependencies
      const pineconeService = new PineconeService({
        apiKey: config.pinecone.apiKey,
        environment: config.pinecone.environment,
        indexName: config.pinecone.indexName
      });

      const supabaseService = new SupabaseService(
        config.supabase.url,
        config.supabase.serviceKey
      );

      const s3Service = new S3DocumentService({
        region: config.aws.region,
        credentials: {
          accessKeyId: config.aws.accessKeyId,
          secretAccessKey: config.aws.secretAccessKey
        },
        bucketName: config.s3.bucketName
      });

      const redis = new Redis({
        host: config.redis.host,
        port: config.redis.port,
        password: config.redis.password,
        db: config.redis.db || 0
      });

      citationService = new CitationLookupService(
        pineconeService,
        supabaseService,
        s3Service,
        redis
      );

      logger.info('Citation lookup service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize citation service:', error);
      throw error;
    }
  }

  return citationService;
}

/**
 * Citation lookup helper functions
 */
export async function lookupCitation(
  vectorId: string,
  includeExactText = false
): Promise<any> {
  const service = await getCitationService();
  return service.lookupByVectorId(vectorId, { includeExactText });
}

export async function lookupCitationsByChunkIds(
  chunkIds: string[],
  includeExactText = false
): Promise<Map<string, any>> {
  const service = await getCitationService();
  return service.lookupBatch(chunkIds, 'chunk', { includeExactText });
}

export async function extractExactQuote(
  s3Key: string,
  startChar: number,
  endChar: number
): Promise<string> {
  const service = await getCitationService();
  return service.extractSourceText(s3Key, startChar, endChar);
}

/**
 * Format citations for response
 */
export function formatCitationsForResponse(
  citations: Map<string, any>,
  format: 'inline' | 'footnote' | 'bibliography' = 'inline'
): string[] {
  const formatted: string[] = [];

  citations.forEach((citation, id) => {
    switch (format) {
      case 'inline':
        formatted.push(
          `[${citation.source.title}, ${citation.source.publishedDate || 'n.d.'}]`
        );
        break;
      
      case 'footnote':
        formatted.push(
          `${citation.source.title}. ` +
          `${citation.source.type.toUpperCase()}. ` +
          `${citation.source.publishedDate || 'n.d.'}. ` +
          `${citation.source.url || 'No URL available'}`
        );
        break;
      
      case 'bibliography':
        formatted.push(
          `${citation.source.metadata?.author || 'Unknown Author'}. ` +
          `(${citation.source.publishedDate || 'n.d.'}). ` +
          `${citation.source.title}. ` +
          `Retrieved from ${citation.source.url || 'internal document'}`
        );
        break;
    }
  });

  return formatted;
}

/**
 * Citation validation
 */
export async function validateCitations(
  citationIds: string[]
): Promise<{ valid: string[]; invalid: string[] }> {
  const service = await getCitationService();
  const results = await service.lookupBatch(citationIds, 'citation');
  
  const valid: string[] = [];
  const invalid: string[] = [];
  
  citationIds.forEach(id => {
    if (results.has(id)) {
      valid.push(id);
    } else {
      invalid.push(id);
    }
  });
  
  return { valid, invalid };
}

/**
 * Clear citation cache
 */
export async function clearCitationCache(pattern?: string): Promise<void> {
  const service = await getCitationService();
  await service.clearCache(pattern);
}

/**
 * Get citation service statistics
 */
export async function getCitationStats(): Promise<any> {
  const service = await getCitationService();
  return service.getStats();
}

// Export types
export { Citation, CitationSource, CitationLookupOptions } from './CitationLookupService';

// Export service class for advanced usage
export { CitationLookupService } from './CitationLookupService';