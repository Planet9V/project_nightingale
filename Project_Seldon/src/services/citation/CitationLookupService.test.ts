import { CitationLookupService } from './CitationLookupService';
import { PineconeService } from '../pinecone/PineconeService';
import { SupabaseService } from '../database/SupabaseService';
import { S3DocumentService } from '../s3/S3DocumentService';
import { Redis } from 'ioredis';

// Mock dependencies
jest.mock('../pinecone/PineconeService');
jest.mock('../database/SupabaseService');
jest.mock('../s3/S3DocumentService');
jest.mock('ioredis');

describe('CitationLookupService', () => {
  let citationService: CitationLookupService;
  let mockPinecone: jest.Mocked<PineconeService>;
  let mockSupabase: jest.Mocked<SupabaseService>;
  let mockS3: jest.Mocked<S3DocumentService>;
  let mockRedis: jest.Mocked<Redis>;

  beforeEach(() => {
    // Create mock instances
    mockPinecone = new PineconeService({} as any) as jest.Mocked<PineconeService>;
    mockSupabase = new SupabaseService('', '') as jest.Mocked<SupabaseService>;
    mockS3 = new S3DocumentService({} as any) as jest.Mocked<S3DocumentService>;
    mockRedis = new Redis() as jest.Mocked<Redis>;

    // Mock Supabase client
    mockSupabase.client = {
      from: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      eq: jest.fn().mockReturnThis(),
      single: jest.fn().mockResolvedValue({
        data: null,
        error: null
      })
    } as any;

    citationService = new CitationLookupService(
      mockPinecone,
      mockSupabase,
      mockS3,
      mockRedis
    );
  });

  describe('lookupByVectorId', () => {
    it('should return cached citation if available', async () => {
      const cachedCitation = {
        id: 'cite_123_456',
        chunkId: '123',
        documentId: 'doc_1',
        source: {
          title: 'Test Document',
          type: 'pdf',
          url: 'https://example.com/doc.pdf'
        },
        text: 'Sample text',
        startChar: 0,
        endChar: 100,
        confidence: 0.95,
        retrievedAt: '2025-01-01T00:00:00Z'
      };

      mockRedis.get.mockResolvedValue(JSON.stringify(cachedCitation));

      const result = await citationService.lookupByVectorId('vec_123');
      expect(result).toEqual(cachedCitation);
      expect(mockPinecone.fetchVector).not.toHaveBeenCalled();
    });

    it('should fetch from Pinecone if not cached', async () => {
      mockRedis.get.mockResolvedValue(null);
      
      mockPinecone.fetchVector = jest.fn().mockResolvedValue({
        id: 'vec_123',
        values: [],
        metadata: {
          vector_id: 'vec_123',
          chunk_id: 'chunk_123',
          document_id: 'doc_1',
          score: 0.95
        }
      });

      const mockChunkData = {
        id: 'chunk_123',
        document_id: 'doc_1',
        text: 'Sample chunk text',
        start_char: 0,
        end_char: 100,
        chunk_index: 0,
        documents: {
          id: 'doc_1',
          title: 'Test Document',
          type: 'pdf',
          source_url: 'https://example.com/doc.pdf',
          s3_key: 'documents/doc_1.pdf',
          metadata: {},
          created_at: '2025-01-01T00:00:00Z'
        }
      };

      (mockSupabase.client.single as jest.Mock).mockResolvedValue({
        data: mockChunkData,
        error: null
      });

      const result = await citationService.lookupByVectorId('vec_123');
      
      expect(result).toBeTruthy();
      expect(result?.vectorId).toBe('vec_123');
      expect(result?.chunkId).toBe('chunk_123');
      expect(result?.source.title).toBe('Test Document');
      expect(mockRedis.setex).toHaveBeenCalled();
    });
  });

  describe('lookupByChunkId', () => {
    it('should return citation from chunk data', async () => {
      mockRedis.get.mockResolvedValue(null);

      const mockChunkData = {
        id: 'chunk_456',
        document_id: 'doc_2',
        text: 'Another sample text',
        start_char: 100,
        end_char: 200,
        page_number: 2,
        chunk_index: 1,
        documents: {
          id: 'doc_2',
          title: 'Another Document',
          type: 'html',
          source_url: 'https://example.com/page.html',
          metadata: { author: 'Test Author' }
        }
      };

      (mockSupabase.client.single as jest.Mock).mockResolvedValue({
        data: mockChunkData,
        error: null
      });

      const result = await citationService.lookupByChunkId('chunk_456');
      
      expect(result).toBeTruthy();
      expect(result?.chunkId).toBe('chunk_456');
      expect(result?.documentId).toBe('doc_2');
      expect(result?.pageNumber).toBe(2);
      expect(result?.source.metadata.author).toBe('Test Author');
    });
  });

  describe('lookupBatch', () => {
    it('should process multiple lookups in parallel', async () => {
      mockRedis.get.mockResolvedValue(null);
      
      // Mock vector lookups
      mockPinecone.fetchVector = jest.fn()
        .mockResolvedValueOnce({
          id: 'vec_1',
          metadata: { chunk_id: 'chunk_1' }
        })
        .mockResolvedValueOnce({
          id: 'vec_2',
          metadata: { chunk_id: 'chunk_2' }
        });

      // Mock chunk data
      (mockSupabase.client.single as jest.Mock)
        .mockResolvedValueOnce({
          data: {
            id: 'chunk_1',
            documents: { title: 'Doc 1' }
          }
        })
        .mockResolvedValueOnce({
          data: {
            id: 'chunk_2',
            documents: { title: 'Doc 2' }
          }
        });

      const results = await citationService.lookupBatch(
        ['vec_1', 'vec_2'],
        'vector'
      );

      expect(results.size).toBe(2);
      expect(results.has('vec_1')).toBe(true);
      expect(results.has('vec_2')).toBe(true);
    });
  });

  describe('extractSourceText', () => {
    it('should extract text from plain text file', async () => {
      const fullText = 'This is a long document with many words...';
      mockS3.downloadDocument.mockResolvedValue(Buffer.from(fullText));

      const extracted = await citationService.extractSourceText(
        'doc.txt',
        5,
        15
      );

      expect(extracted).toBe('is a long ');
    });

    it('should handle HTML text extraction', async () => {
      const html = '<p>Hello <strong>world</strong>!</p>';
      mockS3.downloadDocument.mockResolvedValue(Buffer.from(html));

      const extracted = await citationService.extractSourceText(
        'doc.html',
        0,
        20
      );

      expect(extracted).toContain('Hello');
      expect(extracted).toContain('world');
      expect(extracted).not.toContain('<p>');
    });
  });

  describe('clearCache', () => {
    it('should clear all citation cache entries', async () => {
      mockRedis.keys.mockResolvedValue([
        'citation:vec_1',
        'citation:vec_2',
        'citation:chunk:123'
      ]);

      await citationService.clearCache();

      expect(mockRedis.del).toHaveBeenCalledWith(
        'citation:vec_1',
        'citation:vec_2',
        'citation:chunk:123'
      );
    });

    it('should clear cache entries matching pattern', async () => {
      mockRedis.keys.mockResolvedValue(['citation:vec_1', 'citation:vec_2']);

      await citationService.clearCache('vec_*');

      expect(mockRedis.keys).toHaveBeenCalledWith('citation:vec_*');
    });
  });

  describe('getStats', () => {
    it('should return citation statistics', async () => {
      mockRedis.keys.mockResolvedValue([
        'citation:1',
        'citation:2',
        'citation:3'
      ]);

      const stats = await citationService.getStats();

      expect(stats.cachedCitations).toBe(3);
      expect(stats).toHaveProperty('lookupLatency');
      expect(stats).toHaveProperty('hitRate');
    });
  });
});