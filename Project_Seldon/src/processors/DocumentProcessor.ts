/**
 * Document Processor for Project Seldon ETL Pipeline
 * Handles markdown parsing, metadata extraction, and document chunking
 */

import { readFile } from 'fs/promises';
import path from 'path';
import matter from 'gray-matter';
import crypto from 'crypto';
import { logger } from '../utils/logger';
import { 
  ExtractedDocument, 
  DocumentMetadata, 
  DocumentChunk,
  DocumentFormat,
  ProcessingStatus,
  ContentType
} from '../types/index';
import { Configuration } from '../config/types';

export interface ProcessingOptions {
  chunkSize?: number;
  chunkOverlap?: number;
  includeMetadata?: boolean;
  preserveFormatting?: boolean;
  extractEntities?: boolean;
}

export interface ProcessingResult {
  document: ExtractedDocument;
  chunks: DocumentChunk[];
  metadata: DocumentMetadata;
  stats: ProcessingStats;
  citations?: Citation[];
}

export interface ProcessingStats {
  originalSize: number;
  processedSize: number;
  chunkCount: number;
  processingTime: number;
  formatDetected: DocumentFormat;
}

// Re-export types for compatibility
export type { DocumentChunk, ExtractedDocument as ProcessedDocument } from '../types/index';
export type { Citation } from '../types/index';

export class DocumentProcessor {
  private config: Configuration;
  private supportedFormats: Set<string>;

  constructor(config: Configuration) {
    this.config = config;
    this.supportedFormats = new Set(config.processing.supportedFormats);
  }

  /**
   * Alias for processFile for compatibility
   */
  public async process(
    filePath: string,
    options: ProcessingOptions = {}
  ): Promise<ProcessingResult> {
    return this.processFile(filePath, options);
  }

  /**
   * Process a document file
   */
  public async processFile(
    filePath: string, 
    options: ProcessingOptions = {}
  ): Promise<ProcessingResult> {
    const startTime = Date.now();
    
    try {
      logger.info('Processing document', { filePath, options });

      // Validate file
      await this.validateFile(filePath);

      // Read file content
      const content = await readFile(filePath, 'utf-8');
      const stats = {
        originalSize: Buffer.byteLength(content),
        processedSize: 0,
        chunkCount: 0,
        processingTime: 0,
        formatDetected: this.detectFormat(filePath),
      };

      // Extract metadata and content
      const { metadata, cleanContent } = await this.extractMetadata(content, filePath);

      // Create document
      const document = this.createDocument(filePath, cleanContent, metadata);

      // Chunk document
      const chunks = await this.chunkDocument(document, cleanContent, {
        chunkSize: options.chunkSize || this.config.processing.chunkSize,
        chunkOverlap: options.chunkOverlap || this.config.processing.chunkOverlap,
      });

      stats.processedSize = Buffer.byteLength(cleanContent);
      stats.chunkCount = chunks.length;
      stats.processingTime = Date.now() - startTime;

      logger.info('Document processed successfully', {
        filePath,
        documentId: document.id,
        chunks: chunks.length,
        processingTime: stats.processingTime,
      });

      return {
        document,
        chunks,
        metadata,
        stats,
      };
    } catch (error) {
      logger.error('Failed to process document', error as Error, { filePath });
      throw error;
    }
  }

  /**
   * Process multiple documents in batch
   */
  public async processBatch(
    filePaths: string[],
    options: ProcessingOptions = {}
  ): Promise<ProcessingResult[]> {
    const results: ProcessingResult[] = [];
    const errors: Array<{ filePath: string; error: Error }> = [];

    for (const filePath of filePaths) {
      try {
        const result = await this.processFile(filePath, options);
        results.push(result);
      } catch (error) {
        errors.push({ filePath, error: error as Error });
        logger.error('Failed to process file in batch', error as Error, { filePath });
      }
    }

    if (errors.length > 0) {
      logger.warn('Batch processing completed with errors', {
        total: filePaths.length,
        successful: results.length,
        failed: errors.length,
      });
    }

    return results;
  }

  /**
   * Validate file
   */
  private async validateFile(filePath: string): Promise<void> {
    const ext = path.extname(filePath).toLowerCase();
    
    if (!this.supportedFormats.has(ext)) {
      throw new Error(`Unsupported file format: ${ext}`);
    }

    try {
      const stats = await readFile(filePath);
      if (stats.length > this.config.processing.maxDocumentSize) {
        throw new Error(`File size exceeds maximum allowed size of ${this.config.processing.maxDocumentSize} bytes`);
      }
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        throw new Error(`File not found: ${filePath}`);
      }
      throw error;
    }
  }

  /**
   * Detect document format
   */
  private detectFormat(filePath: string): DocumentFormat {
    const ext = path.extname(filePath).toLowerCase();
    
    switch (ext) {
      case '.md':
        return DocumentFormat.MARKDOWN;
      case '.txt':
        return DocumentFormat.TXT;
      case '.pdf':
        return DocumentFormat.PDF;
      case '.json':
        return DocumentFormat.JSON;
      default:
        return DocumentFormat.TXT;
    }
  }

  /**
   * Extract metadata from document
   */
  private async extractMetadata(
    content: string, 
    filePath: string
  ): Promise<{ metadata: DocumentMetadata; cleanContent: string }> {
    const fileName = path.basename(filePath);
    const format = this.detectFormat(filePath);

    // For markdown files, use gray-matter to extract front matter
    if (format === DocumentFormat.MARKDOWN) {
      const { data, content: cleanContent } = matter(content);
      
      const metadata: DocumentMetadata = {
        title: data.title || this.extractTitleFromContent(cleanContent) || fileName,
        author: data.author || 'Unknown',
        subject: data.description || this.extractDescription(cleanContent),
        keywords: Array.isArray(data.tags) ? data.tags : (data.keywords ? data.keywords.split(',') : []),
        category: data.category || this.inferCategory(filePath),
        source: filePath,
        createdAt: data.createdAt ? new Date(data.createdAt) : new Date(),
        modificationDate: data.updatedAt ? new Date(data.updatedAt) : new Date(),
        customProperties: {
          format,
          language: data.language || 'en',
          version: data.version || '1.0.0',
          ...this.sanitizeCustomMetadata(data)
        }
      };

      return { metadata, cleanContent };
    }

    // For other formats, extract basic metadata
    const metadata: DocumentMetadata = {
      title: this.extractTitleFromContent(content) || fileName,
      author: 'Unknown',
      subject: this.extractDescription(content),
      keywords: [],
      category: this.inferCategory(filePath),
      source: filePath,
      createdAt: new Date(),
      modificationDate: new Date(),
      customProperties: {
        format,
        language: 'en',
        version: '1.0.0'
      }
    };

    return { metadata, cleanContent: content };
  }

  /**
   * Extract title from content
   */
  private extractTitleFromContent(content: string): string | null {
    // Try to find a heading
    const headingMatch = content.match(/^#\s+(.+)$/m);
    if (headingMatch) {
      return headingMatch[1].trim();
    }

    // Try first non-empty line
    const lines = content.split('\n').filter(line => line.trim());
    if (lines.length > 0) {
      return lines[0].trim().substring(0, 100);
    }

    return null;
  }

  /**
   * Extract description from content
   */
  private extractDescription(content: string): string {
    // Remove markdown formatting
    const cleaned = content
      .replace(/^#+\s+/gm, '') // Remove headings
      .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') // Remove links
      .replace(/[*_`]/g, '') // Remove emphasis
      .trim();

    // Get first paragraph
    const paragraphs = cleaned.split(/\n\n+/).filter(p => p.trim());
    if (paragraphs.length > 0) {
      return paragraphs[0].substring(0, 500).trim();
    }

    return '';
  }

  /**
   * Infer category from file path
   */
  private inferCategory(filePath: string): string {
    const parts = filePath.split(path.sep);
    
    // Look for common category indicators
    for (const part of parts) {
      if (part.match(/reports?|intelligence|analysis|research|prospects?|templates?/i)) {
        return part.toLowerCase();
      }
    }

    // Check parent directory
    if (parts.length >= 2) {
      return parts[parts.length - 2].toLowerCase();
    }

    return 'general';
  }

  /**
   * Sanitize custom metadata
   */
  private sanitizeCustomMetadata(data: any): Record<string, any> {
    const reserved = new Set(['title', 'author', 'description', 'tags', 'category', 'format', 'language', 'version', 'createdAt', 'updatedAt']);
    const custom: Record<string, any> = {};

    for (const [key, value] of Object.entries(data)) {
      if (!reserved.has(key) && value !== undefined && value !== null) {
        custom[key] = value;
      }
    }

    return custom;
  }

  /**
   * Create document object
   */
  private createDocument(
    filePath: string,
    content: string,
    metadata: DocumentMetadata
  ): ExtractedDocument {
    const id = this.generateDocumentId(filePath);
    const checksum = this.generateChecksum(content);

    return {
      id,
      sourceId: filePath,
      format: this.detectFormat(filePath),
      content: {
        raw: content,
        cleaned: content,
        normalized: content,
        language: 'en',
        encoding: 'utf-8',
        wordCount: content.split(/\s+/).length,
        characterCount: content.length,
        lineCount: content.split('\n').length
      },
      metadata,
      structure: {
        sections: [],
        headings: [],
        paragraphs: []
      },
      extractionTime: new Date(),
      extractionMethod: 'markdown',
      quality: {
        score: 1.0,
        confidence: 1.0,
        warnings: [],
        issues: []
      },
      checksum,
      status: ProcessingStatus.COMPLETED.toString(),
      extractedAt: new Date(),
      processingTime: 0, // Will be updated later
      error: undefined
    };
  }

  /**
   * Generate document ID
   */
  private generateDocumentId(filePath: string): string {
    const normalized = filePath.toLowerCase().replace(/[^a-z0-9]/g, '-');
    const hash = crypto.createHash('sha256').update(filePath).digest('hex').substring(0, 8);
    return `doc-${normalized}-${hash}`;
  }

  /**
   * Generate content checksum
   */
  private generateChecksum(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Chunk document into smaller pieces
   */
  private async chunkDocument(
    document: ExtractedDocument,
    content: string,
    options: { chunkSize: number; chunkOverlap: number }
  ): Promise<DocumentChunk[]> {
    const chunks: DocumentChunk[] = [];
    const { chunkSize, chunkOverlap } = options;

    // Split content into sentences for better chunking
    const sentences = this.splitIntoSentences(content);
    
    let currentChunk = '';
    let currentTokens = 0;
    let chunkIndex = 0;
    let startOffset = 0;

    for (let i = 0; i < sentences.length; i++) {
      const sentence = sentences[i];
      const sentenceTokens = this.estimateTokens(sentence);

      if (currentTokens + sentenceTokens > chunkSize && currentChunk) {
        // Create chunk
        chunks.push(this.createChunk(
          document,
          currentChunk.trim(),
          chunkIndex,
          startOffset,
          startOffset + currentChunk.length
        ));

        // Handle overlap
        if (chunkOverlap > 0) {
          const overlapSentences = this.getOverlapSentences(sentences, i, chunkOverlap);
          currentChunk = overlapSentences.join(' ');
          currentTokens = this.estimateTokens(currentChunk);
          startOffset = startOffset + currentChunk.length - overlapSentences.join(' ').length;
        } else {
          currentChunk = '';
          currentTokens = 0;
          startOffset += currentChunk.length;
        }

        chunkIndex++;
      }

      currentChunk += (currentChunk ? ' ' : '') + sentence;
      currentTokens += sentenceTokens;
    }

    // Add final chunk
    if (currentChunk) {
      chunks.push(this.createChunk(
        document,
        currentChunk.trim(),
        chunkIndex,
        startOffset,
        content.length
      ));
    }

    return chunks;
  }

  /**
   * Split content into sentences
   */
  private splitIntoSentences(content: string): string[] {
    // Simple sentence splitting - can be improved with NLP libraries
    return content
      .split(/(?<=[.!?])\s+/)
      .filter(s => s.trim().length > 0);
  }

  /**
   * Estimate token count (rough approximation)
   */
  private estimateTokens(text: string): number {
    // Rough estimate: 1 token ≈ 4 characters
    return Math.ceil(text.length / 4);
  }

  /**
   * Get overlap sentences
   */
  private getOverlapSentences(
    sentences: string[],
    currentIndex: number,
    overlapTokens: number
  ): string[] {
    const overlap: string[] = [];
    let tokens = 0;

    for (let i = currentIndex - 1; i >= 0; i--) {
      const sentence = sentences[i];
      const sentenceTokens = this.estimateTokens(sentence);

      if (tokens + sentenceTokens > overlapTokens) {
        break;
      }

      overlap.unshift(sentence);
      tokens += sentenceTokens;
    }

    return overlap;
  }

  /**
   * Create chunk object
   */
  private createChunk(
    document: ExtractedDocument,
    content: string,
    index: number,
    startOffset: number,
    endOffset: number
  ): DocumentChunk {
    const id = `${document.id}-chunk-${index}`;

    return {
      id,
      documentId: document.id,
      sourceId: document.sourceId,
      content,
      metadata: {
        tokenCount: this.estimateTokens(content),
        wordCount: content.split(/\s+/).length,
        language: 'en',
        contentType: ContentType.TEXT
      },
      position: {
        index,
        startOffset,
        endOffset,
        level: 0
      },
      context: {
        preceding: '',
        following: '',
        section: document.metadata.title || '',
        document: document.metadata.title || ''
      },
      relationships: [],
      quality: {
        score: 1.0,
        completeness: 1.0,
        coherence: 1.0,
        relevance: 1.0,
        uniqueness: 1.0
      }
    };
  }

  /**
   * Extract entities from content (placeholder for NER)
   */
  public async extractEntities(content: string): Promise<Array<{ type: string; value: string; confidence: number }>> {
    // Placeholder for entity extraction
    // In production, this would use NLP libraries or APIs
    const entities: Array<{ type: string; value: string; confidence: number }> = [];

    // Simple pattern matching for demonstration
    const patterns = {
      email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      url: /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/g,
      date: /\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b/g,
    };

    for (const [type, pattern] of Object.entries(patterns)) {
      const matches = content.match(pattern) || [];
      for (const match of matches) {
        entities.push({
          type,
          value: match,
          confidence: 0.9,
        });
      }
    }

    return entities;
  }
}