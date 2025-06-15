import { S3Client, GetObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';
import { createHash } from 'crypto';
import * as matter from 'gray-matter';
import { Readable } from 'stream';
import { logger } from '../../utils/logger';
import { SupabaseService } from '../database/SupabaseService';
import { 
  Document, 
  DocumentMetadata, 
  ExtractionResult, 
  ProcessingError,
  DocumentType,
  DocumentStatus
} from '../../types';

interface ExtractionOptions {
  bucket: string;
  prefix?: string;
  maxRetries?: number;
  retryDelay?: number;
  batchSize?: number;
}

interface S3Document {
  key: string;
  size: number;
  lastModified: Date;
  etag?: string;
}

export class DocumentExtractionService {
  private s3Client: S3Client;
  private supabaseService: SupabaseService;
  private maxRetries: number;
  private retryDelay: number;
  private batchSize: number;

  constructor(
    s3Client: S3Client,
    supabaseService: SupabaseService,
    options: Partial<ExtractionOptions> = {}
  ) {
    this.s3Client = s3Client;
    this.supabaseService = supabaseService;
    this.maxRetries = options.maxRetries || 3;
    this.retryDelay = options.retryDelay || 1000;
    this.batchSize = options.batchSize || 10;
  }

  /**
   * Extract documents from S3 bucket
   */
  async extractDocuments(options: ExtractionOptions): Promise<ExtractionResult> {
    const startTime = Date.now();
    const errors: ProcessingError[] = [];
    const processedDocuments: Document[] = [];
    let totalProcessed = 0;
    let totalSkipped = 0;

    try {
      logger.info('Starting document extraction', {
        bucket: options.bucket,
        prefix: options.prefix
      });

      // List all objects in the bucket
      const documents = await this.listS3Documents(options.bucket, options.prefix);
      logger.info(`Found ${documents.length} documents to process`);

      // Process documents in batches
      for (let i = 0; i < documents.length; i += this.batchSize) {
        const batch = documents.slice(i, i + this.batchSize);
        const batchResults = await Promise.allSettled(
          batch.map(doc => this.processDocument(doc, options.bucket))
        );

        // Handle batch results
        for (let j = 0; j < batchResults.length; j++) {
          const result = batchResults[j];
          const document = batch[j];

          if (result.status === 'fulfilled') {
            if (result.value) {
              processedDocuments.push(result.value);
              totalProcessed++;
            } else {
              totalSkipped++;
            }
          } else {
            errors.push({
              timestamp: new Date(),
              message: result.reason.message,
              context: { key: document.key },
              stack: result.reason.stack
            });
          }
        }

        // Log progress
        logger.info(`Processed batch ${Math.floor(i / this.batchSize) + 1}`, {
          processed: totalProcessed,
          skipped: totalSkipped,
          errors: errors.length
        });
      }

      const duration = Date.now() - startTime;
      const extractionResult: ExtractionResult = {
        success: errors.length === 0,
        timestamp: new Date(),
        documentsProcessed: totalProcessed,
        documentsSkipped: totalSkipped,
        errors: errors.length > 0 ? errors : undefined,
        duration
      };

      logger.info('Document extraction completed', extractionResult);
      return extractionResult;

    } catch (error) {
      logger.error('Fatal error during document extraction', error);
      throw error;
    }
  }

  /**
   * List all documents in S3 bucket
   */
  private async listS3Documents(
    bucket: string, 
    prefix?: string
  ): Promise<S3Document[]> {
    const documents: S3Document[] = [];
    let continuationToken: string | undefined;

    do {
      const command = new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: continuationToken
      });

      const response = await this.s3Client.send(command);
      
      if (response.Contents) {
        for (const object of response.Contents) {
          if (object.Key && object.Size && object.LastModified) {
            // Filter for supported document types
            if (this.isSupportedDocument(object.Key)) {
              documents.push({
                key: object.Key,
                size: object.Size,
                lastModified: object.LastModified,
                etag: object.ETag
              });
            }
          }
        }
      }

      continuationToken = response.NextContinuationToken;
    } while (continuationToken);

    return documents;
  }

  /**
   * Process a single document
   */
  private async processDocument(
    s3Document: S3Document,
    bucket: string
  ): Promise<Document | null> {
    const { key } = s3Document;

    try {
      // Check if document already exists
      const existingDoc = await this.supabaseService.getDocumentByPath(key);
      if (existingDoc) {
        // Check if document has been modified
        const existingHash = existingDoc.content_hash;
        const content = await this.downloadDocument(bucket, key);
        const newHash = this.calculateHash(content);

        if (existingHash === newHash) {
          logger.debug(`Document unchanged, skipping: ${key}`);
          return null;
        }
      }

      // Download and process document
      const content = await this.downloadDocument(bucket, key);
      const metadata = this.extractMetadata(key, content, s3Document);
      const processedContent = this.processContent(content, metadata.type);
      const contentHash = this.calculateHash(content);

      // Create document record
      const document: Omit<Document, 'id' | 'created_at' | 'updated_at'> = {
        source_path: key,
        content: processedContent.content,
        content_hash: contentHash,
        metadata,
        type: metadata.type,
        status: DocumentStatus.ACTIVE,
        extraction_date: new Date(),
        file_size: s3Document.size,
        last_modified: s3Document.lastModified
      };

      // Save to database
      const savedDoc = await this.supabaseService.createDocument(document);
      logger.info(`Successfully processed document: ${key}`);
      
      return savedDoc;

    } catch (error) {
      logger.error(`Error processing document: ${key}`, error);
      throw error;
    }
  }

  /**
   * Download document from S3
   */
  private async downloadDocument(
    bucket: string,
    key: string,
    attempt: number = 1
  ): Promise<string> {
    try {
      const command = new GetObjectCommand({
        Bucket: bucket,
        Key: key
      });

      const response = await this.s3Client.send(command);
      
      if (!response.Body) {
        throw new Error('Empty response body from S3');
      }

      // Convert stream to string
      const stream = response.Body as Readable;
      const chunks: Buffer[] = [];
      
      return new Promise((resolve, reject) => {
        stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        stream.on('error', reject);
        stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      });

    } catch (error) {
      if (attempt < this.maxRetries) {
        logger.warn(`Retrying download for ${key}, attempt ${attempt + 1}`);
        await this.delay(this.retryDelay * attempt);
        return this.downloadDocument(bucket, key, attempt + 1);
      }
      throw error;
    }
  }

  /**
   * Extract metadata from document
   */
  private extractMetadata(
    path: string,
    content: string,
    s3Document: S3Document
  ): DocumentMetadata {
    const pathParts = path.split('/');
    const filename = pathParts[pathParts.length - 1];
    const type = this.determineDocumentType(filename);
    
    // Extract metadata based on document type
    let metadata: DocumentMetadata = {
      title: this.extractTitle(filename, content),
      type,
      source: 's3',
      tags: this.extractTags(path),
      category: this.extractCategory(path),
      sector: this.extractSector(path),
      prospect: this.extractProspect(path),
      theme: this.extractTheme(path),
      file_name: filename,
      file_path: path,
      extraction_metadata: {
        etag: s3Document.etag,
        size: s3Document.size,
        lastModified: s3Document.lastModified.toISOString()
      }
    };

    // Parse front matter for markdown files
    if (type === DocumentType.MARKDOWN) {
      const parsed = matter(content);
      if (parsed.data) {
        metadata = {
          ...metadata,
          ...this.sanitizeFrontMatter(parsed.data)
        };
      }
    }

    return metadata;
  }

  /**
   * Process content based on document type
   */
  private processContent(
    content: string,
    type: DocumentType
  ): { content: string; frontMatter?: any } {
    switch (type) {
      case DocumentType.MARKDOWN:
        const parsed = matter(content);
        return {
          content: parsed.content,
          frontMatter: parsed.data
        };
      
      case DocumentType.PDF:
        // TODO: Implement PDF processing
        return { content };
      
      case DocumentType.HTML:
        // TODO: Implement HTML to markdown conversion
        return { content };
      
      case DocumentType.TEXT:
      default:
        return { content };
    }
  }

  /**
   * Calculate content hash
   */
  private calculateHash(content: string): string {
    return createHash('sha256').update(content).digest('hex');
  }

  /**
   * Determine document type from filename
   */
  private determineDocumentType(filename: string): DocumentType {
    const extension = filename.split('.').pop()?.toLowerCase();
    
    switch (extension) {
      case 'md':
      case 'markdown':
        return DocumentType.MARKDOWN;
      case 'pdf':
        return DocumentType.PDF;
      case 'html':
      case 'htm':
        return DocumentType.HTML;
      case 'txt':
      case 'text':
        return DocumentType.TEXT;
      default:
        return DocumentType.OTHER;
    }
  }

  /**
   * Check if document type is supported
   */
  private isSupportedDocument(path: string): boolean {
    const supportedExtensions = ['.md', '.markdown', '.pdf', '.html', '.htm', '.txt', '.text'];
    return supportedExtensions.some(ext => path.toLowerCase().endsWith(ext));
  }

  /**
   * Extract title from filename and content
   */
  private extractTitle(filename: string, content: string): string {
    // Remove extension
    let title = filename.replace(/\.[^/.]+$/, '');
    
    // Try to extract title from content
    const titleMatch = content.match(/^#\s+(.+)$/m);
    if (titleMatch) {
      title = titleMatch[1];
    }
    
    // Clean up title
    return title
      .replace(/_/g, ' ')
      .replace(/-/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Extract tags from path
   */
  private extractTags(path: string): string[] {
    const tags: string[] = [];
    const pathParts = path.split('/');
    
    // Add path components as tags
    pathParts.forEach(part => {
      if (part && !part.includes('.')) {
        tags.push(part.toLowerCase());
      }
    });
    
    return [...new Set(tags)];
  }

  /**
   * Extract category from path
   */
  private extractCategory(path: string): string | undefined {
    const categoryPatterns = [
      { pattern: /reports?/i, category: 'report' },
      { pattern: /landing[_-]?pages?/i, category: 'landing_page' },
      { pattern: /email[_-]?templates?/i, category: 'email_template' },
      { pattern: /prospects?/i, category: 'prospect' },
      { pattern: /appendices/i, category: 'appendix' },
      { pattern: /playbooks?/i, category: 'playbook' },
      { pattern: /intelligence/i, category: 'intelligence' },
      { pattern: /analysis/i, category: 'analysis' }
    ];

    for (const { pattern, category } of categoryPatterns) {
      if (pattern.test(path)) {
        return category;
      }
    }

    return undefined;
  }

  /**
   * Extract sector from path or content
   */
  private extractSector(path: string): string | undefined {
    const sectorPatterns = [
      { pattern: /energy/i, sector: 'energy' },
      { pattern: /manufacturing/i, sector: 'manufacturing' },
      { pattern: /utilities/i, sector: 'utilities' },
      { pattern: /oil[_-]?gas/i, sector: 'oil_gas' },
      { pattern: /transportation/i, sector: 'transportation' },
      { pattern: /food/i, sector: 'food' },
      { pattern: /water/i, sector: 'water' }
    ];

    for (const { pattern, sector } of sectorPatterns) {
      if (pattern.test(path)) {
        return sector;
      }
    }

    return undefined;
  }

  /**
   * Extract prospect name from path
   */
  private extractProspect(path: string): string | undefined {
    // Look for prospect patterns in path
    const prospectMatch = path.match(/prospects?\/([^/]+)/i);
    if (prospectMatch) {
      return prospectMatch[1].replace(/[_-]/g, ' ').trim();
    }

    // Check for appendix pattern
    const appendixMatch = path.match(/A-\d+[_-]([^/]+)/i);
    if (appendixMatch) {
      return appendixMatch[1].replace(/[_-]/g, ' ').trim();
    }

    return undefined;
  }

  /**
   * Extract theme from path or content
   */
  private extractTheme(path: string): string | undefined {
    const themePatterns = [
      { pattern: /itc/i, theme: 'itc' },
      { pattern: /sca/i, theme: 'sca' },
      { pattern: /ransomware/i, theme: 'ransomware' },
      { pattern: /ma/i, theme: 'ma' },
      { pattern: /vulnerabilit/i, theme: 'vulnerability' },
      { pattern: /incident[_-]?response/i, theme: 'incident_response' },
      { pattern: /compliance/i, theme: 'compliance' },
      { pattern: /risk/i, theme: 'risk' },
      { pattern: /safety/i, theme: 'safety' }
    ];

    for (const { pattern, theme } of themePatterns) {
      if (pattern.test(path)) {
        return theme;
      }
    }

    return undefined;
  }

  /**
   * Sanitize front matter data
   */
  private sanitizeFrontMatter(data: any): Partial<DocumentMetadata> {
    const sanitized: Partial<DocumentMetadata> = {};
    
    // Map common front matter fields
    if (data.title) sanitized.title = String(data.title);
    if (data.author) sanitized.author = String(data.author);
    if (data.date) sanitized.date = new Date(data.date);
    if (data.tags && Array.isArray(data.tags)) {
      sanitized.tags = data.tags.map(tag => String(tag));
    }
    if (data.category) sanitized.category = String(data.category);
    if (data.sector) sanitized.sector = String(data.sector);
    if (data.prospect) sanitized.prospect = String(data.prospect);
    if (data.theme) sanitized.theme = String(data.theme);
    if (data.version) sanitized.version = String(data.version);
    if (data.status) sanitized.status = String(data.status);
    
    return sanitized;
  }

  /**
   * Delay helper for retries
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}