/**
 * PDF Document Processor for Project Seldon
 * Handles PDF parsing, text extraction, and chunk generation
 */

import * as pdfParse from 'pdf-parse';
import { promises as fs } from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger';
import { 
  DocumentProcessor,
  ProcessedDocument
} from './DocumentProcessor';

export interface PDFMetadata {
  title: string;
  author?: string;
  subject?: string;
  keywords?: string;
  creator?: string;
  producer?: string;
  creationDate?: Date;
  modDate?: Date;
  pages: number;
}

export interface PDFProcessingOptions {
  chunkSize?: number;
  chunkOverlap?: number;
  enableCitations?: boolean;
  extractMetadata?: boolean;
  cleanText?: boolean;
}

export class PDFProcessor {
  private documentProcessor: DocumentProcessor;
  private defaultOptions: PDFProcessingOptions = {
    chunkSize: 1500,
    chunkOverlap: 200,
    enableCitations: true,
    extractMetadata: true,
    cleanText: true
  };

  constructor(options?: Partial<PDFProcessingOptions>) {
    this.defaultOptions = { ...this.defaultOptions, ...options };
    // DocumentProcessor requires a full Configuration object
    const config = {
      environment: 'development' as const,
      etl: {
        batchSize: 50,
        maxRetries: 3,
        retryDelay: 5000,
        concurrency: 5,
        timeout: 300000,
        enableMetrics: true,
        enableTracing: false
      },
      processing: {
        chunkSize: this.defaultOptions.chunkSize!,
        chunkOverlap: this.defaultOptions.chunkOverlap!,
        maxDocumentSize: 10 * 1024 * 1024,
        supportedFormats: ['.pdf', '.md', '.txt'],
        tempDirectory: '/tmp/project-seldon'
      },
      databases: {
        supabase: {
          url: process.env.SUPABASE_URL || '',
          anonKey: process.env.SUPABASE_ANON_KEY || '',
          serviceKey: process.env.SUPABASE_SERVICE_KEY || '',
          maxRetries: 3,
          retryDelay: 1000
        },
        pinecone: {
          apiKey: process.env.PINECONE_API_KEY || '',
          environment: process.env.PINECONE_ENV || '',
          indexName: process.env.PINECONE_INDEX_NAME || '',
          dimension: 768,
          metric: 'cosine' as const
        },
        neo4j: {
          uri: process.env.NEO4J_URI || '',
          username: process.env.NEO4J_USERNAME || '',
          password: process.env.NEO4J_PASSWORD || '',
          database: process.env.NEO4J_DATABASE || 'neo4j',
          maxConnectionPoolSize: 50,
          connectionTimeout: 30000
        }
      },
      jina: {
        apiKey: process.env.JINA_API_KEY || '',
        baseUrl: 'https://api.jina.ai/v1',
        embeddingModel: 'jina-embeddings-v2-base-en',
        rerankModel: 'jina-reranker-v2-base-multilingual',
        classifierModel: 'jina-clip-v1',
        maxTokens: 8192,
        rateLimit: {
          requestsPerMinute: 50,
          requestsPerHour: 1000,
          burstLimit: 10
        }
      },
      logging: {
        level: 'info' as const,
        directory: './logs',
        maxFileSize: 10 * 1024 * 1024,
        maxFiles: 5,
        enableConsole: true,
        enableFile: true
      },
      monitoring: {
        healthCheckInterval: 60000,
        metricsInterval: 30000,
        enablePrometheus: true,
        prometheusPort: 9090
      }
    };
    this.documentProcessor = new DocumentProcessor(config);
  }

  /**
   * Process a PDF file and extract structured data
   */
  async processPDF(filePath: string): Promise<ProcessedDocument> {
    logger.info(`Processing PDF: ${path.basename(filePath)}`);
    
    try {
      // Read PDF file
      const dataBuffer = await fs.readFile(filePath);
      
      // Parse PDF
      const pdfData = await pdfParse(dataBuffer);
      
      // Extract metadata
      const metadata = this.extractMetadata(pdfData, filePath);
      
      // Clean text if requested
      let text = pdfData.text;
      if (this.defaultOptions.cleanText) {
        text = this.cleanPDFText(text);
      }
      
      // Save cleaned text to temporary file for processing
      const tempFile = path.join('/tmp', `${path.basename(filePath)}.txt`);
      await fs.writeFile(tempFile, text);
      
      try {
        // Process with document processor
        const processedDoc = await this.documentProcessor.process(tempFile, {
          chunkSize: this.defaultOptions.chunkSize,
          chunkOverlap: this.defaultOptions.chunkOverlap,
          includeMetadata: true,
          preserveFormatting: false
        });
      
      // Add PDF-specific information to customProperties
      if (!processedDoc.metadata.customProperties) {
        processedDoc.metadata.customProperties = {};
      }
      processedDoc.metadata.customProperties.pdfInfo = {
        pages: pdfData.numpages,
        version: pdfData.version,
        textLength: text.length,
        rawTextLength: pdfData.text.length
      };
      
        // Merge PDF metadata with processed document
        processedDoc.document.metadata = {
          ...processedDoc.document.metadata,
          ...metadata,
          source: filePath,
          fileType: 'pdf',
          pdfInfo: {
            pages: pdfData.numpages,
            version: pdfData.version,
            textLength: text.length,
            rawTextLength: pdfData.text.length
          }
        };
        
        logger.info(`PDF processed successfully: ${metadata.title}`);
        return processedDoc.document;
      } finally {
        // Clean up temp file
        try {
          await fs.unlink(tempFile);
        } catch (e) {
          // Ignore cleanup errors
        }
      }
      
    } catch (error) {
      logger.error('Failed to process PDF', error);
      throw new Error(`PDF processing failed: ${error.message}`);
    }
  }

  /**
   * Extract metadata from PDF
   */
  private extractMetadata(pdfData: any, filePath: string): PDFMetadata {
    const info = pdfData.info || {};
    
    return {
      title: info.Title || path.basename(filePath, '.pdf'),
      author: info.Author,
      subject: info.Subject,
      keywords: info.Keywords,
      creator: info.Creator,
      producer: info.Producer,
      creationDate: info.CreationDate ? new Date(info.CreationDate) : undefined,
      modDate: info.ModDate ? new Date(info.ModDate) : undefined,
      pages: pdfData.numpages
    };
  }

  /**
   * Clean PDF text
   */
  private cleanPDFText(text: string): string {
    // Remove excessive whitespace
    let cleaned = text.replace(/\s+/g, ' ');
    
    // Remove page headers/footers (common patterns)
    cleaned = cleaned.replace(/Page \d+ of \d+/gi, '');
    cleaned = cleaned.replace(/\d+\s*\|\s*Page/gi, '');
    
    // Fix hyphenated words at line breaks
    cleaned = cleaned.replace(/(\w+)-\s*\n\s*(\w+)/g, '$1$2');
    
    // Remove multiple newlines
    cleaned = cleaned.replace(/\n{3,}/g, '\n\n');
    
    // Trim
    return cleaned.trim();
  }


  /**
   * Process multiple PDFs in batch
   */
  async processBatch(filePaths: string[], options?: {
    concurrency?: number;
    onProgress?: (processed: number, total: number) => void;
  }): Promise<ProcessedDocument[]> {
    const results: ProcessedDocument[] = [];
    const concurrency = options?.concurrency || 3;
    
    // Process in batches
    for (let i = 0; i < filePaths.length; i += concurrency) {
      const batch = filePaths.slice(i, i + concurrency);
      const batchResults = await Promise.all(
        batch.map(filePath => this.processPDF(filePath))
      );
      
      results.push(...batchResults);
      
      if (options?.onProgress) {
        options.onProgress(Math.min(i + concurrency, filePaths.length), filePaths.length);
      }
    }
    
    return results;
  }

  /**
   * Extract text from specific pages
   */
  async extractPages(filePath: string, _pageNumbers: number[]): Promise<string> {
    // Note: pdf-parse doesn't support page-specific extraction
    // This is a placeholder for future enhancement with pdf-lib or similar
    logger.warn('Page-specific extraction not yet implemented, extracting all text');
    
    const dataBuffer = await fs.readFile(filePath);
    const pdfData = await pdfParse(dataBuffer);
    
    return this.cleanPDFText(pdfData.text);
  }

  /**
   * Check if file is a valid PDF
   */
  async isPDF(filePath: string): Promise<boolean> {
    try {
      const buffer = await fs.readFile(filePath, { start: 0, end: 4 });
      return buffer.toString() === '%PDF';
    } catch (error) {
      return false;
    }
  }

  /**
   * Get PDF statistics
   */
  async getStats(filePath: string): Promise<{
    pages: number;
    textLength: number;
    hasText: boolean;
    fileSize: number;
  }> {
    const stats = await fs.stat(filePath);
    const dataBuffer = await fs.readFile(filePath);
    const pdfData = await pdfParse(dataBuffer);
    
    return {
      pages: pdfData.numpages,
      textLength: pdfData.text.length,
      hasText: pdfData.text.trim().length > 0,
      fileSize: stats.size
    };
  }
}

// Export for use
export default PDFProcessor;