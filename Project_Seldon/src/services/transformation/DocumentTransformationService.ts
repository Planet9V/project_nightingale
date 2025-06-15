import { supabase } from '../../config/supabase';
import { JinaServiceManager } from '../jina/JinaServiceManager';
import { DocumentChunk, TransformationRecord, CitationInfo, EmbeddingResult } from '../../types';

interface ExtractedDocument {
  id: string;
  content: string;
  metadata: {
    title?: string;
    author?: string;
    date?: string;
    source?: string;
    [key: string]: any;
  };
  sections?: Array<{
    title: string;
    content: string;
    level: number;
    startIndex: number;
    endIndex: number;
  }>;
}

interface ChunkingOptions {
  maxTokens?: number;
  overlap?: number;
  preserveSentences?: boolean;
  preserveParagraphs?: boolean;
}

interface TransformationResult {
  documentId: string;
  chunks: DocumentChunk[];
  transformationId: string;
  statistics: {
    totalChunks: number;
    totalTokens: number;
    avgChunkSize: number;
    processingTime: number;
  };
}

export class DocumentTransformationService {
  private jinaService: JinaServiceManager;
  private readonly DEFAULT_CHUNK_SIZE = 512;
  private readonly DEFAULT_OVERLAP = 64;
  
  constructor() {
    this.jinaService = JinaServiceManager.getInstance();
  }

  /**
   * Transform an extracted document into chunks with embeddings
   */
  async transformDocument(
    document: ExtractedDocument,
    options: ChunkingOptions = {}
  ): Promise<TransformationResult> {
    const startTime = Date.now();
    console.log(`Starting transformation for document ${document.id}`);

    try {
      // Create transformation record
      const transformationId = await this.createTransformationRecord(document.id);

      // Chunk the document intelligently
      const chunks = await this.chunkDocument(document, options);
      console.log(`Created ${chunks.length} chunks`);

      // Generate embeddings for each chunk
      const chunksWithEmbeddings = await this.generateEmbeddings(chunks);

      // Classify content for each chunk
      const classifiedChunks = await this.classifyChunks(chunksWithEmbeddings);

      // Store chunks in database
      await this.storeChunks(classifiedChunks, transformationId);

      // Update transformation record with results
      const statistics = {
        totalChunks: classifiedChunks.length,
        totalTokens: classifiedChunks.reduce((sum, chunk) => sum + chunk.tokenCount, 0),
        avgChunkSize: Math.round(
          classifiedChunks.reduce((sum, chunk) => sum + chunk.content.length, 0) / 
          classifiedChunks.length
        ),
        processingTime: Date.now() - startTime
      };

      await this.updateTransformationRecord(transformationId, 'completed', statistics);

      return {
        documentId: document.id,
        chunks: classifiedChunks,
        transformationId,
        statistics
      };

    } catch (error) {
      console.error('Error transforming document:', error);
      throw error;
    }
  }

  /**
   * Intelligently chunk document preserving semantic boundaries
   */
  private async chunkDocument(
    document: ExtractedDocument,
    options: ChunkingOptions
  ): Promise<DocumentChunk[]> {
    const {
      maxTokens = this.DEFAULT_CHUNK_SIZE,
      overlap = this.DEFAULT_OVERLAP,
      preserveSentences = true,
      preserveParagraphs = true
    } = options;

    const chunks: DocumentChunk[] = [];
    let chunkIndex = 0;

    // Process sections if available
    if (document.sections && document.sections.length > 0) {
      for (const section of document.sections) {
        const sectionChunks = await this.chunkSection(
          section,
          document,
          chunkIndex,
          { maxTokens, overlap, preserveSentences, preserveParagraphs }
        );
        chunks.push(...sectionChunks);
        chunkIndex += sectionChunks.length;
      }
    } else {
      // Fall back to chunking entire content
      const contentChunks = await this.chunkContent(
        document.content,
        document,
        0,
        { maxTokens, overlap, preserveSentences, preserveParagraphs }
      );
      chunks.push(...contentChunks);
    }

    return chunks;
  }

  /**
   * Chunk a section of content
   */
  private async chunkSection(
    section: any,
    document: ExtractedDocument,
    startChunkIndex: number,
    options: ChunkingOptions
  ): Promise<DocumentChunk[]> {
    const chunks: DocumentChunk[] = [];
    const paragraphs = this.splitIntoParagraphs(section.content);
    
    let currentChunk = '';
    let currentTokens = 0;
    let paragraphIndex = 0;
    let chunkStartChar = section.startIndex;
    
    for (const paragraph of paragraphs) {
      const paragraphTokens = await this.estimateTokens(paragraph);
      
      // If adding this paragraph would exceed limit, create chunk
      if (currentTokens + paragraphTokens > options.maxTokens! && currentChunk) {
        chunks.push(this.createChunk(
          currentChunk,
          document,
          startChunkIndex + chunks.length,
          {
            section: section.title,
            sectionLevel: section.level,
            paragraphStart: Math.max(0, paragraphIndex - 1),
            paragraphEnd: paragraphIndex - 1,
            charStart: chunkStartChar,
            charEnd: chunkStartChar + currentChunk.length
          }
        ));
        
        // Start new chunk with overlap
        if (options.overlap! > 0 && chunks.length > 0) {
          const overlapText = this.getOverlapText(currentChunk, options.overlap!);
          currentChunk = overlapText + '\n\n' + paragraph;
          currentTokens = await this.estimateTokens(currentChunk);
          chunkStartChar = chunkStartChar + currentChunk.length - overlapText.length;
        } else {
          currentChunk = paragraph;
          currentTokens = paragraphTokens;
          chunkStartChar = section.startIndex + 
            paragraphs.slice(0, paragraphIndex).join('\n\n').length;
        }
      } else {
        // Add paragraph to current chunk
        currentChunk = currentChunk ? currentChunk + '\n\n' + paragraph : paragraph;
        currentTokens += paragraphTokens;
      }
      
      paragraphIndex++;
    }
    
    // Add final chunk
    if (currentChunk) {
      chunks.push(this.createChunk(
        currentChunk,
        document,
        startChunkIndex + chunks.length,
        {
          section: section.title,
          sectionLevel: section.level,
          paragraphStart: Math.max(0, paragraphIndex - 1),
          paragraphEnd: paragraphIndex - 1,
          charStart: chunkStartChar,
          charEnd: chunkStartChar + currentChunk.length
        }
      ));
    }
    
    return chunks;
  }

  /**
   * Chunk raw content when sections are not available
   */
  private async chunkContent(
    content: string,
    document: ExtractedDocument,
    startIndex: number,
    options: ChunkingOptions
  ): Promise<DocumentChunk[]> {
    const chunks: DocumentChunk[] = [];
    const sentences = this.splitIntoSentences(content);
    
    let currentChunk = '';
    let currentTokens = 0;
    let sentenceIndex = 0;
    let chunkStartChar = 0;
    
    for (const sentence of sentences) {
      const sentenceTokens = await this.estimateTokens(sentence);
      
      if (currentTokens + sentenceTokens > options.maxTokens! && currentChunk) {
        chunks.push(this.createChunk(
          currentChunk,
          document,
          chunks.length,
          {
            sentenceStart: Math.max(0, sentenceIndex - 1),
            sentenceEnd: sentenceIndex - 1,
            charStart: chunkStartChar,
            charEnd: chunkStartChar + currentChunk.length
          }
        ));
        
        // Handle overlap
        if (options.overlap! > 0) {
          const overlapText = this.getOverlapText(currentChunk, options.overlap!);
          currentChunk = overlapText + ' ' + sentence;
          currentTokens = await this.estimateTokens(currentChunk);
          chunkStartChar = chunkStartChar + currentChunk.length - overlapText.length;
        } else {
          currentChunk = sentence;
          currentTokens = sentenceTokens;
          chunkStartChar += currentChunk.length;
        }
      } else {
        currentChunk = currentChunk ? currentChunk + ' ' + sentence : sentence;
        currentTokens += sentenceTokens;
      }
      
      sentenceIndex++;
    }
    
    // Add final chunk
    if (currentChunk) {
      chunks.push(this.createChunk(
        currentChunk,
        document,
        chunks.length,
        {
          sentenceStart: Math.max(0, sentenceIndex - 1),
          sentenceEnd: sentenceIndex - 1,
          charStart: chunkStartChar,
          charEnd: chunkStartChar + currentChunk.length
        }
      ));
    }
    
    return chunks;
  }

  /**
   * Create a chunk with full citation information
   */
  private createChunk(
    content: string,
    document: ExtractedDocument,
    index: number,
    citation: Partial<CitationInfo>
  ): DocumentChunk {
    return {
      id: `${document.id}_chunk_${index}`,
      documentId: document.id,
      content,
      tokenCount: 0, // Will be updated later
      index,
      citation: {
        documentId: document.id,
        documentTitle: document.metadata.title || 'Untitled',
        ...citation
      } as CitationInfo,
      metadata: {
        ...document.metadata,
        chunkIndex: index
      }
    };
  }

  /**
   * Generate embeddings for chunks using Jina
   */
  private async generateEmbeddings(chunks: DocumentChunk[]): Promise<DocumentChunk[]> {
    console.log(`Generating embeddings for ${chunks.length} chunks`);
    
    const batchSize = 10; // Process in batches to avoid rate limits
    const results: DocumentChunk[] = [];
    
    for (let i = 0; i < chunks.length; i += batchSize) {
      const batch = chunks.slice(i, i + batchSize);
      const embeddings = await Promise.all(
        batch.map(chunk => this.jinaService.generateEmbedding(chunk.content))
      );
      
      // Merge embeddings with chunks
      batch.forEach((chunk, idx) => {
        const embedding = embeddings[idx];
        if (embedding.success && embedding.data) {
          chunk.embedding = embedding.data.embedding;
          chunk.tokenCount = embedding.data.usage?.totalTokens || 
            this.estimateTokensSync(chunk.content);
        }
        results.push(chunk);
      });
      
      // Small delay between batches
      if (i + batchSize < chunks.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    
    return results;
  }

  /**
   * Classify chunks using Jina
   */
  private async classifyChunks(chunks: DocumentChunk[]): Promise<DocumentChunk[]> {
    console.log(`Classifying ${chunks.length} chunks`);
    
    // Define classification labels based on our service themes
    const labels = [
      'ransomware_defense',
      'supply_chain_security', 
      'it_ot_convergence',
      'building_automation',
      'malware_analysis',
      'cyber_resilience',
      'business_continuity',
      'critical_infrastructure',
      'security_operations'
    ];
    
    for (const chunk of chunks) {
      try {
        const classification = await this.jinaService.classifyText(chunk.content, labels);
        if (classification.success && classification.data) {
          chunk.classification = {
            labels: classification.data.labels.slice(0, 3), // Top 3 labels
            scores: classification.data.scores.slice(0, 3)
          };
        }
      } catch (error) {
        console.error(`Error classifying chunk ${chunk.id}:`, error);
      }
    }
    
    return chunks;
  }

  /**
   * Store chunks in database
   */
  private async storeChunks(
    chunks: DocumentChunk[],
    transformationId: string
  ): Promise<void> {
    const { error } = await supabase
      .from('document_chunks')
      .insert(
        chunks.map(chunk => ({
          id: chunk.id,
          document_id: chunk.documentId,
          transformation_id: transformationId,
          content: chunk.content,
          embedding: chunk.embedding,
          token_count: chunk.tokenCount,
          chunk_index: chunk.index,
          citation: chunk.citation,
          classification: chunk.classification,
          metadata: chunk.metadata,
          created_at: new Date().toISOString()
        }))
      );

    if (error) {
      throw new Error(`Failed to store chunks: ${error.message}`);
    }
  }

  /**
   * Create transformation record
   */
  private async createTransformationRecord(documentId: string): Promise<string> {
    const { data, error } = await supabase
      .from('transformation_records')
      .insert({
        document_id: documentId,
        status: 'processing',
        started_at: new Date().toISOString()
      })
      .select('id')
      .single();

    if (error) {
      throw new Error(`Failed to create transformation record: ${error.message}`);
    }

    return data.id;
  }

  /**
   * Update transformation record
   */
  private async updateTransformationRecord(
    id: string,
    status: string,
    statistics?: any
  ): Promise<void> {
    const { error } = await supabase
      .from('transformation_records')
      .update({
        status,
        statistics,
        completed_at: status === 'completed' ? new Date().toISOString() : null
      })
      .eq('id', id);

    if (error) {
      throw new Error(`Failed to update transformation record: ${error.message}`);
    }
  }

  /**
   * Utility functions
   */
  private splitIntoParagraphs(text: string): string[] {
    return text.split(/\n\n+/).filter(p => p.trim().length > 0);
  }

  private splitIntoSentences(text: string): string[] {
    // Simple sentence splitter - could be enhanced with NLP library
    return text.match(/[^.!?]+[.!?]+/g) || [text];
  }

  private async estimateTokens(text: string): Promise<number> {
    // Rough estimate: 1 token ≈ 4 characters
    return Math.ceil(text.length / 4);
  }

  private estimateTokensSync(text: string): number {
    return Math.ceil(text.length / 4);
  }

  private getOverlapText(text: string, overlapTokens: number): string {
    // Get last N estimated tokens worth of text
    const chars = overlapTokens * 4;
    return text.slice(-chars);
  }

  /**
   * Batch processing for multiple documents
   */
  async transformDocuments(
    documents: ExtractedDocument[],
    options: ChunkingOptions = {}
  ): Promise<TransformationResult[]> {
    console.log(`Starting batch transformation for ${documents.length} documents`);
    
    const results: TransformationResult[] = [];
    
    for (const document of documents) {
      try {
        const result = await this.transformDocument(document, options);
        results.push(result);
      } catch (error) {
        console.error(`Error transforming document ${document.id}:`, error);
        // Continue with other documents
      }
    }
    
    return results;
  }
}