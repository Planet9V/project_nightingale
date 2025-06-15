/**
 * Citation Tracker Service for Project Seldon
 * Provides character-level citation support for document traceability
 */

import { logger } from '../utils/logger';
import { 
  Citation,
  CitationReference,
  CitationType,
  ExtractedDocument,
  DocumentChunk
} from '../types/index';
import crypto from 'crypto';

export interface CitationOptions {
  includeLineNumbers?: boolean;
  includeCharOffsets?: boolean;
  includeContext?: boolean;
  contextLength?: number;
}

export interface CitationResult {
  citation: Citation;
  references: CitationReference[];
  metadata: CitationMetadata;
}

export interface CitationMetadata {
  totalReferences: number;
  uniqueSources: number;
  citationTypes: Record<string, number>;
  confidence: number;
}

export class CitationTracker {
  private citationCache: Map<string, Citation> = new Map();
  private referenceIndex: Map<string, CitationReference[]> = new Map();

  /**
   * Create citation for a text segment
   */
  public createCitation(
    text: string,
    document: ExtractedDocument,
    startOffset: number,
    endOffset: number,
    options: CitationOptions = {}
  ): Citation {
    const citationId = this.generateCitationId(document.id, startOffset, endOffset);
    
    // Check cache
    if (this.citationCache.has(citationId)) {
      return this.citationCache.get(citationId)!;
    }

    // Calculate line numbers if requested
    let startLine = 1;
    let endLine = 1;
    let startColumn = 1;
    let endColumn = 1;

    if (options.includeLineNumbers) {
      const lines = document.content.substring(0, startOffset).split('\n');
      startLine = lines.length;
      startColumn = lines[lines.length - 1].length + 1;

      const endLines = document.content.substring(0, endOffset).split('\n');
      endLine = endLines.length;
      endColumn = endLines[endLines.length - 1].length + 1;
    }

    // Extract context if requested
    let context = '';
    if (options.includeContext) {
      const contextLength = options.contextLength || 50;
      const contextStart = Math.max(0, startOffset - contextLength);
      const contextEnd = Math.min(document.content.length, endOffset + contextLength);
      context = document.content.substring(contextStart, contextEnd);
    }

    const citation: Citation = {
      id: citationId,
      documentId: document.id,
      type: this.determineCitationType(text),
      startOffset,
      endOffset,
      startLine,
      endLine,
      startColumn,
      endColumn,
      text,
      context,
      confidence: this.calculateConfidence(text, document),
      metadata: {
        source: document.metadata.source,
        title: document.metadata.title,
        author: document.metadata.author,
        createdAt: document.metadata.createdAt,
      },
    };

    this.citationCache.set(citationId, citation);
    return citation;
  }

  /**
   * Create citations for an entire chunk
   */
  public createChunkCitations(
    chunk: DocumentChunk,
    document: ExtractedDocument,
    options: CitationOptions = {}
  ): Citation[] {
    const citations: Citation[] = [];
    
    // Create main citation for the chunk
    const mainCitation = this.createCitation(
      chunk.content,
      document,
      chunk.startOffset,
      chunk.endOffset,
      options
    );
    citations.push(mainCitation);

    // Extract entity citations if present
    const entityCitations = this.extractEntityCitations(chunk, document, options);
    citations.push(...entityCitations);

    return citations;
  }

  /**
   * Track citation reference
   */
  public trackReference(
    fromDocumentId: string,
    toCitation: Citation,
    referenceText: string,
    confidence: number = 1.0
  ): CitationReference {
    const reference: CitationReference = {
      id: this.generateReferenceId(fromDocumentId, toCitation.id),
      fromDocumentId,
      toCitationId: toCitation.id,
      toDocumentId: toCitation.documentId,
      referenceText,
      confidence,
      createdAt: new Date(),
      metadata: {},
    };

    // Update reference index
    const key = `${fromDocumentId}:${toCitation.documentId}`;
    if (!this.referenceIndex.has(key)) {
      this.referenceIndex.set(key, []);
    }
    this.referenceIndex.get(key)!.push(reference);

    return reference;
  }

  /**
   * Find citations in text
   */
  public findCitations(
    text: string,
    documents: ExtractedDocument[],
    options: CitationOptions = {}
  ): CitationResult[] {
    const results: CitationResult[] = [];
    
    for (const document of documents) {
      const matches = this.findTextMatches(text, document.content);
      
      for (const match of matches) {
        const citation = this.createCitation(
          match.text,
          document,
          match.startOffset,
          match.endOffset,
          options
        );

        const references = this.findReferences(citation);
        
        results.push({
          citation,
          references,
          metadata: this.generateCitationMetadata(citation, references),
        });
      }
    }

    return results;
  }

  /**
   * Merge citations from multiple sources
   */
  public mergeCitations(
    citations: Citation[],
    strategy: 'union' | 'intersection' = 'union'
  ): Citation[] {
    if (citations.length === 0) return [];
    if (citations.length === 1) return citations;

    const merged: Map<string, Citation> = new Map();
    
    if (strategy === 'union') {
      // Include all unique citations
      for (const citation of citations) {
        const key = `${citation.documentId}:${citation.startOffset}:${citation.endOffset}`;
        if (!merged.has(key)) {
          merged.set(key, citation);
        }
      }
    } else {
      // Include only citations that appear in all sources
      const citationGroups = new Map<string, Citation[]>();
      
      for (const citation of citations) {
        const key = `${citation.documentId}:${citation.text}`;
        if (!citationGroups.has(key)) {
          citationGroups.set(key, []);
        }
        citationGroups.get(key)!.push(citation);
      }

      for (const [key, group] of citationGroups) {
        if (group.length === citations.length) {
          merged.set(key, group[0]);
        }
      }
    }

    return Array.from(merged.values());
  }

  /**
   * Validate citation accuracy
   */
  public validateCitation(
    citation: Citation,
    document: ExtractedDocument
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check document ID match
    if (citation.documentId !== document.id) {
      errors.push(`Document ID mismatch: ${citation.documentId} !== ${document.id}`);
    }

    // Check offset bounds
    if (citation.startOffset < 0 || citation.startOffset >= document.content.length) {
      errors.push(`Start offset out of bounds: ${citation.startOffset}`);
    }
    if (citation.endOffset <= citation.startOffset || citation.endOffset > document.content.length) {
      errors.push(`End offset out of bounds: ${citation.endOffset}`);
    }

    // Check text match
    if (errors.length === 0) {
      const extractedText = document.content.substring(citation.startOffset, citation.endOffset);
      if (extractedText !== citation.text) {
        errors.push(`Text mismatch at offsets ${citation.startOffset}-${citation.endOffset}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Generate citation report
   */
  public generateReport(
    citations: Citation[],
    format: 'json' | 'markdown' = 'markdown'
  ): string {
    if (format === 'json') {
      return JSON.stringify({
        totalCitations: citations.length,
        byType: this.groupByType(citations),
        byDocument: this.groupByDocument(citations),
        citations: citations.map(c => ({
          id: c.id,
          documentId: c.documentId,
          type: c.type,
          text: c.text.substring(0, 100) + (c.text.length > 100 ? '...' : ''),
          location: `${c.startLine}:${c.startColumn}-${c.endLine}:${c.endColumn}`,
          confidence: c.confidence,
        })),
      }, null, 2);
    }

    // Markdown format
    let report = '# Citation Report\n\n';
    report += `Total Citations: ${citations.length}\n\n`;
    
    report += '## Citations by Type\n';
    const byType = this.groupByType(citations);
    for (const [type, count] of Object.entries(byType)) {
      report += `- ${type}: ${count}\n`;
    }
    
    report += '\n## Citations by Document\n';
    const byDocument = this.groupByDocument(citations);
    for (const [docId, docCitations] of Object.entries(byDocument)) {
      report += `\n### ${docId}\n`;
      for (const citation of docCitations) {
        report += `- **[${citation.type}]** Line ${citation.startLine}: "${citation.text.substring(0, 50)}..."\n`;
      }
    }

    return report;
  }

  /**
   * Clear citation cache
   */
  public clearCache(): void {
    this.citationCache.clear();
    this.referenceIndex.clear();
    logger.debug('Citation cache cleared');
  }

  /**
   * Get cache statistics
   */
  public getCacheStats(): {
    citationCount: number;
    referenceCount: number;
    memorySizeEstimate: number;
  } {
    let referenceCount = 0;
    for (const refs of this.referenceIndex.values()) {
      referenceCount += refs.length;
    }

    // Rough memory estimate
    const memorySizeEstimate = 
      this.citationCache.size * 1024 + // ~1KB per citation
      referenceCount * 512; // ~512B per reference

    return {
      citationCount: this.citationCache.size,
      referenceCount,
      memorySizeEstimate,
    };
  }

  // Private helper methods

  private generateCitationId(documentId: string, startOffset: number, endOffset: number): string {
    const input = `${documentId}:${startOffset}:${endOffset}`;
    return crypto.createHash('sha256').update(input).digest('hex').substring(0, 16);
  }

  private generateReferenceId(fromDocumentId: string, toCitationId: string): string {
    const input = `${fromDocumentId}:${toCitationId}:${Date.now()}`;
    return crypto.createHash('sha256').update(input).digest('hex').substring(0, 16);
  }

  private determineCitationType(text: string): CitationType {
    // Simple heuristics - can be improved with ML
    if (text.match(/^\d+\./)) return CitationType.NUMBERED_REFERENCE;
    if (text.match(/^[A-Z][a-z]+ \(\d{4}\)/)) return CitationType.AUTHOR_DATE;
    if (text.match(/https?:\/\//)) return CitationType.URL;
    if (text.match(/10\.\d{4,}/)) return CitationType.DOI;
    if (text.match(/^".+"$/)) return CitationType.QUOTE;
    return CitationType.INLINE;
  }

  private calculateConfidence(text: string, document: ExtractedDocument): number {
    // Simple confidence calculation - can be improved
    let confidence = 1.0;
    
    // Reduce confidence for very short citations
    if (text.length < 10) confidence *= 0.8;
    
    // Reduce confidence for generic text
    if (text.match(/^(the|a|an|this|that|these|those)\s/i)) confidence *= 0.9;
    
    // Increase confidence for quoted text
    if (text.match(/^["'].*["']$/)) confidence = Math.min(confidence * 1.2, 1.0);
    
    return confidence;
  }

  private findTextMatches(
    searchText: string,
    content: string
  ): Array<{ text: string; startOffset: number; endOffset: number }> {
    const matches: Array<{ text: string; startOffset: number; endOffset: number }> = [];
    
    // Simple exact match - can be improved with fuzzy matching
    let index = content.indexOf(searchText);
    while (index !== -1) {
      matches.push({
        text: searchText,
        startOffset: index,
        endOffset: index + searchText.length,
      });
      index = content.indexOf(searchText, index + 1);
    }
    
    return matches;
  }

  private extractEntityCitations(
    chunk: DocumentChunk,
    document: ExtractedDocument,
    options: CitationOptions
  ): Citation[] {
    const citations: Citation[] = [];
    
    // Extract URLs
    const urlRegex = /https?:\/\/[^\s]+/g;
    let match;
    while ((match = urlRegex.exec(chunk.content)) !== null) {
      const citation = this.createCitation(
        match[0],
        document,
        chunk.startOffset + match.index,
        chunk.startOffset + match.index + match[0].length,
        options
      );
      citations.push(citation);
    }
    
    // Extract DOIs
    const doiRegex = /10\.\d{4,}\/[-._;()\/:a-zA-Z0-9]+/g;
    while ((match = doiRegex.exec(chunk.content)) !== null) {
      const citation = this.createCitation(
        match[0],
        document,
        chunk.startOffset + match.index,
        chunk.startOffset + match.index + match[0].length,
        options
      );
      citations.push(citation);
    }
    
    return citations;
  }

  private findReferences(citation: Citation): CitationReference[] {
    const key = `*:${citation.documentId}`;
    const references: CitationReference[] = [];
    
    for (const [indexKey, refs] of this.referenceIndex) {
      if (indexKey.endsWith(`:${citation.documentId}`)) {
        references.push(...refs.filter(ref => ref.toCitationId === citation.id));
      }
    }
    
    return references;
  }

  private generateCitationMetadata(
    citation: Citation,
    references: CitationReference[]
  ): CitationMetadata {
    const uniqueSources = new Set(references.map(ref => ref.fromDocumentId));
    const citationTypes: Record<string, number> = {};
    
    citationTypes[citation.type] = 1;
    
    return {
      totalReferences: references.length,
      uniqueSources: uniqueSources.size,
      citationTypes,
      confidence: citation.confidence,
    };
  }

  private groupByType(citations: Citation[]): Record<string, number> {
    const groups: Record<string, number> = {};
    
    for (const citation of citations) {
      groups[citation.type] = (groups[citation.type] || 0) + 1;
    }
    
    return groups;
  }

  private groupByDocument(citations: Citation[]): Record<string, Citation[]> {
    const groups: Record<string, Citation[]> = {};
    
    for (const citation of citations) {
      if (!groups[citation.documentId]) {
        groups[citation.documentId] = [];
      }
      groups[citation.documentId].push(citation);
    }
    
    return groups;
  }
}