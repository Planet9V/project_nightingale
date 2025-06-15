import { 
  getCitationService,
  lookupCitation,
  lookupCitationsByChunkIds,
  formatCitationsForResponse,
  extractExactQuote
} from './index';
import { RAGService } from '../rag/RAGService';
import { logger } from '../../utils/logger';

/**
 * Example: RAG Query with Full Citation Support
 */
export async function performRAGQueryWithCitations(
  query: string,
  includeExactQuotes = true
): Promise<{
  answer: string;
  citations: any[];
  formattedCitations: string[];
}> {
  try {
    // 1. Get RAG service and perform semantic search
    const ragService = new RAGService();
    const searchResults = await ragService.semanticSearch(query, {
      topK: 5,
      includeMetadata: true
    });

    // 2. Extract vector IDs from search results
    const vectorIds = searchResults.matches.map(match => match.id);
    
    // 3. Lookup full citations for each vector
    const citationService = await getCitationService();
    const citations = await citationService.lookupBatch(
      vectorIds,
      'vector',
      { includeExactText: includeExactQuotes }
    );

    // 4. Generate answer using retrieved context
    const context = searchResults.matches.map(match => match.metadata?.text || '').join('\n\n');
    const answer = await ragService.generateAnswer(query, context);

    // 5. Format citations for display
    const formattedCitations = formatCitationsForResponse(citations, 'footnote');

    // 6. Return complete response
    return {
      answer,
      citations: Array.from(citations.values()),
      formattedCitations
    };
  } catch (error) {
    logger.error('Error in RAG query with citations:', error);
    throw error;
  }
}

/**
 * Example: Multi-Document Citation Aggregation
 */
export async function aggregateDocumentCitations(
  documentIds: string[]
): Promise<Map<string, any[]>> {
  try {
    const citationService = await getCitationService();
    const documentCitations = new Map<string, any[]>();

    // Get all chunks for each document
    for (const docId of documentIds) {
      // Query chunks for this document
      const chunks = await getChunksForDocument(docId);
      const chunkIds = chunks.map(c => c.id);
      
      // Lookup citations for all chunks
      const citations = await citationService.lookupBatch(chunkIds, 'chunk');
      
      documentCitations.set(docId, Array.from(citations.values()));
    }

    return documentCitations;
  } catch (error) {
    logger.error('Error aggregating document citations:', error);
    throw error;
  }
}

/**
 * Example: Verify and Extract Exact Quotes
 */
export async function verifyQuoteAccuracy(
  citationId: string,
  claimedQuote: string
): Promise<{
  isAccurate: boolean;
  actualQuote?: string;
  similarity: number;
}> {
  try {
    // 1. Lookup the citation
    const citation = await lookupCitation(citationId, true);
    if (!citation) {
      return { isAccurate: false, similarity: 0 };
    }

    // 2. Extract the exact text from source
    const actualQuote = citation.text;

    // 3. Compare with claimed quote
    const similarity = calculateTextSimilarity(claimedQuote, actualQuote);
    const isAccurate = similarity > 0.9; // 90% similarity threshold

    return {
      isAccurate,
      actualQuote,
      similarity
    };
  } catch (error) {
    logger.error('Error verifying quote accuracy:', error);
    throw error;
  }
}

/**
 * Example: Citation Chain Tracking
 */
export async function trackCitationChain(
  startingVectorId: string,
  depth = 3
): Promise<any[]> {
  try {
    const citationService = await getCitationService();
    const chain: any[] = [];
    const visited = new Set<string>();

    async function traverse(vectorId: string, currentDepth: number) {
      if (currentDepth >= depth || visited.has(vectorId)) {
        return;
      }
      
      visited.add(vectorId);
      
      // Get citation for this vector
      const citation = await citationService.lookupByVectorId(vectorId);
      if (!citation) return;
      
      chain.push({
        depth: currentDepth,
        citation
      });

      // Find related vectors (this would query your similarity index)
      const relatedVectors = await findRelatedVectors(vectorId);
      
      // Traverse related vectors
      for (const related of relatedVectors) {
        await traverse(related.id, currentDepth + 1);
      }
    }

    await traverse(startingVectorId, 0);
    return chain;
  } catch (error) {
    logger.error('Error tracking citation chain:', error);
    throw error;
  }
}

/**
 * Example: Generate Citation Report
 */
export async function generateCitationReport(
  queryResults: any[]
): Promise<string> {
  const report: string[] = ['# Citation Report\n'];
  
  // Group by source type
  const byType = new Map<string, any[]>();
  
  for (const result of queryResults) {
    const type = result.source.type;
    if (!byType.has(type)) {
      byType.set(type, []);
    }
    byType.get(type)!.push(result);
  }
  
  // Generate sections by type
  byType.forEach((citations, type) => {
    report.push(`\n## ${type.toUpperCase()} Sources (${citations.length})\n`);
    
    citations.forEach((citation, idx) => {
      report.push(`### ${idx + 1}. ${citation.source.title}`);
      report.push(`- **Date**: ${citation.source.publishedDate || 'Not specified'}`);
      report.push(`- **Confidence**: ${(citation.confidence * 100).toFixed(1)}%`);
      report.push(`- **Page**: ${citation.pageNumber || 'N/A'}`);
      if (citation.source.url) {
        report.push(`- **URL**: ${citation.source.url}`);
      }
      report.push(`- **Excerpt**: "${citation.text.substring(0, 200)}..."`);
      report.push('');
    });
  });
  
  // Add statistics
  report.push('\n## Statistics\n');
  report.push(`- Total Citations: ${queryResults.length}`);
  report.push(`- Source Types: ${byType.size}`);
  report.push(`- Average Confidence: ${
    (queryResults.reduce((sum, r) => sum + r.confidence, 0) / queryResults.length * 100).toFixed(1)
  }%`);
  
  return report.join('\n');
}

/**
 * Helper Functions
 */
async function getChunksForDocument(documentId: string): Promise<any[]> {
  // Implementation would query your database
  return [];
}

async function findRelatedVectors(vectorId: string): Promise<any[]> {
  // Implementation would query your vector index
  return [];
}

function calculateTextSimilarity(text1: string, text2: string): number {
  // Simple implementation - you might want to use a more sophisticated algorithm
  const words1 = text1.toLowerCase().split(/\s+/);
  const words2 = text2.toLowerCase().split(/\s+/);
  
  const set1 = new Set(words1);
  const set2 = new Set(words2);
  
  const intersection = new Set([...set1].filter(x => set2.has(x)));
  const union = new Set([...set1, ...set2]);
  
  return intersection.size / union.size;
}

/**
 * Example Usage
 */
async function exampleUsage() {
  // 1. Perform a query with citations
  const result = await performRAGQueryWithCitations(
    "What are the security implications of Volt Typhoon on critical infrastructure?"
  );
  
  console.log('Answer:', result.answer);
  console.log('\nCitations:');
  result.formattedCitations.forEach((citation, idx) => {
    console.log(`[${idx + 1}] ${citation}`);
  });

  // 2. Verify a quote
  const verification = await verifyQuoteAccuracy(
    'cite_123_456',
    'Volt Typhoon has been active since 2021'
  );
  
  console.log('\nQuote Verification:');
  console.log('Accurate:', verification.isAccurate);
  console.log('Similarity:', (verification.similarity * 100).toFixed(1) + '%');

  // 3. Generate citation report
  const report = await generateCitationReport(result.citations);
  console.log('\nCitation Report:');
  console.log(report);
}