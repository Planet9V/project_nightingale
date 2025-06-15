import { DocumentLoadingService } from './DocumentLoadingService';
import { TransformedDocument } from '../transformation/types';

// Example usage of the DocumentLoadingService
async function exampleUsage() {
  // Initialize the service with configuration
  const loadingService = new DocumentLoadingService({
    supabase: {
      connectionString: process.env.SUPABASE_CONNECTION_STRING!,
      schema: 'psychohistory',
    },
    pinecone: {
      apiKey: process.env.PINECONE_API_KEY!,
      environment: process.env.PINECONE_ENVIRONMENT!,
      indexName: 'psychohistory-docs',
      namespace: 'research-papers',
    },
    neo4j: {
      uri: process.env.NEO4J_URI!,
      username: process.env.NEO4J_USERNAME!,
      password: process.env.NEO4J_PASSWORD!,
      database: 'psychohistory',
    },
    batchSize: 50,
    maxConcurrency: 3,
  });

  // Check database health before loading
  const health = await loadingService.healthCheck();
  console.log('Database health:', health);

  // Example transformed document
  const sampleDocument: TransformedDocument = {
    id: 'doc-001',
    title: 'Psychohistorical Analysis of Critical Infrastructure Protection',
    authors: ['Hari Seldon', 'Gaal Dornick'],
    publicationDate: new Date('2024-01-15'),
    abstract: 'This paper presents a mathematical framework for predicting critical infrastructure vulnerabilities...',
    keywords: ['psychohistory', 'critical infrastructure', 'predictive analytics', 'cybersecurity'],
    methodology: 'We employed statistical mechanics and chaos theory to model infrastructure interdependencies...',
    keyFindings: 'Our model successfully predicted 87% of critical failure cascades in simulated environments...',
    limitations: 'The model requires extensive historical data and may not account for black swan events...',
    futureWork: 'Future research will focus on incorporating quantum computing threats and AI-driven attacks...',
    chunks: [
      {
        id: 'chunk-001-001',
        index: 0,
        content: 'Introduction: The field of psychohistory, as applied to critical infrastructure protection...',
        embedding: new Array(1536).fill(0).map(() => Math.random()), // Mock embedding
        citations: [
          {
            text: 'As demonstrated by Smith et al. (2023), infrastructure interdependencies create cascading failures...',
            authors: ['Smith, J.', 'Johnson, K.', 'Williams, L.'],
            year: 2023,
            title: 'Cascading Failures in Critical Infrastructure Networks',
            journal: 'Journal of Infrastructure Security',
            doi: '10.1234/jis.2023.001',
            url: 'https://doi.org/10.1234/jis.2023.001',
            type: 'direct',
            confidenceScore: 0.95,
          },
        ],
        metadata: {
          sectionTitle: 'Introduction',
          chunkType: 'introduction',
          startPage: 1,
          endPage: 2,
        },
      },
      {
        id: 'chunk-001-002',
        index: 1,
        content: 'Methodology: Our psychohistorical approach combines multiple mathematical disciplines...',
        embedding: new Array(1536).fill(0).map(() => Math.random()), // Mock embedding
        citations: [
          {
            text: 'The mathematical foundation draws from Asimov\'s original formulation (1951)...',
            authors: ['Asimov, I.'],
            year: 1951,
            title: 'Foundation',
            journal: 'Astounding Science Fiction',
            type: 'indirect',
            confidenceScore: 0.85,
          },
        ],
        metadata: {
          sectionTitle: 'Methodology',
          chunkType: 'methodology',
          startPage: 3,
          endPage: 5,
        },
      },
    ],
    metadata: {
      collectionId: 'critical-infrastructure-2024',
      documentType: 'paper',
      sourceUrl: 'https://arxiv.org/abs/2024.12345',
      processingDate: new Date(),
      version: '1.0',
      tags: ['security', 'infrastructure', 'predictive-modeling'],
    },
  };

  // Load the document
  const results = await loadingService.loadDocuments([sampleDocument]);
  
  console.log('Loading results:');
  results.forEach(result => {
    console.log(`Document ${result.documentId}:`);
    console.log(`  Status: ${result.status}`);
    console.log(`  Supabase ID: ${result.supabaseId}`);
    console.log(`  Pinecone IDs: ${result.pineconeIds?.length} chunks`);
    console.log(`  Neo4j Node ID: ${result.neo4jNodeId}`);
    if (result.errors && result.errors.length > 0) {
      console.log('  Errors:');
      result.errors.forEach(err => {
        console.log(`    - ${err.database}: ${err.error}`);
      });
    }
  });

  // Cleanup
  await loadingService.close();
}

// Run the example
if (require.main === module) {
  exampleUsage()
    .then(() => {
      console.log('Example completed successfully');
      process.exit(0);
    })
    .catch(error => {
      console.error('Example failed:', error);
      process.exit(1);
    });
}