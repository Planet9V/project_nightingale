#!/usr/bin/env node

const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs').promises;
const axios = require('axios');
const chalk = require('chalk');
const pdf = require('pdf-parse');
const { Pinecone } = require('@pinecone-database/pinecone');

// Load environment variables - EXPLICIT PATH
const envPath = path.join(__dirname, '.env');
console.log(chalk.gray(`Loading .env from: ${envPath}`));
dotenv.config({ path: envPath });

// Verify key is loaded
const JINA_KEY = process.env.JINA_API_KEY || 'jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q';
console.log(chalk.gray(`Using Jina key: ${JINA_KEY.substring(0, 20)}...${JINA_KEY.substring(JINA_KEY.length - 10)}\n`));

async function testCompletePDFPipeline() {
  console.log(chalk.cyan('🚀 Testing Complete PDF → Embeddings → Pinecone Pipeline\n'));
  
  const pdfPath = path.join(
    __dirname,
    '../Current_advisories_2025_7_1/CISA Adds Five Known Exploited Vulnerabillities-2025_7_1.pdf'
  );
  
  try {
    // 1. Parse PDF
    console.log(chalk.yellow('1. Parsing PDF...'));
    const dataBuffer = await fs.readFile(pdfPath);
    const pdfData = await pdf(dataBuffer);
    const cleanText = pdfData.text.replace(/\s+/g, ' ').trim();
    
    console.log(chalk.green('   ✅ PDF parsed'));
    console.log(chalk.gray(`   Text: ${cleanText.substring(0, 100)}...`));
    
    // 2. Create chunks
    console.log(chalk.yellow('\n2. Creating chunks...'));
    const chunks = [];
    const chunkSize = 800;
    
    for (let i = 0; i < cleanText.length; i += chunkSize) {
      chunks.push({
        text: cleanText.slice(i, i + chunkSize),
        metadata: {
          source: 'CISA Advisory',
          chunkIndex: chunks.length,
          startChar: i
        }
      });
    }
    
    console.log(chalk.green(`   ✅ Created ${chunks.length} chunks`));
    
    // 3. Generate embeddings for first 2 chunks
    console.log(chalk.yellow('\n3. Generating embeddings with Jina...'));
    const testChunks = chunks.slice(0, 2);
    
    try {
      const response = await axios.post(
        'https://api.jina.ai/v1/embeddings',
        {
          model: 'jina-embeddings-v3',
          input: testChunks.map(c => c.text),
          task: 'retrieval.passage',
          dimensions: 768
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${JINA_KEY}`
          }
        }
      );
      
      console.log(chalk.green('   ✅ Embeddings generated!'));
      console.log(chalk.gray(`   Model: ${response.data.model}`));
      console.log(chalk.gray(`   Embeddings: ${response.data.data.length}`));
      console.log(chalk.gray(`   Dimensions: ${response.data.data[0].embedding.length}`));
      console.log(chalk.gray(`   Tokens used: ${response.data.usage.total_tokens}`));
      
      // 4. Store in Pinecone
      console.log(chalk.yellow('\n4. Storing in Pinecone...'));
      
      const pinecone = new Pinecone({
        apiKey: process.env.PINECONE_API_KEY
      });
      
      const index = pinecone.index('nightingale');
      
      // Prepare vectors
      const vectors = response.data.data.map((embed, i) => ({
        id: `cisa-advisory-chunk-${i}-${Date.now()}`,
        values: embed.embedding,
        metadata: {
          text: testChunks[i].text.substring(0, 200),
          source: 'CISA Advisory 2025-07-01',
          chunkIndex: i,
          documentType: 'security-advisory',
          date: '2025-07-01'
        }
      }));
      
      // Upsert to Pinecone
      await index.upsert(vectors);
      
      console.log(chalk.green(`   ✅ Stored ${vectors.length} vectors in Pinecone!`));
      
      // 5. Query to verify
      console.log(chalk.yellow('\n5. Querying Pinecone to verify...'));
      
      const queryText = 'ASUS router vulnerability';
      const queryResponse = await axios.post(
        'https://api.jina.ai/v1/embeddings',
        {
          model: 'jina-embeddings-v3',
          input: [queryText],
          task: 'retrieval.query',
          dimensions: 768
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${JINA_KEY}`
          }
        }
      );
      
      const queryEmbedding = queryResponse.data.data[0].embedding;
      
      const searchResults = await index.query({
        vector: queryEmbedding,
        topK: 2,
        includeMetadata: true
      });
      
      console.log(chalk.green('   ✅ Query successful!'));
      console.log(chalk.gray(`   Query: "${queryText}"`));
      console.log(chalk.gray('   Results:'));
      
      searchResults.matches.forEach((match, i) => {
        console.log(chalk.gray(`   ${i + 1}. Score: ${match.score.toFixed(4)}`));
        console.log(chalk.gray(`      Text: ${match.metadata.text}...`));
      });
      
      // Success summary
      console.log(chalk.cyan('\n✅ Complete Pipeline Success!\n'));
      console.log(chalk.white('─'.repeat(60)));
      console.log(chalk.green('PDF → Text → Chunks → Embeddings → Pinecone → Search'));
      console.log(chalk.white('─'.repeat(60)));
      console.log(chalk.green(`• Parsed: ${pdfData.numpages} page PDF`));
      console.log(chalk.green(`• Created: ${chunks.length} chunks`));
      console.log(chalk.green(`• Generated: ${response.data.data.length} embeddings (768d)`));
      console.log(chalk.green(`• Stored: ${vectors.length} vectors in Pinecone`));
      console.log(chalk.green(`• Searched: Found relevant results`));
      console.log(chalk.white('─'.repeat(60)));
      
    } catch (error) {
      console.log(chalk.red('   ❌ Error:', error.response?.data || error.message));
    }
    
  } catch (error) {
    console.log(chalk.red('❌ Pipeline failed:', error.message));
  }
}

// Run the test
testCompletePDFPipeline().catch(console.error);