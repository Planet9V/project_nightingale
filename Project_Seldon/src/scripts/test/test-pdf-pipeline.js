#!/usr/bin/env node

const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs').promises;
const axios = require('axios');
const chalk = require('chalk');
const pdf = require('pdf-parse');
const { Pinecone } = require('@pinecone-database/pinecone');

// Load environment variables
dotenv.config({ path: path.join(__dirname, '.env') });

async function testPDFPipeline() {
  console.log(chalk.cyan('\n🔧 Testing Complete PDF ETL Pipeline\n'));
  
  const pdfPath = path.join(
    __dirname,
    '../Current_advisories_2025_7_1/CISA Adds Five Known Exploited Vulnerabillities-2025_7_1.pdf'
  );
  
  const results = {
    pdfParsing: false,
    textExtraction: false,
    chunking: false,
    jinaAPI: false,
    pinecone: false,
    supabase: false
  };
  
  try {
    // 1. PDF Parsing & Text Extraction
    console.log(chalk.yellow('1. PDF Parsing & Text Extraction...'));
    let pdfText = '';
    let pdfMetadata = {};
    
    try {
      const dataBuffer = await fs.readFile(pdfPath);
      const pdfData = await pdf(dataBuffer);
      
      pdfText = pdfData.text.replace(/\s+/g, ' ').trim();
      pdfMetadata = {
        title: path.basename(pdfPath, '.pdf'),
        pages: pdfData.numpages,
        textLength: pdfText.length,
        info: pdfData.info || {}
      };
      
      console.log(chalk.green('   ✅ PDF parsed successfully'));
      console.log(chalk.gray(`   Title: ${pdfMetadata.title}`));
      console.log(chalk.gray(`   Pages: ${pdfMetadata.pages}`));
      console.log(chalk.gray(`   Text: ${pdfMetadata.textLength} characters`));
      results.pdfParsing = true;
      results.textExtraction = true;
      
    } catch (error) {
      console.log(chalk.red('   ❌ PDF parsing failed:', error.message));
    }
    
    // 2. Text Chunking
    console.log(chalk.yellow('\n2. Text Chunking...'));
    let chunks = [];
    
    try {
      const chunkSize = 1000;
      const chunkOverlap = 200;
      
      for (let i = 0; i < pdfText.length; i += (chunkSize - chunkOverlap)) {
        const chunk = pdfText.slice(i, i + chunkSize);
        if (chunk.trim()) {
          chunks.push({
            id: `chunk-${i}`,
            text: chunk,
            metadata: {
              source: pdfMetadata.title,
              chunkIndex: chunks.length,
              startChar: i,
              endChar: Math.min(i + chunkSize, pdfText.length)
            }
          });
        }
      }
      
      console.log(chalk.green(`   ✅ Created ${chunks.length} chunks`));
      console.log(chalk.gray(`   Chunk size: ${chunkSize} chars`));
      console.log(chalk.gray(`   Overlap: ${chunkOverlap} chars`));
      results.chunking = true;
      
    } catch (error) {
      console.log(chalk.red('   ❌ Chunking failed:', error.message));
    }
    
    // 3. Jina Embeddings Test
    console.log(chalk.yellow('\n3. Testing Jina Embeddings...'));
    let embeddings = [];
    
    try {
      // Test with just first chunk
      const testChunk = chunks[0];
      
      const response = await axios.post(
        'https://api.jina.ai/v1/embeddings',
        {
          model: 'jina-embeddings-v3',
          input: [testChunk.text],
          task: 'retrieval.passage',
          dimensions: 768
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${process.env.JINA_API_KEY}`
          },
          timeout: 30000
        }
      );
      
      if (response.data && response.data.data) {
        embeddings = response.data.data;
        console.log(chalk.green('   ✅ Jina API working'));
        console.log(chalk.gray(`   Model: ${response.data.model}`));
        console.log(chalk.gray(`   Dimension: ${response.data.data[0].embedding.length}`));
        console.log(chalk.gray(`   Tokens: ${response.data.usage.total_tokens}`));
        results.jinaAPI = true;
      }
      
    } catch (error) {
      if (error.response?.status === 402) {
        console.log(chalk.red('   ❌ Jina API: Payment Required'));
        console.log(chalk.yellow('      Need to activate paid plan'));
      } else {
        console.log(chalk.red('   ❌ Jina API error:', error.message));
      }
    }
    
    // 4. Pinecone Test
    console.log(chalk.yellow('\n4. Testing Pinecone Connection...'));
    
    try {
      const pinecone = new Pinecone({
        apiKey: process.env.PINECONE_API_KEY
      });
      
      const index = pinecone.index('nightingale');
      const stats = await index.describeIndexStats();
      
      console.log(chalk.green('   ✅ Pinecone connected'));
      console.log(chalk.gray(`   Index: nightingale`));
      console.log(chalk.gray(`   Dimension: 768`));
      console.log(chalk.gray(`   Vectors: ${stats.totalRecordCount || 0}`));
      console.log(chalk.gray(`   Ready for embeddings`));
      results.pinecone = true;
      
    } catch (error) {
      console.log(chalk.red('   ❌ Pinecone error:', error.message));
    }
    
    // 5. Supabase Test
    console.log(chalk.yellow('\n5. Testing Supabase Connection...'));
    
    try {
      const response = await axios.get(
        `${process.env.SUPABASE_URL}/rest/v1/`,
        {
          headers: {
            'apikey': process.env.SUPABASE_ANON_KEY,
            'Authorization': `Bearer ${process.env.SUPABASE_ANON_KEY}`
          },
          timeout: 5000
        }
      );
      
      console.log(chalk.green('   ✅ Supabase connected'));
      console.log(chalk.gray('   Ready for document storage'));
      results.supabase = true;
      
    } catch (error) {
      console.log(chalk.red('   ❌ Supabase error:', error.message));
      if (error.code === 'ECONNABORTED') {
        console.log(chalk.yellow('      Connection timeout - check network'));
      }
    }
    
    // 6. Summary
    console.log(chalk.cyan('\n📊 Pipeline Test Summary:\n'));
    console.log(chalk.white('─'.repeat(50)));
    
    const components = [
      { name: 'PDF Parsing', status: results.pdfParsing },
      { name: 'Text Extraction', status: results.textExtraction },
      { name: 'Chunking', status: results.chunking },
      { name: 'Jina API', status: results.jinaAPI },
      { name: 'Pinecone', status: results.pinecone },
      { name: 'Supabase', status: results.supabase }
    ];
    
    components.forEach(comp => {
      const icon = comp.status ? '✅' : '❌';
      const color = comp.status ? chalk.green : chalk.red;
      console.log(`${icon} ${color(comp.name.padEnd(20))} ${comp.status ? 'Ready' : 'Failed'}`);
    });
    
    console.log(chalk.white('─'.repeat(50)));
    
    const readyCount = Object.values(results).filter(v => v).length;
    const totalCount = Object.values(results).length;
    
    if (readyCount === totalCount) {
      console.log(chalk.green('\n✅ All components ready! Pipeline can process PDFs.'));
    } else {
      console.log(chalk.yellow(`\n⚠️  ${readyCount}/${totalCount} components ready`));
      console.log(chalk.yellow('   Fix failed components before running full pipeline'));
    }
    
    // 7. Sample pipeline command
    console.log(chalk.cyan('\n🚀 To process all PDFs in a directory:\n'));
    console.log(chalk.white('npm run etl -- \\'));
    console.log(chalk.white('  --input Current_advisories_2025_7_1 \\'));
    console.log(chalk.white('  --file-pattern "\\.pdf$" \\'));
    console.log(chalk.white('  --max-files 5'));
    
  } catch (error) {
    console.log(chalk.red('\n❌ Pipeline test failed:', error.message));
    console.error(error);
  }
}

// Run health check first
console.log(chalk.cyan('🏥 Running MCP Health Check first...\n'));
const { execSync } = require('child_process');
try {
  execSync('node src/scripts/check-mcp-health.js', { stdio: 'inherit' });
} catch (error) {
  console.log(chalk.yellow('\n⚠️  Some MCP services need attention'));
}

// Run pipeline test
console.log(chalk.cyan('\n─────────────────────────────────────────'));
testPDFPipeline().catch(console.error);