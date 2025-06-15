#!/usr/bin/env node

const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs').promises;
const axios = require('axios');
const chalk = require('chalk');
const pdf = require('pdf-parse');

// Load environment variables
dotenv.config({ path: path.join(__dirname, '.env') });

async function testPDFProcessing() {
  console.log(chalk.cyan('\n📄 Testing ETL Pipeline with PDF Document\n'));
  
  // PDF to test - CISA advisory
  const pdfPath = path.join(
    __dirname,
    '../Current_advisories_2025_7_1/CISA Adds Five Known Exploited Vulnerabillities-2025_7_1.pdf'
  );
  
  try {
    // 1. Check if PDF exists
    console.log(chalk.yellow('1. Checking PDF file...'));
    try {
      const stats = await fs.stat(pdfPath);
      console.log(chalk.green(`   ✓ PDF found: ${(stats.size / 1024).toFixed(2)} KB`));
      console.log(chalk.gray(`   Path: ${path.basename(pdfPath)}`));
    } catch (error) {
      console.log(chalk.red('   ❌ PDF not found!'));
      return;
    }
    
    // 2. Read and parse PDF
    console.log(chalk.yellow('\n2. Reading PDF content...'));
    try {
      const dataBuffer = await fs.readFile(pdfPath);
      const data = await pdf(dataBuffer);
      
      console.log(chalk.green('   ✓ PDF parsed successfully'));
      console.log(chalk.gray(`   Pages: ${data.numpages}`));
      console.log(chalk.gray(`   Text length: ${data.text.length} characters`));
      
      // Show first 500 characters
      console.log(chalk.yellow('\n   First 500 characters:'));
      console.log(chalk.gray('   ' + data.text.substring(0, 500).replace(/\n/g, '\n   ')));
      
      // 3. Create chunks from PDF text
      console.log(chalk.yellow('\n3. Creating text chunks...'));
      const chunks = [];
      const chunkSize = 1500;
      const chunkOverlap = 200;
      
      // Clean text - remove excessive whitespace
      const cleanText = data.text.replace(/\s+/g, ' ').trim();
      
      for (let i = 0; i < cleanText.length; i += (chunkSize - chunkOverlap)) {
        const chunk = cleanText.slice(i, i + chunkSize);
        if (chunk.trim()) {
          chunks.push({
            text: chunk,
            startChar: i,
            endChar: Math.min(i + chunkSize, cleanText.length),
            pageInfo: `Chunk from PDF pages 1-${data.numpages}`
          });
        }
      }
      
      console.log(chalk.green(`   ✓ Created ${chunks.length} chunks`));
      console.log(chalk.gray(`   Average chunk size: ${Math.round(cleanText.length / chunks.length)} chars`));
      
      // 4. Test Jina API with first 2 chunks
      console.log(chalk.yellow('\n4. Testing Jina embeddings API...'));
      const testChunks = chunks.slice(0, 2).map(c => c.text);
      
      try {
        const response = await axios.post(
          'https://api.jina.ai/v1/embeddings',
          {
            model: 'jina-clip-v2',
            input: testChunks.map(text => ({ text }))
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
          console.log(chalk.green('   ✅ Jina API is working!'));
          console.log(chalk.gray(`   Model: ${response.data.model}`));
          console.log(chalk.gray(`   Embeddings: ${response.data.data.length}`));
          console.log(chalk.gray(`   Dimension: ${response.data.data[0].embedding.length}`));
          console.log(chalk.gray(`   Tokens used: ${response.data.usage.total_tokens}`));
          
          // Calculate cost estimate
          const tokensPerMillion = 1000000;
          const costPerMillion = 0.02; // $0.02 per 1M tokens
          const estimatedCost = (response.data.usage.total_tokens / tokensPerMillion) * costPerMillion;
          console.log(chalk.gray(`   Estimated cost: $${estimatedCost.toFixed(6)}`));
        }
        
      } catch (error) {
        if (error.response?.status === 402) {
          console.log(chalk.red('   ❌ Jina API: Payment Required'));
          console.log(chalk.yellow('   ⚠️  Your paid plan may not be active yet'));
        } else {
          console.log(chalk.red('   ❌ Jina API error:', error.message));
        }
      }
      
      // 5. Extract metadata from PDF
      console.log(chalk.yellow('\n5. Extracting PDF metadata...'));
      const metadata = {
        title: path.basename(pdfPath, '.pdf'),
        pages: data.numpages,
        textLength: data.text.length,
        chunks: chunks.length,
        type: 'CISA Advisory',
        date: '2025-07-01',
        source: 'CISA Known Exploited Vulnerabilities'
      };
      
      console.log(chalk.green('   ✓ Metadata extracted:'));
      Object.entries(metadata).forEach(([key, value]) => {
        console.log(chalk.gray(`     ${key}: ${value}`));
      });
      
      // 6. Summary
      console.log(chalk.cyan('\n📊 PDF Processing Summary:\n'));
      console.log(chalk.white('─'.repeat(60)));
      console.log(chalk.green(`Document: ${metadata.title}`));
      console.log(chalk.green(`Type: ${metadata.type}`));
      console.log(chalk.green(`Pages: ${metadata.pages}`));
      console.log(chalk.green(`Text extracted: ${(metadata.textLength / 1024).toFixed(2)} KB`));
      console.log(chalk.green(`Chunks created: ${metadata.chunks}`));
      console.log(chalk.green(`Ready for: Embeddings → Pinecone → Knowledge Graph`));
      console.log(chalk.white('─'.repeat(60)));
      
      // 7. Next steps
      console.log(chalk.cyan('\n🚀 Next Steps:\n'));
      console.log(chalk.white('1. Activate Jina paid plan'));
      console.log(chalk.white('2. Fix Supabase connection'));
      console.log(chalk.white('3. Run full ETL pipeline:'));
      console.log(chalk.gray('   npm run etl -- --input Current_advisories_2025_7_1 --file-pattern "\\.pdf$"'));
      
    } catch (error) {
      console.log(chalk.red('   ❌ Failed to parse PDF:', error.message));
      console.log(chalk.yellow('   Installing pdf-parse...'));
      
      // Try to install pdf-parse
      const { execSync } = require('child_process');
      try {
        execSync('npm install pdf-parse', { stdio: 'inherit' });
        console.log(chalk.green('   ✓ pdf-parse installed, please run again'));
      } catch (installError) {
        console.log(chalk.red('   ❌ Failed to install pdf-parse'));
      }
    }
    
  } catch (error) {
    console.log(chalk.red('\n❌ Test failed:', error.message));
    console.error(error);
  }
}

// Run the test
console.log(chalk.cyan('🚀 Starting PDF ETL Test...'));
testPDFProcessing().catch(console.error);