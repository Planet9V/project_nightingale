#!/usr/bin/env node

const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs').promises;
const axios = require('axios');
const chalk = require('chalk');

// Load environment variables
dotenv.config({ path: path.join(__dirname, '.env') });

async function testSingleDocument() {
  console.log(chalk.cyan('\n📄 Testing ETL Pipeline with Single Document\n'));
  
  const documentPath = path.join(
    __dirname,
    '../Annual_cyber_reports/Annual_cyber_reports_2023/Dragos-Year-In-Review-Report-2023.md'
  );
  
  try {
    // 1. Read the document
    console.log(chalk.yellow('1. Reading document...'));
    const content = await fs.readFile(documentPath, 'utf-8');
    console.log(chalk.green(`   ✓ Document loaded: ${content.length} characters`));
    
    // 2. Extract some text chunks (simple splitting for now)
    console.log(chalk.yellow('\n2. Creating text chunks...'));
    const chunks = [];
    const chunkSize = 1500;
    const chunkOverlap = 200;
    
    for (let i = 0; i < content.length; i += (chunkSize - chunkOverlap)) {
      const chunk = content.slice(i, i + chunkSize);
      if (chunk.trim()) {
        chunks.push({
          text: chunk,
          startChar: i,
          endChar: Math.min(i + chunkSize, content.length)
        });
      }
    }
    console.log(chalk.green(`   ✓ Created ${chunks.length} chunks`));
    
    // 3. Test Jina API with first 3 chunks
    console.log(chalk.yellow('\n3. Testing Jina embeddings API...'));
    const testChunks = chunks.slice(0, 3).map(c => c.text);
    
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
          }
        }
      );
      
      if (response.data && response.data.data) {
        console.log(chalk.green('   ✅ Jina API is working!'));
        console.log(chalk.gray(`   Model: ${response.data.model}`));
        console.log(chalk.gray(`   Embeddings: ${response.data.data.length}`));
        console.log(chalk.gray(`   Dimension: ${response.data.data[0].embedding.length}`));
        console.log(chalk.gray(`   Tokens used: ${response.data.usage.total_tokens}`));
      }
      
    } catch (error) {
      if (error.response?.status === 402) {
        console.log(chalk.red('   ❌ Jina API: Payment Required'));
        console.log(chalk.yellow('   ⚠️  Your paid plan may not be active yet'));
      } else {
        console.log(chalk.red('   ❌ Jina API error:', error.message));
      }
    }
    
    // 4. Test Supabase connection
    console.log(chalk.yellow('\n4. Testing Supabase connection...'));
    try {
      const supabaseUrl = process.env.SUPABASE_URL;
      const supabaseKey = process.env.SUPABASE_ANON_KEY;
      
      const response = await axios.get(
        `${supabaseUrl}/rest/v1/`,
        {
          headers: {
            'apikey': supabaseKey,
            'Authorization': `Bearer ${supabaseKey}`
          }
        }
      );
      
      console.log(chalk.green('   ✓ Supabase is accessible'));
      
    } catch (error) {
      console.log(chalk.red('   ❌ Supabase connection failed:', error.message));
    }
    
    // 5. Summary
    console.log(chalk.cyan('\n📊 Test Summary:\n'));
    console.log(chalk.white('─'.repeat(50)));
    console.log(chalk.green(`Document: ${path.basename(documentPath)}`));
    console.log(chalk.green(`Size: ${(content.length / 1024).toFixed(2)} KB`));
    console.log(chalk.green(`Chunks: ${chunks.length}`));
    console.log(chalk.green(`Avg chunk size: ${Math.round(content.length / chunks.length)} chars`));
    console.log(chalk.white('─'.repeat(50)));
    
  } catch (error) {
    console.log(chalk.red('\n❌ Test failed:', error.message));
  }
}

// Run the test
testSingleDocument().catch(console.error);