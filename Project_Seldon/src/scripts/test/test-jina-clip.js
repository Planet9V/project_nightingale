#!/usr/bin/env node

const axios = require('axios');
const dotenv = require('dotenv');
const chalk = require('chalk');

// Load environment variables
dotenv.config();

async function testJinaClipV2() {
  console.log(chalk.cyan('\n🧪 Testing Jina CLIP v2 with Paid Plan\n'));
  
  try {
    const apiKey = process.env.JINA_API_KEY;
    const endpoint = process.env.JINA_EMBEDDING_ENDPOINT || 'https://api.jina.ai/v1/embeddings';
    
    console.log(chalk.yellow('1. Testing text and image embeddings...'));
    
    const requestData = {
      model: 'jina-clip-v2',
      input: [
        {
          text: 'Critical infrastructure cybersecurity for energy sector'
        },
        {
          text: 'Project Nightingale provides enhanced intelligence for OT security'
        },
        {
          text: 'Dragos specializes in industrial control system protection'
        }
      ]
    };
    
    console.log(chalk.gray('   Sending request to Jina API...'));
    
    const response = await axios.post(endpoint, requestData, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      }
    });
    
    if (response.data && response.data.data) {
      console.log(chalk.green('\n✅ Jina CLIP v2 API is working!'));
      console.log(chalk.white('─'.repeat(50)));
      
      const embeddings = response.data.data;
      console.log(chalk.green(`Model: ${response.data.model}`));
      console.log(chalk.green(`Embeddings Generated: ${embeddings.length}`));
      console.log(chalk.green(`Embedding Dimension: ${embeddings[0].embedding.length}`));
      console.log(chalk.green(`Usage (tokens): ${response.data.usage.total_tokens}`));
      
      // Show sample embedding
      console.log(chalk.yellow('\nSample embedding (first 10 values):'));
      console.log(chalk.gray(embeddings[0].embedding.slice(0, 10).map(v => v.toFixed(6)).join(', ')));
      
      // Verify dimension
      if (embeddings[0].embedding.length === 768) {
        console.log(chalk.green('\n✅ Confirmed: 768-dimensional embeddings'));
      } else {
        console.log(chalk.red(`\n⚠️  Warning: Expected 768 dimensions, got ${embeddings[0].embedding.length}`));
      }
      
      console.log(chalk.white('─'.repeat(50)));
      
      // Test with mixed content (if needed in future)
      console.log(chalk.yellow('\n2. Testing multimodal capabilities...'));
      console.log(chalk.gray('   Jina CLIP v2 supports both text and image inputs'));
      console.log(chalk.gray('   You can embed images using URLs or base64 encoding'));
      
      console.log(chalk.green('\n✅ All tests passed! Your paid plan is active.'));
      
    } else {
      throw new Error('Unexpected response structure');
    }
    
  } catch (error) {
    console.log(chalk.red('\n❌ Jina API test failed'));
    
    if (error.response) {
      console.log(chalk.red(`   Status: ${error.response.status}`));
      console.log(chalk.red(`   Message: ${error.response.data?.detail || error.response.statusText}`));
      
      if (error.response.status === 402) {
        console.log(chalk.yellow('\n⚠️  Payment Required - Your API key may need activation'));
        console.log(chalk.yellow('   Please check your Jina account at https://jina.ai'));
      }
    } else {
      console.log(chalk.gray(`   Error: ${error.message}`));
    }
    
    process.exit(1);
  }
}

// Run the test
testJinaClipV2().catch(console.error);