#!/usr/bin/env node

const axios = require('axios');
const chalk = require('chalk');

async function testJinaSimple() {
  console.log(chalk.cyan('\n🧪 Testing Jina API with Simple Request\n'));
  
  const apiKey = 'jina_22fcccb12b074e1e8031ad132783af842yMCjxeInP4j_Ncx31_5LAPEdt0q';
  
  console.log(chalk.yellow('Testing with different models...'));
  
  // Test 1: Try jina-embeddings-v2-base-en
  console.log(chalk.gray('\n1. Testing jina-embeddings-v2-base-en...'));
  try {
    const response = await axios.post(
      'https://api.jina.ai/v1/embeddings',
      {
        model: 'jina-embeddings-v2-base-en',
        input: ['Test embedding for Project Seldon']
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        }
      }
    );
    
    console.log(chalk.green('   ✅ Success!'));
    console.log(chalk.gray(`   Model: ${response.data.model}`));
    console.log(chalk.gray(`   Dimensions: ${response.data.data[0].embedding.length}`));
    console.log(chalk.gray(`   Usage: ${JSON.stringify(response.data.usage)}`));
    
  } catch (error) {
    console.log(chalk.red(`   ❌ Failed: ${error.response?.status} - ${error.response?.data?.detail || error.message}`));
  }
  
  // Test 2: Try jina-embeddings-v3
  console.log(chalk.gray('\n2. Testing jina-embeddings-v3...'));
  try {
    const response = await axios.post(
      'https://api.jina.ai/v1/embeddings',
      {
        model: 'jina-embeddings-v3',
        input: ['Test embedding for Project Seldon'],
        task: 'retrieval.passage',
        dimensions: 768
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        }
      }
    );
    
    console.log(chalk.green('   ✅ Success!'));
    console.log(chalk.gray(`   Model: ${response.data.model}`));
    console.log(chalk.gray(`   Dimensions: ${response.data.data[0].embedding.length}`));
    console.log(chalk.gray(`   Usage: ${JSON.stringify(response.data.usage)}`));
    
  } catch (error) {
    console.log(chalk.red(`   ❌ Failed: ${error.response?.status} - ${error.response?.data?.detail || error.message}`));
  }
  
  // Test 3: Try jina-clip-v2 with proper format
  console.log(chalk.gray('\n3. Testing jina-clip-v2 (multimodal)...'));
  try {
    const response = await axios.post(
      'https://api.jina.ai/v1/embeddings',
      {
        model: 'jina-clip-v2',
        input: [{
          text: 'Test embedding for Project Seldon'
        }],
        normalized: true,
        embedding_type: 'float'
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        }
      }
    );
    
    console.log(chalk.green('   ✅ Success!'));
    console.log(chalk.gray(`   Model: ${response.data.model}`));
    console.log(chalk.gray(`   Dimensions: ${response.data.data[0].embedding.length}`));
    console.log(chalk.gray(`   Usage: ${JSON.stringify(response.data.usage)}`));
    
  } catch (error) {
    console.log(chalk.red(`   ❌ Failed: ${error.response?.status} - ${error.response?.data?.detail || error.message}`));
  }
  
  // Test 4: Check account info
  console.log(chalk.gray('\n4. Checking API key info...'));
  console.log(chalk.gray(`   Key: ${apiKey.substring(0, 20)}...${apiKey.substring(apiKey.length - 10)}`));
  console.log(chalk.gray(`   Length: ${apiKey.length} characters`));
  
  console.log(chalk.cyan('\n📝 Notes:'));
  console.log(chalk.white('• If all models fail with 402, the key might need billing activation'));
  console.log(chalk.white('• Visit https://jina.ai/dashboard to check account status'));
  console.log(chalk.white('• Some models may require specific plans'));
}

testJinaSimple().catch(console.error);