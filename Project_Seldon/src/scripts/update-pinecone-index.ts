#!/usr/bin/env node

import { Pinecone } from '@pinecone-database/pinecone';
import * as dotenv from 'dotenv';
import chalk from 'chalk';

// Load environment variables
dotenv.config();

async function updateNightingaleIndex() {
  console.log(chalk.cyan('\n🔄 Updating Nightingale Index to 768 Dimensions\n'));
  
  try {
    const pinecone = new Pinecone({
      apiKey: process.env.PINECONE_API_KEY!
    });
    
    const indexName = 'nightingale';
    
    // Step 1: Check if index exists
    console.log(chalk.yellow('1. Checking if nightingale index exists...'));
    const indexes = await pinecone.listIndexes();
    const nightingaleIndex = indexes.indexes?.find(i => i.name === indexName);
    
    if (nightingaleIndex) {
      console.log(chalk.green(`   ✓ Found ${indexName} index`));
      console.log(chalk.gray(`   Current dimension: ${nightingaleIndex.dimension}`));
      
      if (nightingaleIndex.dimension === 768) {
        console.log(chalk.green('\n✅ Index already has 768 dimensions!'));
        return;
      }
      
      // Step 2: Delete the existing index
      console.log(chalk.yellow('\n2. Deleting existing index...'));
      await pinecone.deleteIndex(indexName);
      console.log(chalk.green('   ✓ Index deleted successfully'));
      
      // Wait a bit for deletion to propagate
      console.log(chalk.gray('   Waiting for deletion to complete...'));
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
    
    // Step 3: Create new index with 768 dimensions
    console.log(chalk.yellow('\n3. Creating new nightingale index with 768 dimensions...'));
    await pinecone.createIndex({
      name: indexName,
      dimension: 768,
      metric: 'cosine',
      spec: {
        serverless: {
          cloud: 'aws',
          region: 'us-east-1'
        }
      }
    });
    
    console.log(chalk.green('   ✓ Index created successfully'));
    
    // Step 4: Wait for index to be ready
    console.log(chalk.yellow('\n4. Waiting for index to be ready...'));
    let ready = false;
    let attempts = 0;
    const maxAttempts = 30; // 5 minutes max
    
    while (!ready && attempts < maxAttempts) {
      attempts++;
      const indexes = await pinecone.listIndexes();
      const newIndex = indexes.indexes?.find(i => i.name === indexName);
      
      if (newIndex?.status?.ready) {
        ready = true;
        console.log(chalk.green('   ✓ Index is ready!'));
      } else {
        process.stdout.write(chalk.gray(`   Waiting... (${attempts * 10}s)\r`));
        await new Promise(resolve => setTimeout(resolve, 10000)); // 10 seconds
      }
    }
    
    if (!ready) {
      throw new Error('Index creation timed out');
    }
    
    // Step 5: Verify the new index
    console.log(chalk.yellow('\n5. Verifying new index configuration...'));
    const finalIndexes = await pinecone.listIndexes();
    const finalIndex = finalIndexes.indexes?.find(i => i.name === indexName);
    
    if (finalIndex) {
      console.log(chalk.green(`\n✅ Successfully updated ${indexName} index!`));
      console.log(chalk.white('─'.repeat(50)));
      console.log(chalk.green(`   Name: ${finalIndex.name}`));
      console.log(chalk.green(`   Dimension: ${finalIndex.dimension}`));
      console.log(chalk.green(`   Metric: ${finalIndex.metric}`));
      console.log(chalk.green(`   Host: ${finalIndex.host}`));
      console.log(chalk.green(`   Status: Ready`));
      console.log(chalk.white('─'.repeat(50)));
      
      // Update environment variables
      console.log(chalk.yellow('\n6. Updating configuration...'));
      console.log(chalk.cyan('   Please update your .env file with:'));
      console.log(chalk.white(`   PINECONE_HOST=${finalIndex.host}`));
      console.log(chalk.white(`   PINECONE_INDEX_NAME=${indexName}`));
    }
    
  } catch (error) {
    console.log(chalk.red('\n❌ Failed to update index'));
    console.log(chalk.gray(`   Error: ${error.message}`));
    process.exit(1);
  }
}

// Run the script
updateNightingaleIndex().catch(console.error);