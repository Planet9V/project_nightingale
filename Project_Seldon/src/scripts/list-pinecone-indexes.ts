#!/usr/bin/env node

const { Pinecone } = require('@pinecone-database/pinecone');
const dotenv = require('dotenv');
const chalk = require('chalk');

// Load environment variables
dotenv.config();

async function listPineconeIndexes() {
  console.log(chalk.cyan('\n📊 Pinecone Indexes\n'));
  
  try {
    const pinecone = new Pinecone({
      apiKey: process.env.PINECONE_API_KEY
    });
    
    const indexes = await pinecone.listIndexes();
    
    if (!indexes.indexes || indexes.indexes.length === 0) {
      console.log(chalk.yellow('No indexes found'));
      return;
    }
    
    console.log(chalk.green(`Found ${indexes.indexes.length} indexes:\n`));
    
    // Display in a table format
    for (const index of indexes.indexes) {
      console.log(chalk.white('─'.repeat(50)));
      console.log(chalk.green(`Index: ${index.name}`));
      console.log(chalk.gray(`  Dimension: ${index.dimension}`));
      console.log(chalk.gray(`  Metric: ${index.metric}`));
      console.log(chalk.gray(`  Host: ${index.host}`));
      console.log(chalk.gray(`  Status: ${index.status?.ready ? '✅ Ready' : '⏳ Not Ready'}`));
      
      if (index.dimension === 768) {
        console.log(chalk.cyan(`  ✓ Compatible with Jina embeddings`));
      } else {
        console.log(chalk.yellow(`  ⚠ Not compatible with Jina (needs 768 dimensions)`));
      }
    }
    
    console.log(chalk.white('\n' + '─'.repeat(50)));
    
    // Recommendation
    const compatibleIndexes = indexes.indexes.filter(i => i.dimension === 768);
    if (compatibleIndexes.length > 0) {
      console.log(chalk.green(`\n✅ Compatible indexes for Jina (768d):`));
      compatibleIndexes.forEach(i => {
        console.log(chalk.cyan(`   - ${i.name}`));
      });
    } else {
      console.log(chalk.yellow(`\n⚠️  No 768-dimensional indexes found.`));
      console.log(chalk.yellow(`   You'll need to create a new index for Jina embeddings.`));
    }
    
  } catch (error) {
    console.log(chalk.red('❌ Failed to list indexes'));
    console.log(chalk.gray(`   Error: ${error.message}`));
  }
}

// Run the script
listPineconeIndexes().catch(console.error);