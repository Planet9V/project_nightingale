#!/usr/bin/env node

const path = require('path');
const dotenv = require('dotenv');
const chalk = require('chalk');
const { ComprehensiveETLPipeline } = require('../pipelines/ComprehensiveETLPipeline');

// Load environment variables
dotenv.config();

async function processSingleDocument() {
  console.log(chalk.cyan('\n📄 Processing Single Document Test\n'));
  
  const pipeline = new ComprehensiveETLPipeline();
  
  // Document to process
  const documentPath = path.resolve(
    __dirname,
    '../../../Annual_cyber_reports/Annual_cyber_reports_2023/Dragos-Year-In-Review-Report-2023.md'
  );
  
  console.log(chalk.yellow('Document:', path.basename(documentPath)));
  console.log(chalk.gray('Path:', documentPath));
  console.log(chalk.gray('Testing ETL pipeline with single document...\n'));
  
  try {
    // Initialize pipeline
    console.log(chalk.yellow('1. Initializing ETL Pipeline...'));
    await pipeline.initialize();
    console.log(chalk.green('   ✓ Pipeline initialized'));
    
    // Process document
    console.log(chalk.yellow('\n2. Processing document...'));
    const result = await pipeline.process({
      inputPath: documentPath,
      maxFiles: 1,
      skipHealthCheck: true, // Skip for now due to connection issues
      dryRun: false
    });
    
    // Display results
    console.log(chalk.green('\n✅ Processing Complete!\n'));
    console.log(chalk.white('─'.repeat(50)));
    console.log(chalk.green(`Processed Files: ${result.processedFiles}`));
    console.log(chalk.red(`Failed Files: ${result.failedFiles}`));
    console.log(chalk.cyan(`Total Chunks: ${result.totalChunks}`));
    console.log(chalk.cyan(`Total Embeddings: ${result.totalEmbeddings}`));
    console.log(chalk.cyan(`Total Citations: ${result.totalCitations}`));
    console.log(chalk.gray(`Duration: ${(result.duration / 1000).toFixed(2)}s`));
    
    if (result.errors.length > 0) {
      console.log(chalk.red('\nErrors:'));
      result.errors.forEach(err => {
        console.log(chalk.red(`  - ${err.file}: ${err.error}`));
      });
    }
    
    console.log(chalk.white('─'.repeat(50)));
    
  } catch (error) {
    console.log(chalk.red('\n❌ Pipeline failed'));
    console.log(chalk.red(`Error: ${error.message}`));
    
    if (error.stack) {
      console.log(chalk.gray('\nStack trace:'));
      console.log(chalk.gray(error.stack));
    }
    
    process.exit(1);
  }
}

// Add event listeners for progress
process.on('unhandledRejection', (reason, promise) => {
  console.error(chalk.red('Unhandled Rejection at:'), promise, chalk.red('reason:'), reason);
  process.exit(1);
});

// Run the processor
processSingleDocument().catch(console.error);