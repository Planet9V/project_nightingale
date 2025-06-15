#!/usr/bin/env node

/**
 * Project Seldon ETL Pipeline Runner
 * Main script to process documents through the complete ETL pipeline
 */

import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs/promises';
import chalk from 'chalk';
import { ComprehensiveETLPipeline } from '../pipelines/ComprehensiveETLPipeline';
import { Configuration } from '../config/ConfigurationManager';
import { logger } from '../utils/logger';
import { DocumentFormat } from '../types';

const program = new Command();

program
  .name('run-etl')
  .description('Run the Project Seldon ETL pipeline')
  .version('1.0.0')
  .requiredOption('-i, --input <path>', 'Input directory or file path')
  .option('-p, --pattern <pattern>', 'File pattern to match (e.g., "*.pdf")', '*.pdf')
  .option('-f, --format <format>', 'Document format (pdf, md, txt)', 'pdf')
  .option('-b, --batch-size <number>', 'Batch processing size', '10')
  .option('-m, --max-files <number>', 'Maximum files to process')
  .option('--skip-embeddings', 'Skip embedding generation')
  .option('--skip-neo4j', 'Skip Neo4j relationship creation')
  .option('--skip-s3', 'Skip S3 upload')
  .option('--dry-run', 'Show what would be processed without executing')
  .parse(process.argv);

const options = program.opts();

async function findFiles(inputPath: string, pattern: string): Promise<string[]> {
  const stats = await fs.stat(inputPath);
  
  if (stats.isFile()) {
    return [inputPath];
  }
  
  if (stats.isDirectory()) {
    const files = await fs.readdir(inputPath, { withFileTypes: true });
    const matches: string[] = [];
    
    for (const file of files) {
      if (file.isFile()) {
        const fullPath = path.join(inputPath, file.name);
        const regex = new RegExp(pattern.replace('*', '.*'));
        if (regex.test(file.name)) {
          matches.push(fullPath);
        }
      }
    }
    
    return matches;
  }
  
  throw new Error(`Invalid input path: ${inputPath}`);
}

async function main() {
  console.log(chalk.cyan('\n🚀 Project Seldon ETL Pipeline\n'));
  
  try {
    // Find files to process
    const files = await findFiles(options.input, options.pattern);
    const filesToProcess = options.maxFiles 
      ? files.slice(0, parseInt(options.maxFiles))
      : files;
    
    console.log(chalk.yellow(`Found ${files.length} files matching pattern "${options.pattern}"`));
    
    if (filesToProcess.length === 0) {
      console.log(chalk.red('No files to process'));
      process.exit(0);
    }
    
    console.log(chalk.green(`Processing ${filesToProcess.length} files\n`));
    
    if (options.dryRun) {
      console.log(chalk.yellow('DRY RUN - Files that would be processed:'));
      filesToProcess.forEach((file, index) => {
        console.log(chalk.gray(`  ${index + 1}. ${path.basename(file)}`));
      });
      process.exit(0);
    }
    
    // Initialize configuration
    const config = await Configuration.load();
    
    // Configure pipeline options
    const pipelineOptions = {
      skipEmbeddings: options.skipEmbeddings,
      skipNeo4j: options.skipNeo4j,
      skipS3: options.skipS3,
      batchSize: parseInt(options.batchSize),
      format: options.format.toUpperCase() as DocumentFormat,
    };
    
    // Initialize pipeline
    const pipeline = new ComprehensiveETLPipeline(config);
    await pipeline.initialize();
    
    console.log(chalk.cyan('\n📊 Processing Files:\n'));
    
    let processed = 0;
    let failed = 0;
    const startTime = Date.now();
    
    // Process files
    for (const file of filesToProcess) {
      try {
        console.log(chalk.yellow(`\nProcessing: ${path.basename(file)}`));
        
        const result = await pipeline.processDocument(file, pipelineOptions);
        
        if (result.success) {
          processed++;
          console.log(chalk.green(`✅ Success: ${path.basename(file)}`));
          console.log(chalk.gray(`   Chunks: ${result.chunksCreated}`));
          console.log(chalk.gray(`   Embeddings: ${result.embeddingsCreated}`));
          console.log(chalk.gray(`   Time: ${result.processingTime}ms`));
        } else {
          failed++;
          console.log(chalk.red(`❌ Failed: ${path.basename(file)}`));
          console.log(chalk.red(`   Error: ${result.error}`));
        }
        
      } catch (error) {
        failed++;
        console.log(chalk.red(`❌ Error processing ${path.basename(file)}:`));
        console.log(chalk.red(`   ${error.message}`));
        logger.error('File processing error', error);
      }
    }
    
    const duration = Date.now() - startTime;
    
    // Summary
    console.log(chalk.cyan('\n📈 Pipeline Summary:\n'));
    console.log(chalk.white('─'.repeat(50)));
    console.log(chalk.green(`✅ Processed: ${processed} files`));
    console.log(chalk.red(`❌ Failed: ${failed} files`));
    console.log(chalk.yellow(`⏱️  Duration: ${(duration / 1000).toFixed(2)} seconds`));
    console.log(chalk.cyan(`📊 Rate: ${(processed / (duration / 1000)).toFixed(2)} files/second`));
    console.log(chalk.white('─'.repeat(50)));
    
    // Cleanup
    await pipeline.shutdown();
    
    process.exit(failed > 0 ? 1 : 0);
    
  } catch (error) {
    console.error(chalk.red('\n❌ Pipeline Error:'), error.message);
    logger.error('Pipeline failed', error);
    process.exit(1);
  }
}

// Run the pipeline
main().catch((error) => {
  console.error(chalk.red('Fatal error:'), error);
  process.exit(1);
});