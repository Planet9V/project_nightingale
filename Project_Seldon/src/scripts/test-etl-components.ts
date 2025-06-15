#!/usr/bin/env node

/**
 * Project Seldon ETL Component Tester
 * Tests individual components of the ETL pipeline
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { Configuration } from '../config/ConfigurationManager';
import { DatabaseHealthChecker } from '../services/DatabaseHealthChecker';
import { JinaServiceManager } from '../services/jina/JinaServiceManager';
import { PineconeConnector } from '../connectors/PineconeConnector';
import { SupabaseConnector } from '../connectors/SupabaseConnector';
import { Neo4jConnector } from '../connectors/Neo4jConnector';
import { PDFProcessor } from '../processors/PDFProcessor';
import { logger } from '../utils/logger';

const program = new Command();

program
  .name('test-etl')
  .description('Test Project Seldon ETL components')
  .version('1.0.0')
  .option('--all', 'Test all components')
  .option('--health', 'Run health checks')
  .option('--jina', 'Test Jina API')
  .option('--pinecone', 'Test Pinecone connection')
  .option('--supabase', 'Test Supabase connection')
  .option('--neo4j', 'Test Neo4j connection')
  .option('--pdf <file>', 'Test PDF processing with file')
  .option('--mcp', 'Check MCP services')
  .parse(process.argv);

const options = program.opts();

interface TestResult {
  component: string;
  status: 'passed' | 'failed' | 'skipped';
  message?: string;
  duration?: number;
}

const results: TestResult[] = [];

async function testHealthCheck(config: Configuration): Promise<TestResult> {
  const start = Date.now();
  console.log(chalk.yellow('\n🏥 Testing Health Checks...'));
  
  try {
    const healthChecker = new DatabaseHealthChecker(config);
    const health = await healthChecker.checkAll();
    
    console.log(chalk.gray(`   Supabase: ${health.supabase ? '✅' : '❌'}`));
    console.log(chalk.gray(`   Pinecone: ${health.pinecone ? '✅' : '❌'}`));
    console.log(chalk.gray(`   Neo4j: ${health.neo4j ? '✅' : '❌'}`));
    console.log(chalk.gray(`   S3: ${health.s3 ? '✅' : '❌'}`));
    
    const allHealthy = Object.values(health).every(v => v === true);
    
    return {
      component: 'Health Checks',
      status: allHealthy ? 'passed' : 'failed',
      message: `${Object.values(health).filter(v => v).length}/${Object.keys(health).length} services healthy`,
      duration: Date.now() - start
    };
  } catch (error) {
    return {
      component: 'Health Checks',
      status: 'failed',
      message: error.message,
      duration: Date.now() - start
    };
  }
}

async function testJina(config: Configuration): Promise<TestResult> {
  const start = Date.now();
  console.log(chalk.yellow('\n🤖 Testing Jina API...'));
  
  try {
    const jinaService = JinaServiceManager.getInstance(config);
    
    // Test embedding
    const testText = 'Project Seldon ETL pipeline test';
    const embedding = await jinaService.generateEmbedding(testText);
    
    console.log(chalk.gray(`   Model: ${embedding.model}`));
    console.log(chalk.gray(`   Dimensions: ${embedding.embedding.length}`));
    console.log(chalk.gray(`   Tokens: ${embedding.usage.total_tokens}`));
    
    return {
      component: 'Jina API',
      status: 'passed',
      message: `Successfully generated ${embedding.embedding.length}D embedding`,
      duration: Date.now() - start
    };
  } catch (error) {
    const is402 = error.message.includes('402');
    return {
      component: 'Jina API',
      status: 'failed',
      message: is402 ? 'Payment required - activate paid plan' : error.message,
      duration: Date.now() - start
    };
  }
}

async function testPinecone(config: Configuration): Promise<TestResult> {
  const start = Date.now();
  console.log(chalk.yellow('\n🌲 Testing Pinecone...'));
  
  try {
    const pinecone = new PineconeConnector(config);
    const context = { 
      logger, 
      metrics: { 
        increment: () => {}, 
        gauge: () => {}, 
        histogram: () => {}, 
        timing: () => {} 
      } 
    };
    
    await pinecone.initialize(context);
    const stats = await pinecone.getStats();
    
    console.log(chalk.gray(`   Index: ${config.databases.pinecone.indexName}`));
    console.log(chalk.gray(`   Dimensions: ${stats.dimension}`));
    console.log(chalk.gray(`   Vectors: ${stats.totalVectors}`));
    console.log(chalk.gray(`   Namespaces: ${stats.namespaces.join(', ') || 'none'}`));
    
    return {
      component: 'Pinecone',
      status: 'passed',
      message: `Connected to ${config.databases.pinecone.indexName} (${stats.totalVectors} vectors)`,
      duration: Date.now() - start
    };
  } catch (error) {
    return {
      component: 'Pinecone',
      status: 'failed',
      message: error.message,
      duration: Date.now() - start
    };
  }
}

async function testSupabase(config: Configuration): Promise<TestResult> {
  const start = Date.now();
  console.log(chalk.yellow('\n🗄️  Testing Supabase...'));
  
  try {
    const supabase = new SupabaseConnector(config);
    const context = { logger };
    
    await supabase.initialize(context);
    const health = await supabase.healthCheck();
    
    if (health) {
      console.log(chalk.gray(`   Connected to: ${config.databases.supabase.url}`));
      console.log(chalk.gray(`   Database ready`));
      
      return {
        component: 'Supabase',
        status: 'passed',
        message: 'Successfully connected',
        duration: Date.now() - start
      };
    } else {
      throw new Error('Health check failed');
    }
  } catch (error) {
    const isTimeout = error.message.includes('timeout');
    return {
      component: 'Supabase',
      status: 'failed',
      message: isTimeout ? 'Connection timeout - check network/firewall' : error.message,
      duration: Date.now() - start
    };
  }
}

async function testNeo4j(config: Configuration): Promise<TestResult> {
  const start = Date.now();
  console.log(chalk.yellow('\n🔗 Testing Neo4j...'));
  
  try {
    const neo4j = new Neo4jConnector(config);
    const context = { logger };
    
    await neo4j.initialize(context);
    const health = await neo4j.healthCheck();
    
    if (health) {
      console.log(chalk.gray(`   Connected to: ${config.databases.neo4j.uri}`));
      console.log(chalk.gray(`   Database ready`));
      
      return {
        component: 'Neo4j',
        status: 'passed',
        message: 'Successfully connected',
        duration: Date.now() - start
      };
    } else {
      throw new Error('Health check failed');
    }
  } catch (error) {
    return {
      component: 'Neo4j',
      status: 'failed',
      message: error.message,
      duration: Date.now() - start
    };
  }
}

async function testPDF(config: Configuration, filePath: string): Promise<TestResult> {
  const start = Date.now();
  console.log(chalk.yellow(`\n📄 Testing PDF Processing: ${filePath}...`));
  
  try {
    const processor = new PDFProcessor();
    const result = await processor.processPDF(filePath);
    
    console.log(chalk.gray(`   Title: ${result.metadata.title}`));
    console.log(chalk.gray(`   Pages: ${result.metadata.pdfInfo.pages}`));
    console.log(chalk.gray(`   Text length: ${result.content.length}`));
    console.log(chalk.gray(`   Chunks: ${result.chunks.length}`));
    console.log(chalk.gray(`   Avg chunk size: ${Math.round(result.content.length / result.chunks.length)} chars`));
    
    return {
      component: 'PDF Processing',
      status: 'passed',
      message: `Processed ${result.metadata.pdfInfo.pages} pages, created ${result.chunks.length} chunks`,
      duration: Date.now() - start
    };
  } catch (error) {
    return {
      component: 'PDF Processing',
      status: 'failed',
      message: error.message,
      duration: Date.now() - start
    };
  }
}

async function main() {
  console.log(chalk.cyan('\n🧪 Project Seldon Component Tests\n'));
  
  try {
    const config = await Configuration.load();
    
    // Determine which tests to run
    const runAll = options.all || Object.keys(options).length === 0;
    
    if (runAll || options.health) {
      results.push(await testHealthCheck(config));
    }
    
    if (runAll || options.jina) {
      results.push(await testJina(config));
    }
    
    if (runAll || options.pinecone) {
      results.push(await testPinecone(config));
    }
    
    if (runAll || options.supabase) {
      results.push(await testSupabase(config));
    }
    
    if (runAll || options.neo4j) {
      results.push(await testNeo4j(config));
    }
    
    if (options.pdf) {
      results.push(await testPDF(config, options.pdf));
    }
    
    // Display results
    console.log(chalk.cyan('\n📊 Test Results:\n'));
    console.log(chalk.white('─'.repeat(60)));
    
    results.forEach(result => {
      const icon = result.status === 'passed' ? '✅' : 
                   result.status === 'failed' ? '❌' : '⏭️';
      const color = result.status === 'passed' ? chalk.green :
                    result.status === 'failed' ? chalk.red : chalk.gray;
      
      console.log(`${icon} ${color(result.component.padEnd(20))} ${result.message || ''}`);
      if (result.duration) {
        console.log(chalk.gray(`   Duration: ${result.duration}ms`));
      }
    });
    
    console.log(chalk.white('─'.repeat(60)));
    
    const passed = results.filter(r => r.status === 'passed').length;
    const failed = results.filter(r => r.status === 'failed').length;
    const total = results.length;
    
    console.log(chalk.cyan(`\nSummary: ${passed}/${total} tests passed`));
    
    if (failed > 0) {
      console.log(chalk.red(`\n⚠️  ${failed} tests failed`));
      process.exit(1);
    } else {
      console.log(chalk.green('\n✅ All tests passed!'));
      process.exit(0);
    }
    
  } catch (error) {
    console.error(chalk.red('\n❌ Test Error:'), error.message);
    process.exit(1);
  }
}

// Run tests
main().catch((error) => {
  console.error(chalk.red('Fatal error:'), error);
  process.exit(1);
});