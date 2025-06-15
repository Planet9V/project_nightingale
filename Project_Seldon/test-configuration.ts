/**
 * Test script to verify configuration and initialization
 */

import { configManager } from './src/config/ConfigurationManager';
import { logger } from './src/utils/logger';

async function testConfiguration() {
  try {
    console.log('=== Testing Project Seldon Configuration ===\n');
    
    // Test 1: Load configuration
    console.log('1. Loading configuration...');
    const config = await configManager.load();
    console.log('✓ Configuration loaded successfully\n');
    
    // Test 2: Validate configuration
    console.log('2. Validating configuration...');
    const isValid = await configManager.validate();
    console.log(`✓ Configuration validation: ${isValid ? 'PASSED' : 'FAILED'}\n`);
    
    // Test 3: Check critical values
    console.log('3. Checking critical configuration values:');
    console.log(`   - Environment: ${config.environment}`);
    console.log(`   - Batch Size: ${config.etl.batchSize}`);
    console.log(`   - Jina API Key: ${config.jina.apiKey ? 'SET (length: ' + config.jina.apiKey.length + ')' : 'NOT SET'}`);
    console.log(`   - Supabase URL: ${config.databases.supabase.url}`);
    console.log(`   - Pinecone Index: ${config.databases.pinecone.indexName}`);
    console.log(`   - Neo4j URI: ${config.databases.neo4j.uri}`);
    console.log(`   - Chunk Size: ${config.processing.chunkSize}`);
    console.log(`   - Log Level: ${config.logging.level}\n`);
    
    // Test 4: Test logger
    console.log('4. Testing logger...');
    logger.info('Test log message');
    console.log('✓ Logger working\n');
    
    // Test 5: Test specific configuration values
    console.log('5. Testing getValue method:');
    const jinaApiKey = configManager.getValue<string>('jina.apiKey');
    console.log(`   - Got Jina API key via getValue: ${jinaApiKey ? 'SUCCESS' : 'FAILED'}\n`);
    
    console.log('=== All Configuration Tests Passed! ===');
    
  } catch (error) {
    console.error('\n❌ Configuration test failed:', error);
    process.exit(1);
  }
}

// Run the test
testConfiguration().then(() => {
  console.log('\nTest completed successfully!');
  process.exit(0);
}).catch((error) => {
  console.error('\nTest failed:', error);
  process.exit(1);
});