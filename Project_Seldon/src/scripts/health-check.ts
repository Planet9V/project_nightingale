#!/usr/bin/env node

const { DatabaseHealthChecker } = require('../services/DatabaseHealthChecker');
const dotenv = require('dotenv');
const chalk = require('chalk');

// Load environment variables
dotenv.config();

async function main() {
  console.log(chalk.cyan('\n🏥 Running Project Seldon Health Check\n'));
  
  const healthChecker = new DatabaseHealthChecker({
    supabaseUrl: process.env.SUPABASE_URL!,
    supabaseKey: process.env.SUPABASE_ANON_KEY!,
    pineconeApiKey: process.env.PINECONE_API_KEY!,
    neo4jUri: process.env.NEO4J_URI!,
    neo4jUser: process.env.NEO4J_USER!,
    neo4jPassword: process.env.NEO4J_PASSWORD!,
    awsRegion: process.env.AWS_REGION,
    jinaApiKey: process.env.JINA_API_KEY!,
  });
  
  try {
    const report = await healthChecker.performFullHealthCheck();
    DatabaseHealthChecker.displayReport(report);
    
    if (report.overall === 'unhealthy') {
      process.exit(1);
    }
  } catch (error) {
    console.error(chalk.red('\n❌ Health check failed:'), error);
    process.exit(1);
  } finally {
    await healthChecker.cleanup();
  }
}

main().catch(console.error);