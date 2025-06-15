#!/usr/bin/env node

const chalk = require('chalk');
const { execSync } = require('child_process');
const path = require('path');

console.log(chalk.cyan('\n🚀 Project Seldon Startup Checks\n'));

// 1. Check MCP Health
console.log(chalk.yellow('1. Checking Critical MCP Services...'));
try {
  execSync('node ' + path.join(__dirname, 'check-mcp-health.js'), { stdio: 'inherit' });
} catch (error) {
  console.log(chalk.red('\n⚠️  MCP services need attention!'));
}

// 2. Check Environment Variables
console.log(chalk.yellow('\n2. Checking Environment Variables...'));
const requiredEnvVars = [
  'JINA_API_KEY',
  'PINECONE_API_KEY',
  'SUPABASE_URL',
  'SUPABASE_ANON_KEY',
  'NEO4J_URI',
  'NEO4J_PASSWORD'
];

let envHealthy = true;
for (const envVar of requiredEnvVars) {
  if (process.env[envVar]) {
    console.log(chalk.green(`   ✅ ${envVar} is set`));
  } else {
    console.log(chalk.red(`   ❌ ${envVar} is missing`));
    envHealthy = false;
  }
}

// 3. Quick API Status Check
console.log(chalk.yellow('\n3. Quick API Status...'));
console.log(chalk.gray('   Jina API: Check with test-jina-clip.js'));
console.log(chalk.gray('   Pinecone: Index "nightingale" configured for 768 dimensions'));
console.log(chalk.gray('   Supabase: Connection test available'));

// 4. Development Reminders
console.log(chalk.cyan('\n📝 Development Reminders:\n'));
console.log(chalk.white('• Always start with: "Remembering..." to load context'));
console.log(chalk.white('• Use "use context7" for documentation lookups'));
console.log(chalk.white('• Update memories regularly with SuperMemory'));
console.log(chalk.white('• Check TypeScript errors with: npm run build'));

// 5. Quick Commands
console.log(chalk.cyan('\n⚡ Quick Commands:\n'));
console.log(chalk.gray('Check MCP health:     ') + chalk.white('node src/scripts/check-mcp-health.js'));
console.log(chalk.gray('Test Jina API:        ') + chalk.white('node src/scripts/test-jina-clip.js'));
console.log(chalk.gray('List Pinecone indexes:') + chalk.white('node src/scripts/list-pinecone-indexes.js'));
console.log(chalk.gray('Test connections:     ') + chalk.white('node src/scripts/test-connections.js'));
console.log(chalk.gray('Process single doc:   ') + chalk.white('node test-single-doc.js'));

console.log(chalk.green('\n✅ Startup checks complete!\n'));