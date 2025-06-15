#!/usr/bin/env node

const { exec } = require('child_process');
const chalk = require('chalk');
const fs = require('fs').promises;
const path = require('path');

// Critical MCP servers that must always be running
const CRITICAL_SERVERS = ['context7', 'supermemory', 'knowledge-graph-memory'];

// MCP configuration file path
const MCP_CONFIG_PATH = path.join(process.cwd(), '../.cursor/mcp.json');

async function checkMCPHealth() {
  console.log(chalk.cyan('\n🔍 MCP Health Check - Critical Services\n'));
  console.log(chalk.yellow('Checking Context7, SuperMemory, and Knowledge Graph Memory...\n'));

  try {
    // Read MCP configuration
    const configContent = await fs.readFile(MCP_CONFIG_PATH, 'utf-8');
    const config = JSON.parse(configContent);
    
    const results = {
      context7: { configured: false, status: 'unknown' },
      supermemory: { configured: false, status: 'unknown' },
      'knowledge-graph-memory': { configured: false, status: 'unknown' }
    };

    // Check configuration
    for (const server of CRITICAL_SERVERS) {
      if (config.mcpServers && config.mcpServers[server]) {
        results[server].configured = true;
        const serverConfig = config.mcpServers[server];
        
        // Check if disabled
        if (serverConfig.disabled === true) {
          results[server].status = 'disabled';
        } else {
          results[server].status = 'configured';
        }
      }
    }

    // Display results
    console.log(chalk.white('─'.repeat(60)));
    console.log(chalk.white('SERVER                  CONFIGURED   STATUS'));
    console.log(chalk.white('─'.repeat(60)));

    let allHealthy = true;

    for (const server of CRITICAL_SERVERS) {
      const result = results[server];
      const configuredIcon = result.configured ? '✅' : '❌';
      const statusColor = result.status === 'configured' ? chalk.green : 
                         result.status === 'disabled' ? chalk.yellow :
                         chalk.red;
      
      const statusText = result.status === 'configured' ? 'Ready' :
                        result.status === 'disabled' ? 'Disabled' :
                        'Not Found';

      console.log(
        `${server.padEnd(24)}${configuredIcon.padEnd(13)}${statusColor(statusText)}`
      );

      if (!result.configured || result.status !== 'configured') {
        allHealthy = false;
      }
    }

    console.log(chalk.white('─'.repeat(60)));

    // Additional checks
    console.log(chalk.cyan('\n📋 Additional Checks:\n'));

    // Check Node.js version
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.split('.')[0].substring(1));
    if (majorVersion >= 18) {
      console.log(chalk.green(`✅ Node.js ${nodeVersion} (Required: 18+)`));
    } else {
      console.log(chalk.red(`❌ Node.js ${nodeVersion} (Required: 18+)`));
      allHealthy = false;
    }

    // Check memory directory
    const memoryDir = '/home/jim/gtm-campaign-project/.mcp-memory';
    try {
      await fs.access(memoryDir);
      console.log(chalk.green(`✅ Memory directory exists: ${memoryDir}`));
    } catch {
      console.log(chalk.yellow(`⚠️  Memory directory missing: ${memoryDir}`));
      console.log(chalk.gray('   Creating directory...'));
      await fs.mkdir(memoryDir, { recursive: true });
      console.log(chalk.green('   ✓ Directory created'));
    }

    // Check for SuperMemory URL
    if (results.supermemory.configured) {
      console.log(chalk.yellow('\n⚠️  SuperMemory Note:'));
      console.log(chalk.gray('   Visit https://mcp.supermemory.ai to get your unique URL'));
      console.log(chalk.gray('   Save the URL securely - it\'s your access key!'));
    }

    // Summary
    console.log(chalk.cyan('\n📊 Summary:\n'));
    if (allHealthy) {
      console.log(chalk.green('✅ All critical MCP servers are configured and ready!'));
    } else {
      console.log(chalk.red('❌ Some critical MCP servers need attention'));
      console.log(chalk.yellow('\nTo fix:'));
      console.log(chalk.gray('1. Restart Cursor/VSCode after configuration changes'));
      console.log(chalk.gray('2. Ensure all servers are enabled (not disabled: true)'));
      console.log(chalk.gray('3. Check the MCP output panel for errors'));
    }

    // Test commands
    console.log(chalk.cyan('\n🧪 Test Commands:\n'));
    console.log(chalk.gray('Context7:'));
    console.log(chalk.white('  "What is TypeScript tsconfig.json? use context7"'));
    console.log(chalk.gray('\nSuperMemory:'));
    console.log(chalk.white('  "Remember that we are working on Project Seldon ETL pipeline"'));
    console.log(chalk.gray('\nKnowledge Graph:'));
    console.log(chalk.white('  "Remembering..." (to retrieve memories)'));

    return allHealthy;

  } catch (error) {
    console.log(chalk.red('\n❌ Error checking MCP health:'));
    console.log(chalk.red(error.message));
    return false;
  }
}

// Run the health check
checkMCPHealth().then(healthy => {
  process.exit(healthy ? 0 : 1);
}).catch(error => {
  console.error(chalk.red('Fatal error:'), error);
  process.exit(1);
});