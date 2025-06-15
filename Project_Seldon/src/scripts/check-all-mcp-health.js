#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

// ANSI color codes
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    dim: '\x1b[2m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    white: '\x1b[37m'
};

// Check symbol helpers
const symbols = {
    success: `${colors.green}✅${colors.reset}`,
    error: `${colors.red}❌${colors.reset}`,
    warning: `${colors.yellow}⚠️${colors.reset}`,
    info: `${colors.blue}ℹ️${colors.reset}`,
    working: `${colors.cyan}🔄${colors.reset}`
};

async function loadMcpConfig() {
    const configPaths = [
        path.join(process.cwd(), '..', '.claude', 'mcp.json'),
        path.join(process.cwd(), '.claude', 'mcp.json'),
        path.join(process.env.HOME, 'gtm-campaign-project', '.claude', 'mcp.json')
    ];
    
    for (const configPath of configPaths) {
        if (fs.existsSync(configPath)) {
            console.log(`${symbols.info} Loading MCP config from: ${configPath}`);
            const configContent = fs.readFileSync(configPath, 'utf8');
            return JSON.parse(configContent);
        }
    }
    
    throw new Error('No .claude/mcp.json file found');
}

async function checkServerConnection(serverName, serverConfig) {
    return new Promise((resolve) => {
        const timeout = setTimeout(() => {
            resolve({ status: 'timeout', error: 'Connection timeout after 5s' });
        }, 5000);

        try {
            // Check if server is disabled
            if (serverConfig.disabled) {
                clearTimeout(timeout);
                resolve({ status: 'disabled' });
                return;
            }

            // Check for missing required environment variables
            const missingEnvVars = [];
            if (serverConfig.env) {
                for (const [key, value] of Object.entries(serverConfig.env)) {
                    if (value && value.includes('YOUR_') && value.includes('_HERE')) {
                        missingEnvVars.push(key);
                    }
                }
            }

            if (missingEnvVars.length > 0) {
                clearTimeout(timeout);
                resolve({ 
                    status: 'missing-config', 
                    error: `Missing API keys: ${missingEnvVars.join(', ')}` 
                });
                return;
            }

            // Try to spawn the process to check if it can start
            const child = spawn(serverConfig.command, [...serverConfig.args, '--version'], {
                env: { ...process.env, ...serverConfig.env },
                stdio: 'pipe'
            });

            let output = '';
            child.stdout.on('data', (data) => {
                output += data.toString();
            });

            child.stderr.on('data', (data) => {
                output += data.toString();
            });

            child.on('error', (error) => {
                clearTimeout(timeout);
                resolve({ status: 'error', error: error.message });
            });

            child.on('close', (code) => {
                clearTimeout(timeout);
                if (code === 0 || output.includes('version')) {
                    resolve({ status: 'ready' });
                } else {
                    resolve({ status: 'error', error: `Exit code: ${code}` });
                }
            });

        } catch (error) {
            clearTimeout(timeout);
            resolve({ status: 'error', error: error.message });
        }
    });
}

async function main() {
    console.log('\n🔍 MCP Health Check - All Servers\n');
    console.log('Loading configuration and checking all MCP servers...\n');

    try {
        const config = await loadMcpConfig();
        const servers = config.mcpServers || {};
        
        console.log(`Found ${Object.keys(servers).length} MCP servers in configuration\n`);
        
        const line = '─'.repeat(80);
        console.log(line);
        console.log(`${'SERVER'.padEnd(25)} ${'STATUS'.padEnd(15)} ${'DETAILS'}`);
        console.log(line);

        const criticalServers = ['context7', 'supermemory', 'knowledge-graph-memory'];
        const results = {};

        // Check all servers
        for (const [serverName, serverConfig] of Object.entries(servers)) {
            process.stdout.write(`${serverName.padEnd(25)} ${symbols.working} Checking...`);
            
            const result = await checkServerConnection(serverName, serverConfig);
            results[serverName] = result;
            
            // Clear the line and write the result
            process.stdout.write('\r');
            
            let statusSymbol = symbols.error;
            let statusText = 'Failed';
            let details = '';

            switch (result.status) {
                case 'ready':
                    statusSymbol = symbols.success;
                    statusText = 'Ready';
                    break;
                case 'disabled':
                    statusSymbol = symbols.warning;
                    statusText = 'Disabled';
                    break;
                case 'missing-config':
                    statusSymbol = symbols.warning;
                    statusText = 'Not Configured';
                    details = result.error;
                    break;
                case 'timeout':
                    statusSymbol = symbols.error;
                    statusText = 'Timeout';
                    details = result.error;
                    break;
                case 'error':
                    statusSymbol = symbols.error;
                    statusText = 'Error';
                    details = result.error;
                    break;
            }

            console.log(`${serverName.padEnd(25)} ${statusSymbol} ${statusText.padEnd(13)} ${details}`);
        }

        console.log(line);

        // Summary
        console.log('\n📊 Summary:\n');
        
        // Critical services status
        console.log(`${colors.bright}Critical Services:${colors.reset}`);
        for (const server of criticalServers) {
            if (results[server]) {
                const status = results[server].status === 'ready' ? symbols.success : symbols.error;
                console.log(`  ${status} ${server}`);
            }
        }

        // Overall stats
        const readyCount = Object.values(results).filter(r => r.status === 'ready').length;
        const configuredCount = Object.values(results).filter(r => r.status !== 'missing-config').length;
        const totalCount = Object.keys(results).length;

        console.log(`\n${colors.bright}Statistics:${colors.reset}`);
        console.log(`  • Ready: ${readyCount}/${totalCount}`);
        console.log(`  • Configured: ${configuredCount}/${totalCount}`);
        console.log(`  • Not Configured: ${totalCount - configuredCount}`);

        // Recommendations
        if (totalCount - configuredCount > 0) {
            console.log(`\n${symbols.warning} ${colors.yellow}Some servers need configuration:${colors.reset}`);
            for (const [server, result] of Object.entries(results)) {
                if (result.status === 'missing-config') {
                    console.log(`  • ${server}: ${result.error}`);
                }
            }
        }

        // Exit with appropriate code
        const criticalReady = criticalServers.every(s => results[s]?.status === 'ready');
        if (!criticalReady) {
            console.log(`\n${symbols.error} ${colors.red}Critical services are not ready!${colors.reset}`);
            process.exit(1);
        } else {
            console.log(`\n${symbols.success} ${colors.green}All critical services are ready!${colors.reset}`);
            process.exit(0);
        }

    } catch (error) {
        console.error(`\n${symbols.error} Error: ${error.message}`);
        process.exit(1);
    }
}

main();