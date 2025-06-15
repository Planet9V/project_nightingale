#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// ANSI color codes
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m'
};

// Helper functions
const log = (message, color = colors.reset) => console.log(`${color}${message}${colors.reset}`);
const success = (message) => log(`✅ ${message}`, colors.green);
const error = (message) => log(`❌ ${message}`, colors.red);
const info = (message) => log(`ℹ️  ${message}`, colors.blue);
const warning = (message) => log(`⚠️  ${message}`, colors.yellow);

// Get current timestamp
function getTimestamp() {
    return new Date().toISOString().replace('T', ' ').slice(0, -5) + ' UTC';
}

// Create session log entry
function createSessionLog() {
    const timestamp = getTimestamp();
    const sessionData = {
        timestamp,
        nodeVersion: process.version,
        platform: process.platform,
        projectRoot: process.cwd(),
        user: process.env.USER || 'unknown'
    };
    
    // Create logs directory if it doesn't exist
    const logsDir = path.join(process.cwd(), '.claude', 'logs');
    if (!fs.existsSync(logsDir)) {
        fs.mkdirSync(logsDir, { recursive: true });
    }
    
    // Write session log
    const logFile = path.join(logsDir, `session-${timestamp.replace(/[: ]/g, '-')}.json`);
    fs.writeFileSync(logFile, JSON.stringify(sessionData, null, 2));
    
    return sessionData;
}

// Main startup sequence
async function main() {
    console.log('\n🚀 Project Nightingale SuperMemory-Enhanced Startup\n');
    
    // 1. Get current timestamp
    const timestamp = getTimestamp();
    info(`Current Time: ${timestamp}`);
    
    // 2. Create session log
    const sessionData = createSessionLog();
    success('Session log created');
    
    // 3. Display SuperMemory initialization prompts
    console.log('\n📝 SuperMemory Initialization Commands:\n');
    console.log(`1. Store session start:`);
    console.log(`   ${colors.cyan}"Remember that [${timestamp}] SESSION_START: New session initiated for Project Nightingale"${colors.reset}`);
    
    console.log(`\n2. Load previous session:`);
    console.log(`   ${colors.cyan}"What do you remember about the last session?"${colors.reset}`);
    
    console.log(`\n3. Check project status:`);
    console.log(`   ${colors.cyan}"Search memories for PROJECT_STATUS"${colors.reset}`);
    
    // 4. Display recent changes tracking
    console.log('\n📊 Recent Configuration Changes:\n');
    console.log(`• [${timestamp}] CONFIG_CHANGE: Removed 4 MCPs (graphlit, task-master-ai, brave, windtools)`);
    console.log(`• [${timestamp}] CONFIG_CHANGE: Updated to 14 active MCP servers`);
    console.log(`• [${timestamp}] DECISION: Context7 set as authoritative source for all code/library questions`);
    console.log(`• [${timestamp}] DECISION: Timestamps required for all status updates and logging`);
    
    // 5. Display Context7 reminders
    console.log('\n🔍 Context7 Usage Reminders:\n');
    console.log('Always use Context7 for code/library questions:');
    console.log(`• ${colors.cyan}"What is [topic]? use context7"${colors.reset}`);
    console.log(`• ${colors.cyan}"How does [library] work? use context7"${colors.reset}`);
    console.log(`• ${colors.cyan}"Explain [framework] concepts. use context7"${colors.reset}`);
    
    // 6. Display timestamp format
    console.log('\n⏰ Timestamp Format:\n');
    console.log(`Required format: [YYYY-MM-DD HH:MM:SS TZ]`);
    console.log(`Example: [${timestamp}]`);
    console.log(`Get current time: ${colors.cyan}date${colors.reset} command`);
    
    // 7. SuperMemory categories reference
    console.log('\n📁 SuperMemory Categories:\n');
    const categories = [
        { name: 'SESSION_START', desc: 'Session initialization' },
        { name: 'PROJECT_STATUS', desc: 'Major project updates' },
        { name: 'TASK_COMPLETE', desc: 'Completed tasks' },
        { name: 'CONFIG_CHANGE', desc: 'Configuration modifications' },
        { name: 'ERROR_FIX', desc: 'Problem resolutions' },
        { name: 'DECISION', desc: 'Architectural choices' }
    ];
    
    categories.forEach(cat => {
        console.log(`• ${colors.bright}${cat.name}${colors.reset}: ${cat.desc}`);
    });
    
    // 8. Quick commands
    console.log('\n⚡ Quick Commands:\n');
    console.log(`• Check MCP status: ${colors.cyan}npm run mcp-status${colors.reset}`);
    console.log(`• This startup check: ${colors.cyan}npm run supermemory-init${colors.reset}`);
    console.log(`• Full startup: ${colors.cyan}./startup.sh${colors.reset}`);
    
    console.log('\n✅ SuperMemory startup sequence complete!\n');
}

// Run main function
main().catch(err => {
    error(`Startup error: ${err.message}`);
    process.exit(1);
});