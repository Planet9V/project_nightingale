# Claude Desktop vs Claude Code: MCP Architecture Explained

## Quick Summary

**Claude Desktop (Windows) and Claude Code (WSL) are completely separate and CANNOT share MCP servers.**

### Key Points:
- Different config files
- Different process spaces
- No cross-communication
- Must configure MCPs separately for each

---

## Technical Architecture

### 1. Process Isolation

```
Windows 10 Host OS
│
├── Claude Desktop Application (Windows Process)
│   ├── Config: C:\Users\[username]\AppData\Roaming\Claude\claude_desktop_config.json
│   ├── MCP Process Space: Windows native
│   └── Cannot access WSL2 processes
│
└── WSL2 Virtual Machine (Lightweight Linux VM)
    └── Claude Code (Linux Process)
        ├── Config: /home/[user]/.config/claude/claude_code_config.json
        ├── Alternative: /home/[user]/project/.cursor/mcp.json
        ├── MCP Process Space: Linux
        └── Cannot access Windows processes
```

### 2. MCP Communication Model

According to the Model Context Protocol specification:
- MCPs communicate via **stdio** (standard input/output streams)
- No network protocols involved
- Parent process (Claude) spawns child process (MCP)
- Communication is through pipes, not sockets

### 3. Why Cross-Environment MCPs Don't Work

#### Windows → WSL Limitation:
- Windows processes cannot directly spawn WSL processes via stdio
- WSL2 runs in a Hyper-V virtual machine
- No shared process namespace

#### WSL → Windows Limitation:
- WSL processes see Windows as `/mnt/c/` filesystem
- Cannot spawn Windows .exe files with proper stdio handling
- Different executable formats (ELF vs PE)

---

## Configuration Examples

### Claude Desktop (Windows)
Location: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "tavily": {
      "command": "npx",
      "args": ["-y", "tavily-mcp@latest"],
      "env": {
        "TAVILY_API_KEY": "your-key-here"
      }
    }
  }
}
```

### Claude Code (WSL)
Location: `~/.config/claude/claude_code_config.json` or `.cursor/mcp.json`

```json
{
  "mcpServers": {
    "tavily": {
      "command": "npx",
      "args": ["-y", "tavily-mcp@latest"],
      "env": {
        "TAVILY_API_KEY": "your-key-here"
      }
    }
  }
}
```

---

## Practical Setup Guide

### To Use Tavily in Both Environments:

#### 1. Windows (Claude Desktop):
```powershell
# In Windows PowerShell/CMD
npm install -g tavily-mcp
# Edit %APPDATA%\Claude\claude_desktop_config.json
```

#### 2. WSL (Claude Code):
```bash
# In WSL terminal
npm install tavily-mcp
# Edit ~/.config/claude/claude_code_config.json or .cursor/mcp.json
```

### Important Notes:
1. **Separate NPM installations** - Windows npm and WSL npm are different
2. **Separate node_modules** - No sharing between environments
3. **API keys must be configured twice** - Once for each environment

---

## Theoretical Workarounds (Not Recommended)

### Network-Based MCP:
If an MCP server supported network communication (TCP/HTTP):
```
Windows MCP Server (port 8080) ← Network → WSL Claude Code
```
But this would require:
- Custom MCP implementation
- Network protocol support (not in MCP spec)
- Security considerations

### WSL Interop (Limited):
```bash
# WSL can run Windows executables
/mnt/c/Windows/System32/cmd.exe /c "npx tavily-mcp"
```
But stdio redirection is problematic and unreliable.

---

## Best Practices

1. **Treat as separate environments** - Configure MCPs independently
2. **Use version control** - Commit both config files
3. **Document both setups** - Maintain separate documentation
4. **Consistent API keys** - Use same keys in both for consistency

---

## References

1. **MCP Specification**: https://github.com/anthropics/model-context-protocol
   - "Servers communicate with clients via stdio"
   
2. **WSL2 Architecture**: https://docs.microsoft.com/en-us/windows/wsl/compare-versions
   - "WSL 2 uses virtualization technology to run a Linux kernel inside of a lightweight utility virtual machine (VM)"

3. **Claude Desktop Config**: https://docs.anthropic.com/claude/docs/claude-desktop
   - Configuration stored in platform-specific locations

4. **Process Isolation**: https://docs.microsoft.com/en-us/windows/wsl/filesystems
   - WSL2 and Windows have separate process namespaces

---

## Summary

Claude Desktop and Claude Code operate in completely isolated environments with no ability to share MCP servers. This is by design for:
- Security isolation
- Process stability  
- Platform compatibility
- Clear separation of concerns

**Bottom line**: Install and configure your MCPs twice - once for each environment.