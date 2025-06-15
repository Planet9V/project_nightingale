# Context7 MCP Configuration Guide

## Overview
Context7 is an MCP server that provides up-to-date code documentation directly in your AI coding environment. It dynamically fetches current official documentation and code examples, injecting them into your AI assistant's context window.

## Installation Status
✅ **Context7 is already configured** in your `.cursor/mcp.json` file

## Configuration Details

### Current Configuration
```json
{
  "context7": {
    "command": "npx",
    "args": [
      "-y",
      "@upstash/context7-mcp@latest"
    ],
    "env": {},
    "disabled": false,
    "autoApprove": ["get-library-docs", "resolve-library-id"]
  }
}
```

### Key Features
- **Real-Time Documentation**: Fetches the latest docs from official sources
- **Version-Specific Examples**: Gets code examples for exact library versions
- **No API Key Required**: Context7 is free and open-source
- **Auto-Approved Tools**: Documentation fetching is pre-approved for seamless use

## How to Use Context7

### Basic Usage
Simply add `use context7` to your prompts when you need documentation:

```
How do I create embeddings with Jina AI? use context7
```

### Examples

1. **TypeScript Questions**
   ```
   How do I configure tsconfig.json for CommonJS modules? use context7
   ```

2. **Library-Specific Help**
   ```
   Show me how to use Pinecone's upsert method with TypeScript use context7
   ```

3. **Framework Documentation**
   ```
   What's the latest Next.js App Router pattern? use context7
   ```

### Available Tools

1. **resolve-library-id**
   - Translates library names to internal IDs
   - Automatically called when needed

2. **get-library-docs**
   - Fetches documentation for specific libraries
   - Accepts optional topic parameter
   - Examples:
     ```
     get-library-docs("react", "hooks")
     get-library-docs("typescript", "configuration")
     get-library-docs("pinecone", "vector operations")
     ```

## Prioritization Strategy

### 1. Context7 First (Local Documentation)
When you need:
- Library/framework documentation
- API references
- Configuration examples
- Code patterns
- Version-specific information

### 2. Web Search Second (Current Information)
When you need:
- Recent updates not in Context7
- Blog posts and tutorials
- Community solutions
- Troubleshooting specific errors
- Real-world examples

### Configuration for Priority Usage

The MCP servers are configured in priority order:
1. **Context7** - For documentation
2. **Tavily** - For web search
3. **Jina AI** - For content processing
4. Other specialized servers

## Troubleshooting

### If Context7 Doesn't Work

1. **Check Node.js Version**
   ```bash
   node -v  # Should be 18.0.0 or higher
   ```

2. **Test Context7 Manually**
   ```bash
   npx -y @upstash/context7-mcp@latest
   ```

3. **Restart Cursor/VSCode**
   After configuration changes, restart your editor

### Common Issues

1. **"Context7 not available"**
   - Ensure MCP is enabled in your editor
   - Check that the configuration is in the correct file
   - Verify Node.js is installed

2. **Outdated Documentation**
   - Context7 fetches from official sources
   - Some libraries may not be indexed
   - Fall back to web search for very new features

## Best Practices

### 1. Specific Queries
```
# Good
How do I use Jina embeddings v2 with TypeScript? use context7

# Better
Show me Jina AI embedding API TypeScript examples use context7
```

### 2. Combine with Web Search
```
# First try Context7
How to configure Pinecone index? use context7

# If needed, follow up with web search
What are the latest Pinecone best practices for 2025?
```

### 3. Library Version Awareness
```
# Specify versions when relevant
How to use React 18 Suspense? use context7
TypeScript 5.0 new features use context7
```

## Supported Libraries

Context7 supports documentation for:
- **Languages**: TypeScript, JavaScript, Python, Go, Rust, Java
- **Frameworks**: React, Next.js, Vue, Angular, Express
- **Databases**: PostgreSQL, MongoDB, Redis, Neo4j
- **AI/ML**: TensorFlow, PyTorch, Hugging Face, OpenAI
- **Cloud**: AWS, Azure, GCP, Vercel, Netlify
- **Tools**: Docker, Kubernetes, Git, npm, yarn

## Integration with Project Seldon

For Project Seldon development, use Context7 for:

1. **TypeScript Configuration**
   ```
   How to fix TypeScript module resolution errors? use context7
   ```

2. **Jina AI Integration**
   ```
   Jina AI embeddings API documentation use context7
   ```

3. **Pinecone Operations**
   ```
   Pinecone vector database TypeScript SDK use context7
   ```

4. **Supabase Queries**
   ```
   Supabase JavaScript client documentation use context7
   ```

## Monitoring Usage

Context7 usage is logged in your editor's output panel:
1. Open Output panel
2. Select "MCP" or "Context7" from dropdown
3. View fetched documentation and errors

## Additional Resources

- [Context7 GitHub Repository](https://github.com/upstash/context7)
- [MCP Documentation](https://modelcontextprotocol.io)
- [Upstash Blog on Context7](https://upstash.com/blog/context7-mcp)

---

**Last Updated**: June 13, 2025  
**Status**: ✅ Configured and Ready  
**Priority**: Primary documentation source before web search