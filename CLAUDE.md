# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

This project uses Python with uv for dependency management:

```bash
# Install dependencies
uv sync

# Run the OAuth 2.1 authorization server (terminal 1) - REQUIRED
uv run python oauth.py

# Run the weather MCP server (terminal 2) - uses custom OAuth middleware
uv run python weather.py

# Run the MCP client (terminal 3) - uses custom OAuth implementation
uv run python client.py

# Run client with custom URLs
uv run python client.py --server-url http://localhost:8000/mcp --auth-server http://localhost:8001
```

## Project Architecture

This is an MCP (Model Context Protocol) client-server demonstration project exploring client security patterns. The architecture consists of:

### Core Components

- **MCPClient** (`client.py`): Custom MCP client with OAuth 2.1 implementation
  - Uses MCP's `ClientSession` with HTTP streamable transport
  - Custom OAuth 2.1 authorization code flow with PKCE
  - Manual token management and validation
  - Browser-based authorization flow for user consent
  - Manages bi-directional communication with Claude API and MCP tools
  - Implements tool execution workflow with proper message threading
  
- **Weather MCP Server** (`weather.py`): FastMCP server with custom OAuth middleware
  - Runs as HTTP server using SSE transport on localhost:8000
  - Custom OAuth validation middleware using `get_http_headers()`
  - Implements two tools: `get_alerts(state)` and `get_forecast(latitude, longitude)`
  - Uses National Weather Service API with proper error handling
  - OAuth token validation for all MCP requests

- **OAuth 2.1 Authorization Server** (`oauth.py`): Full-featured OAuth server
  - Supports dynamic client registration (RFC 7591)
  - Implements OAuth 2.1 authorization code flow with PKCE
  - Provides authorization server metadata discovery (RFC 8414)
  - Supports resource indicators for MCP server targeting
  - Token validation endpoint for MCP server middleware
  - Runs on localhost:8001 with web interface

### Key Architecture Patterns

- **Custom OAuth Implementation**: Manual OAuth 2.1 implementation with PKCE security
- **Three-Tier Architecture**: OAuth Server → MCP Server → Client with proper token validation
- **HTTP Communication**: Client and server communicate via HTTP Server-Sent Events (SSE)
- **Separate Processes**: All components run independently as separate HTTP services
- **Manual Token Management**: Custom token handling, validation, and HTTP header management
- **Browser-based Flow**: OAuth authentication opens browser for user consent
- **PKCE Security**: Authorization code flow uses PKCE for enhanced security
- **Resource Targeting**: OAuth tokens include resource indicators for specific MCP servers
- **Context Manager Pattern**: MCP ClientSession uses async context managers for proper cleanup
- **Tool Call Flow**: Client → Claude API → Tool Execution → Results back to Claude → Final Response
- **Dynamic Client Registration**: Automatic client registration with OAuth server
- **Middleware Authentication**: FastMCP middleware validates OAuth tokens using `get_http_headers()`

### OAuth Flow (Custom Implementation)

1. **Client Registration**: Dynamic registration with OAuth server using RFC 7591
2. **PKCE Generation**: Generate code verifier and challenge for enhanced security
3. **Browser Authorization**: Open browser for user consent with authorization URL
4. **Manual Code Entry**: User manually enters authorization code from callback
5. **Token Exchange**: Authorization code exchanged for access tokens with PKCE verification
6. **HTTP Headers**: Access tokens manually included in MCP request headers
7. **Server Validation**: MCP server middleware validates tokens with OAuth server

### Dependencies

- `mcp>=1.13.1`: Core MCP protocol implementation
- `fastmcp>=2.11.0`: FastMCP for server implementation and middleware
- `anthropic>=0.64.0`: Claude API integration  
- `python-dotenv>=1.1.1`: Environment variable management
- `uvicorn>=0.20.0`: ASGI server for HTTP transport
- `fastapi>=0.104.0`: Web framework for OAuth server
- `python-multipart>=0.0.6`: Form data parsing for OAuth
- `httpx`: HTTP client for weather API calls and OAuth validation

The client expects an `.env` file with `ANTHROPIC_API_KEY` for Claude API access.

### Benefits of Custom OAuth Implementation

- ✅ **Educational Value**: Demonstrates OAuth 2.1 flow implementation details
- ✅ **Full Control**: Complete control over token management and validation
- ✅ **Security Standards**: PKCE, dynamic registration, resource indicators
- ✅ **Debugging Visibility**: Clear logging of each OAuth step
- ✅ **Standards Compliant**: Full OAuth 2.1 and RFC compliance
- ✅ **Middleware Integration**: Custom FastMCP middleware for token validation