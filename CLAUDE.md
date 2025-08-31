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

# Run the MCP client (terminal 3) - uses OAuth discovery via RFC 8414
uv run python client.py

# Run client with custom MCP server URL (OAuth server auto-discovered)
uv run python client.py --server-url http://localhost:8000/mcp

# Run unit tests
uv run pytest test_client.py -v

# Run tests with coverage report
uv run pytest test_client.py -v --cov=client --cov-report=term-missing
```

## Project Architecture

This is an MCP (Model Context Protocol) client-server demonstration project exploring client security patterns. The architecture consists of:

### Core Components

- **MCPClient** (`client.py`): Custom MCP client with OAuth 2.1 discovery
  - Uses MCP's `ClientSession` with HTTP streamable transport
  - Automatic OAuth server discovery via RFC 8414
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

- **RFC 8414 Discovery**: Automatic OAuth server discovery via authorization server metadata
- **RFC 8707 Resource Indicators**: Precise token audience targeting for specific MCP servers
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
- **Middleware Authentication**: FastMCP middleware validates OAuth tokens and resource access

### OAuth Flow (Discovery + Resource Indicators)

1. **Server Discovery**: Discover OAuth server from MCP server's `/.well-known/oauth-protected-resource`
2. **Metadata Validation**: Validate OAuth server metadata via RFC 8414 `/.well-known/oauth-authorization-server`
3. **Resource Validation**: Validate MCP server URI per RFC 8707 (absolute URI, no fragments)
4. **Client Registration**: Dynamic registration with OAuth server using RFC 7591
5. **PKCE Generation**: Generate code verifier and challenge for enhanced security
6. **Authorization Request**: Request authorization with resource indicator targeting specific MCP server
7. **Browser Authorization**: Open browser for user consent with authorization URL
8. **Manual Code Entry**: User manually enters authorization code from callback
9. **Token Exchange**: Exchange code for access token with resource indicator for audience restriction
10. **Resource Verification**: Validate returned token resource matches requested resource
11. **HTTP Headers**: Include access tokens in MCP request headers
12. **Server Validation**: MCP server middleware validates tokens and resource access per RFC 8707

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

## Testing

The project includes comprehensive unit tests for the OAuth client implementation:

### Test Coverage
- **OAuth Server Discovery**: Tests RFC 8414 endpoint discovery and metadata validation
- **Resource URI Validation**: Tests RFC 8707 resource indicator validation
- **PKCE Generation**: Tests code verifier and challenge generation for security
- **Client Registration**: Tests dynamic client registration per RFC 7591
- **Token Exchange**: Tests OAuth 2.1 authorization code flow with resource indicators
- **Error Handling**: Tests various failure scenarios and edge cases
- **Integration Tests**: End-to-end flow testing with mocked HTTP responses

### Running Tests
```bash
# Install test dependencies
uv sync --extra test

# Run all tests
uv run pytest test_client.py -v

# Run tests with coverage report
uv run pytest test_client.py -v --cov=client --cov-report=term-missing

# Run specific test
uv run pytest test_client.py::TestMCPClient::test_validate_resource_uri_valid -v

# Run test runner script (with coverage HTML report)
uv run python run_tests.py
```

### Test Structure
- `TestMCPClient`: Unit tests for individual methods and functionality
- `TestMCPClientIntegration`: Integration tests for complete workflows
- Comprehensive mocking of HTTP requests and responses
- Async test support with pytest-asyncio
- Coverage reporting with pytest-cov

### Benefits of Discovery-Based OAuth with Resource Indicators

- ✅ **Automatic Discovery**: Zero configuration OAuth server discovery via RFC 8414
- ✅ **Standards Compliant**: Full OAuth 2.1, RFC 8414, RFC 8707, and RFC 7591 compliance
- ✅ **Precise Authorization**: Resource indicators prevent cross-server token misuse
- ✅ **Educational Value**: Demonstrates complete OAuth 2.1 flow with modern extensions
- ✅ **Full Control**: Complete control over token management and validation
- ✅ **Security Standards**: PKCE, dynamic registration, resource targeting
- ✅ **Resource Validation**: Client-side and server-side resource access validation
- ✅ **Debugging Visibility**: Clear logging of discovery, OAuth, and resource validation steps
- ✅ **Middleware Integration**: Custom FastMCP middleware for comprehensive validation
- ✅ **Production Ready**: Robust error handling, fallback mechanisms, and security checks