# Secure MCP Client with OAuth 2.1

A demonstration of secure Model Context Protocol (MCP) client-server communication using OAuth 2.1 authentication with automatic server discovery and resource indicators.

## Overview

This project showcases a three-tier secure MCP architecture:

- **OAuth 2.1 Authorization Server** - Handles client registration and token issuance
- **Weather MCP Server** - Provides weather tools with OAuth protection
- **MCP Client** - Connects to weather server via OAuth and integrates with Claude API

The client automatically discovers OAuth servers using RFC 8414, implements PKCE for security, and uses RFC 8707 resource indicators for fine-grained access control.

## Prerequisites

- Python 3.11 or higher
- [uv](https://docs.astral.sh/uv/) package manager
- Anthropic API key

## Quick Start

### 1. Install Dependencies

```bash
uv sync
```

### 2. Set Up Environment

Create a `.env` file with your Anthropic API key:

```bash
echo "ANTHROPIC_API_KEY=your_api_key_here" > .env
```

### 3. Start the Services

You'll need **three separate terminals** for the three components:

**Terminal 1: OAuth Authorization Server**

```bash
uv run python oauth.py
```

*Server starts on http://localhost:8003*

**Terminal 2: Weather MCP Server**

```bash
uv run python weather.py
```

*Server starts on http://127.0.0.1:8000*

**Terminal 3: MCP Client**

```bash
uv run python client.py
```

### 4. Authenticate and Query

When you start the client:

1. It will automatically discover the OAuth server
1. Register as a new OAuth client
1. Open your browser for authentication
1. After authorizing, paste the authorization code when prompted

### 5. Try an Example Query

Once authenticated, try this example query:

```
alerts in CA
```

This will use the weather server's `get_alerts` tool to fetch current weather alerts for California.

Other example queries:

- `get weather forecast for San Francisco`
- `check alerts in Texas`
- `weather forecast for latitude 37.7749 longitude -122.4194`

## Architecture Details

### OAuth 2.1 Flow

1. **Auto Discovery**: Client discovers OAuth server via RFC 8414 metadata
1. **Dynamic Registration**: Client registers with OAuth server (RFC 7591)
1. **Authorization**: Browser-based PKCE flow with resource indicators
1. **Token Exchange**: Secure token acquisition with resource targeting
1. **API Access**: Protected MCP server access with Bearer tokens

### Security Features

- **PKCE (Proof Key for Code Exchange)** - Prevents authorization code interception
- **Resource Indicators (RFC 8707)** - Restricts token usage to specific resources
- **Automatic Discovery (RFC 8414)** - No hardcoded OAuth endpoints
- **Token Validation** - Server-side token verification and resource checking

## Development

### Running Tests

```bash
# Install test dependencies
uv sync --extra test

# Run tests with coverage
python run_tests.py

# Run specific test
python run_tests.py test_specific_function_name
```

### Project Structure

```
├── client.py          # MCP OAuth client with discovery
├── weather.py         # Protected MCP server with weather tools  
├── oauth.py          # OAuth 2.1 authorization server
├── test_client.py    # Comprehensive test suite (99% coverage)
├── run_tests.py      # Test runner with coverage reporting
└── CLAUDE.md         # Detailed technical documentation
```

## Troubleshooting

**"Failed to discover OAuth authorization server"**

- Ensure the OAuth server is running on localhost:8003
- Check that the weather server is running on 127.0.0.1:8000

**"Resource access denied"**

- Verify consistent hostnames (127.0.0.1 vs localhost)
- Ensure OAuth flow completed successfully

**"No tools available"**

- Confirm weather server is running and accessible
- Check OAuth token is valid and not expired

For more technical details, see [CLAUDE.md](CLAUDE.md).
