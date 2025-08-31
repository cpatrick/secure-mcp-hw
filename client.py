import asyncio
from typing import Optional
import webbrowser
import urllib.parse
import secrets
import base64
import hashlib

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()  # load environment variables from .env

_MODEL = "claude-3-5-haiku-20241022"


class MCPClient:
    def __init__(self):
        # Initialize session and client objects
        self.session: Optional[ClientSession] = None
        self.anthropic = Anthropic()
        self.access_token: Optional[str] = None
        self.client_id: Optional[str] = None
        self.client_secret: Optional[str] = None
        self.server_url: Optional[str] = None
        self.discovered_auth_server: Optional[str] = None

    async def discover_oauth_server(self, mcp_server_url: str) -> Optional[str]:
        """Discover OAuth authorization server from MCP server metadata (RFC 8414)"""
        try:
            # Try to discover OAuth protected resource metadata
            async with httpx.AsyncClient() as client:
                # Remove /mcp suffix if present for metadata discovery
                base_url = mcp_server_url.rstrip("/mcp").rstrip("/")
                metadata_url = f"{base_url}/.well-known/oauth-protected-resource"

                print(f"🔍 Discovering OAuth server from: {metadata_url}")
                response = await client.get(metadata_url, timeout=10.0)

                if response.status_code == 200:
                    metadata = response.json()
                    auth_servers = metadata.get("authorization_servers", [])

                    if auth_servers:
                        auth_server_url = auth_servers[0]  # Use the first one
                        print(f"✓ Discovered OAuth server: {auth_server_url}")

                        # Now get the authorization server metadata (RFC 8414)
                        auth_metadata = await self.get_authorization_server_metadata(
                            auth_server_url
                        )
                        if auth_metadata:
                            self.discovered_auth_server = auth_server_url
                            return auth_server_url

                print("⚠️  No OAuth server discovered from MCP server metadata")
                return None

        except Exception as e:
            print(f"⚠️  OAuth server discovery failed: {e}")
            return None

    async def get_authorization_server_metadata(
        self, auth_server_url: str
    ) -> Optional[dict]:
        """Get OAuth authorization server metadata per RFC 8414"""
        try:
            async with httpx.AsyncClient() as client:
                # RFC 8414 specifies /.well-known/oauth-authorization-server
                metadata_url = (
                    f"{auth_server_url}/.well-known/oauth-authorization-server"
                )

                print(f"📋 Getting authorization server metadata from: {metadata_url}")
                response = await client.get(metadata_url, timeout=10.0)
                response.raise_for_status()

                metadata = response.json()

                # Validate required fields per RFC 8414
                required_fields = [
                    "issuer",
                    "authorization_endpoint",
                    "token_endpoint",
                    "response_types_supported",
                ]
                for field in required_fields:
                    if field not in metadata:
                        print(f"❌ Missing required metadata field: {field}")
                        return None

                # Validate issuer matches the authorization server URL
                if metadata["issuer"] != auth_server_url:
                    print(
                        f"❌ Issuer mismatch: {metadata['issuer']} != {auth_server_url}"
                    )
                    return None

                print(f"✓ Valid authorization server metadata discovered")
                print(
                    f"  - Authorization endpoint: {metadata['authorization_endpoint']}"
                )
                print(f"  - Token endpoint: {metadata['token_endpoint']}")
                if "registration_endpoint" in metadata:
                    print(
                        f"  - Registration endpoint: {metadata['registration_endpoint']}"
                    )

                return metadata

        except Exception as e:
            print(f"❌ Failed to get authorization server metadata: {e}")
            return None

    async def register_oauth_client(self, auth_server_url: str, server_url: str):
        """Register as OAuth client with dynamic client registration"""
        registration_data = {
            "client_name": "MCP Weather Client",
            "redirect_uris": ["http://localhost:8080/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{auth_server_url}/oauth/register",
                json=registration_data,
                timeout=30.0,
            )
            response.raise_for_status()

            client_data = response.json()
            self.client_id = client_data["client_id"]
            self.client_secret = client_data["client_secret"]

            print(f"✓ Registered OAuth client: {self.client_id}")
            return client_data

    def generate_pkce_challenge(self):
        """Generate PKCE code verifier and challenge"""
        code_verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .decode("utf-8")
            .rstrip("=")
        )
        code_challenge = (
            base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode("utf-8")).digest()
            )
            .decode("utf-8")
            .rstrip("=")
        )
        return code_verifier, code_challenge

    async def perform_oauth_flow(self, auth_server_url: str, server_url: str):
        """Perform OAuth 2.1 authorization code flow with PKCE"""

        # Generate PKCE parameters
        code_verifier, code_challenge = self.generate_pkce_challenge()

        # Build authorization URL
        auth_params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": "http://localhost:8080/callback",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "scope": "read",
            "resource": server_url,
            "state": secrets.token_urlsafe(16),
        }

        auth_url = f"{auth_server_url}/oauth/authorize?" + urllib.parse.urlencode(
            auth_params
        )

        print(f"Opening browser for OAuth authorization...")
        print(f"If browser doesn't open, visit: {auth_url}")

        # Open browser for authorization
        webbrowser.open(auth_url)

        # Get authorization code from user
        auth_code = input(
            "\nPaste the authorization code from the callback URL: "
        ).strip()

        # Exchange code for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": "http://localhost:8080/callback",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code_verifier": code_verifier,
            "resource": server_url,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{auth_server_url}/oauth/token", data=token_data, timeout=30.0
            )
            response.raise_for_status()

            token_response = response.json()
            self.access_token = token_response["access_token"]

            print("✓ Successfully obtained access token")
            return token_response

    async def connect_to_server(
        self,
        server_url: str = "http://127.0.0.1:8000",
    ):
        """Connect to an MCP server using HTTP transport with OAuth 2.1
        OAuth authorization is mandatory and discovered automatically via RFC 8414.

        Args:
            server_url: URL of the MCP server
        """

        print(f"\nConnecting to MCP server: {server_url}")

        # Always discover OAuth server via RFC 8414
        print("🔍 Discovering OAuth server via RFC 8414...")
        auth_server_url = await self.discover_oauth_server(server_url)

        if not auth_server_url:
            raise ValueError(
                "Failed to discover OAuth authorization server. Ensure the MCP server exposes OAuth metadata at /.well-known/oauth-protected-resource"
            )

        print(f"✓ Discovered OAuth server: {auth_server_url}")

        # Register OAuth client
        await self.register_oauth_client(auth_server_url, server_url)

        # Perform OAuth authorization flow
        await self.perform_oauth_flow(auth_server_url, server_url)

        # Store server URL for later use
        self.server_url = server_url

        print("✓ MCP client configured with streamable HTTP transport and OAuth")

    async def process_query(self, query: str) -> str:
        """Process a query using Claude and available tools"""
        if not self.access_token or not self.server_url:
            raise ValueError("Client not connected. Call connect_to_server first.")

        print("Processing query with MCP tools...")

        # Create HTTP headers with OAuth token
        headers = {"Authorization": f"Bearer {self.access_token}"}

        # Use streamablehttp_client to create session streams
        try:
            async with streamablehttp_client(self.server_url, headers=headers) as (
                read_stream,
                write_stream,
                get_session_id,
            ):
                print(f"✓ Connected to {self.server_url}")

                # Create MCP session with the streams
                async with ClientSession(read_stream, write_stream) as session:
                    print("✓ Initializing MCP session...")
                    # Initialize the session
                    await session.initialize()
                    print("✓ MCP session initialized")

                    messages = [{"role": "user", "content": query}]

                    # Get available tools from MCP session
                    print("✓ Getting available tools...")
                    tools_response = await session.list_tools()
                    tools_list = tools_response.tools if tools_response else []

                    if not tools_list:
                        return "No tools available from the server."

                    print(f"Available tools: {[tool.name for tool in tools_list]}")

                    # Convert MCP tools to Anthropic format
                    available_tools = [
                        {
                            "name": tool.name,
                            "description": tool.description or "No description",
                            "input_schema": (
                                tool.inputSchema if tool.inputSchema else {}
                            ),
                        }
                        for tool in tools_list
                    ]

                    # Initial Claude API call
                    print("✓ Calling Claude API...")
                    response = self.anthropic.messages.create(
                        model=_MODEL,
                        max_tokens=1000,
                        messages=messages,
                        tools=available_tools,
                    )

                    # Process response and handle tool calls
                    final_text = []
                    assistant_message_content = []

                    for content in response.content:
                        if content.type == "text":
                            final_text.append(content.text)
                            assistant_message_content.append(content)
                        elif content.type == "tool_use":
                            tool_name = content.name
                            tool_args = content.input

                            print(f"Calling tool {tool_name} with args {tool_args}")

                            # Execute tool call using MCP session
                            result = await session.call_tool(tool_name, tool_args or {})
                            tool_result = (
                                result.content[0].text
                                if result.content
                                else str(result)
                            )

                            final_text.append(
                                f"[Calling tool {tool_name} with args {tool_args}]"
                            )

                            assistant_message_content.append(content)
                            messages.append(
                                {
                                    "role": "assistant",
                                    "content": assistant_message_content,
                                }
                            )
                            messages.append(
                                {
                                    "role": "user",
                                    "content": [
                                        {
                                            "type": "tool_result",
                                            "tool_use_id": content.id,
                                            "content": tool_result,
                                        }
                                    ],
                                }
                            )

                            # Get next response from Claude
                            response = self.anthropic.messages.create(
                                model=_MODEL,
                                max_tokens=1000,
                                messages=messages,
                                tools=available_tools,
                            )

                            final_text.append(response.content[0].text)

                    return "\n".join(final_text)
        except Exception as e:
            print(f"Error in MCP communication: {e}")
            import traceback

            traceback.print_exc()
            raise

    async def chat_loop(self):
        """Run an interactive chat loop"""
        print("\nMCP Client Started!")
        print("Type your queries or 'quit' to exit.")

        while True:
            try:
                query = input("\nQuery: ").strip()

                if query.lower() == "quit":
                    break

                response = await self.process_query(query)
                print("\n" + response)

            except Exception as e:
                print(f"\nError: {str(e)}")

    async def cleanup(self):
        """Clean up resources"""
        # Session cleanup is handled by context managers
        pass


async def main():
    server_url = "http://127.0.0.1:8000/mcp"

    # Parse command line arguments
    import argparse

    parser = argparse.ArgumentParser(
        description="MCP Client with HTTP transport and OAuth 2.1 authentication (OAuth server auto-discovered via RFC 8414)"
    )
    parser.add_argument("--server-url", default=server_url, help="MCP server URL")

    args = parser.parse_args()

    client = MCPClient()
    try:
        await client.connect_to_server(server_url=args.server_url)
        await client.chat_loop()
    finally:
        await client.cleanup()


if __name__ == "__main__":
    import sys

    asyncio.run(main())
