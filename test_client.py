"""
Unit tests for MCP Client with OAuth 2.1 and Resource Indicators (RFC 8707)
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, mock_open
from typing import Optional
import json

import httpx
from client import MCPClient


class TestMCPClient:
    """Test suite for MCPClient class"""

    def setup_method(self):
        """Set up test fixtures before each test method"""
        self.client = MCPClient()

    def test_init(self):
        """Test MCPClient initialization"""
        client = MCPClient()
        assert client.access_token is None
        assert client.client_id is None
        assert client.client_secret is None
        assert client.server_url is None
        assert client.discovered_auth_server is None
        assert client.token_resource is None

    def test_validate_resource_uri_valid(self):
        """Test resource URI validation with valid URIs"""
        # Test HTTP URI
        result = self.client.validate_resource_uri("http://example.com/api")
        assert result == "http://example.com/api"

        # Test HTTPS URI
        result = self.client.validate_resource_uri("https://example.com/api")
        assert result == "https://example.com/api"

        # Test URI with trailing slash removal
        result = self.client.validate_resource_uri("http://example.com/api/")
        assert result == "http://example.com/api"

        # Test URI with multiple trailing slashes
        result = self.client.validate_resource_uri("http://example.com/api///")
        assert result == "http://example.com/api"

    def test_validate_resource_uri_invalid(self):
        """Test resource URI validation with invalid URIs"""
        # Test relative URI (should fail per RFC 8707)
        with pytest.raises(ValueError, match="Resource URI must be absolute"):
            self.client.validate_resource_uri("/relative/path")

        # Test URI with fragment (should fail per RFC 8707)
        with pytest.raises(ValueError, match="Resource URI must not contain fragment"):
            self.client.validate_resource_uri("http://example.com/api#fragment")

        # Test non-HTTP URI
        with pytest.raises(ValueError, match="Resource URI must be absolute"):
            self.client.validate_resource_uri("ftp://example.com")

    @pytest.mark.asyncio
    async def test_discover_oauth_server_success(self):
        """Test successful OAuth server discovery"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "resource": "http://example.com",
            "authorization_servers": ["http://auth.example.com"]
        }

        mock_auth_metadata = {
            "issuer": "http://auth.example.com",
            "authorization_endpoint": "http://auth.example.com/oauth/authorize",
            "token_endpoint": "http://auth.example.com/oauth/token",
            "response_types_supported": ["code"]
        }

        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get.side_effect = [mock_response, MagicMock(
                status_code=200,
                json=lambda: mock_auth_metadata,
                raise_for_status=MagicMock()
            )]

            result = await self.client.discover_oauth_server("http://example.com/mcp")

            assert result == "http://auth.example.com"
            assert self.client.discovered_auth_server == "http://auth.example.com"

    @pytest.mark.asyncio
    async def test_discover_oauth_server_no_metadata(self):
        """Test OAuth server discovery when metadata endpoint is not found"""
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get.return_value = mock_response

            result = await self.client.discover_oauth_server("http://example.com/mcp")

            assert result is None
            assert self.client.discovered_auth_server is None

    @pytest.mark.asyncio
    async def test_discover_oauth_server_no_auth_servers(self):
        """Test OAuth server discovery when no authorization servers are listed"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "resource": "http://example.com",
            "authorization_servers": []
        }

        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get.return_value = mock_response

            result = await self.client.discover_oauth_server("http://example.com/mcp")

            assert result is None

    @pytest.mark.asyncio
    async def test_get_authorization_server_metadata_success(self):
        """Test successful authorization server metadata retrieval"""
        mock_metadata = {
            "issuer": "http://auth.example.com",
            "authorization_endpoint": "http://auth.example.com/oauth/authorize",
            "token_endpoint": "http://auth.example.com/oauth/token",
            "response_types_supported": ["code"],
            "registration_endpoint": "http://auth.example.com/oauth/register"
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_metadata
        mock_response.raise_for_status = MagicMock()

        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get.return_value = mock_response

            result = await self.client.get_authorization_server_metadata("http://auth.example.com")

            assert result == mock_metadata
            mock_instance.get.assert_called_once_with(
                "http://auth.example.com/.well-known/oauth-authorization-server",
                timeout=10.0
            )

    @pytest.mark.asyncio
    async def test_get_authorization_server_metadata_missing_required_field(self):
        """Test authorization server metadata with missing required fields"""
        mock_metadata = {
            "issuer": "http://auth.example.com",
            "authorization_endpoint": "http://auth.example.com/oauth/authorize",
            # Missing token_endpoint and response_types_supported
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_metadata
        mock_response.raise_for_status = MagicMock()

        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get.return_value = mock_response

            result = await self.client.get_authorization_server_metadata("http://auth.example.com")

            assert result is None

    @pytest.mark.asyncio
    async def test_get_authorization_server_metadata_issuer_mismatch(self):
        """Test authorization server metadata with issuer mismatch"""
        mock_metadata = {
            "issuer": "http://different.example.com",  # Mismatched issuer
            "authorization_endpoint": "http://auth.example.com/oauth/authorize",
            "token_endpoint": "http://auth.example.com/oauth/token",
            "response_types_supported": ["code"]
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_metadata
        mock_response.raise_for_status = MagicMock()

        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get.return_value = mock_response

            result = await self.client.get_authorization_server_metadata("http://auth.example.com")

            assert result is None

    @pytest.mark.asyncio
    async def test_register_oauth_client_success(self):
        """Test successful OAuth client registration"""
        mock_response_data = {
            "client_id": "test_client_123",
            "client_secret": "test_secret_456",
            "client_name": "MCP Weather Client"
        }

        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status = MagicMock()

        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.post.return_value = mock_response

            result = await self.client.register_oauth_client(
                "http://auth.example.com",
                "http://example.com/mcp"
            )

            assert result == mock_response_data
            assert self.client.client_id == "test_client_123"
            assert self.client.client_secret == "test_secret_456"

    def test_generate_pkce_challenge(self):
        """Test PKCE challenge generation"""
        code_verifier, code_challenge = self.client.generate_pkce_challenge()

        # Verify code verifier properties
        assert len(code_verifier) >= 43  # Base64url without padding
        assert len(code_verifier) <= 128
        # Base64url characters: A-Z, a-z, 0-9, -, _
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        assert all(c in valid_chars for c in code_verifier)

        # Verify code challenge properties
        assert len(code_challenge) == 43  # SHA256 base64url without padding
        assert all(c in valid_chars for c in code_challenge)

        # Verify they're different
        assert code_verifier != code_challenge

    @pytest.mark.asyncio
    async def test_perform_oauth_flow_success(self):
        """Test successful OAuth flow execution"""
        # Setup client credentials
        self.client.client_id = "test_client"
        self.client.client_secret = "test_secret"

        # Mock token response
        mock_token_response = {
            "access_token": "test_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "resource": "http://example.com/mcp"
        }

        mock_response = MagicMock()
        mock_response.json.return_value = mock_token_response
        mock_response.raise_for_status = MagicMock()

        with patch('httpx.AsyncClient') as mock_client, \
             patch('webbrowser.open') as mock_browser, \
             patch('builtins.input', return_value='test_auth_code'):

            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.post.return_value = mock_response

            result = await self.client.perform_oauth_flow(
                "http://auth.example.com",
                "http://example.com/mcp"
            )

            assert result == mock_token_response
            assert self.client.access_token == "test_access_token"
            assert self.client.token_resource == "http://example.com/mcp"

    @pytest.mark.asyncio
    async def test_connect_to_server_with_discovery(self):
        """Test connect_to_server with OAuth discovery"""
        # Mock discovery response
        mock_discovery_response = MagicMock()
        mock_discovery_response.status_code = 200
        mock_discovery_response.json.return_value = {
            "resource": "http://127.0.0.1:8000",
            "authorization_servers": ["http://localhost:8001"]
        }

        # Mock auth server metadata
        mock_auth_metadata = {
            "issuer": "http://localhost:8001",
            "authorization_endpoint": "http://localhost:8001/oauth/authorize",
            "token_endpoint": "http://localhost:8001/oauth/token",
            "response_types_supported": ["code"]
        }

        # Mock registration response
        mock_registration_response = MagicMock()
        mock_registration_response.json.return_value = {
            "client_id": "test_client",
            "client_secret": "test_secret"
        }
        mock_registration_response.raise_for_status = MagicMock()

        # Mock token response
        mock_token_response = MagicMock()
        mock_token_response.json.return_value = {
            "access_token": "test_token",
            "resource": "http://127.0.0.1:8000/mcp"
        }
        mock_token_response.raise_for_status = MagicMock()

        with patch('httpx.AsyncClient') as mock_client, \
             patch('webbrowser.open'), \
             patch('builtins.input', return_value='auth_code'):

            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get.side_effect = [
                mock_discovery_response,  # Discovery endpoint
                MagicMock(status_code=200, json=lambda: mock_auth_metadata, raise_for_status=MagicMock())  # Auth metadata
            ]
            mock_instance.post.side_effect = [
                mock_registration_response,  # Registration
                mock_token_response  # Token
            ]

            await self.client.connect_to_server("http://127.0.0.1:8000/mcp")

            assert self.client.server_url == "http://127.0.0.1:8000/mcp"
            assert self.client.access_token == "test_token"

    @pytest.mark.asyncio
    async def test_connect_to_server_discovery_fails(self):
        """Test connect_to_server when discovery fails"""
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get.return_value = MagicMock(status_code=404)

            with pytest.raises(ValueError, match="Failed to discover OAuth authorization server"):
                await self.client.connect_to_server("http://127.0.0.1:8000/mcp")

    @pytest.mark.asyncio
    async def test_process_query_resource_mismatch(self):
        """Test process_query with token resource mismatch"""
        # Setup client state
        self.client.access_token = "test_token"
        self.client.server_url = "http://example.com/mcp"
        self.client.token_resource = "http://different.com/mcp"

        with pytest.raises(ValueError, match="Token resource mismatch"):
            await self.client.process_query("test query")

    def test_cleanup(self):
        """Test cleanup method"""
        # Should not raise any exceptions
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.client.cleanup())
        finally:
            loop.close()


class TestMCPClientIntegration:
    """Integration tests for MCPClient"""

    @pytest.mark.asyncio
    async def test_full_discovery_flow_mock(self):
        """Test the complete discovery and connection flow with mocked responses"""
        client = MCPClient()

        # Mock all HTTP responses in sequence
        discovery_response = MagicMock()
        discovery_response.status_code = 200
        discovery_response.json.return_value = {
            "resource": "http://127.0.0.1:8000",
            "authorization_servers": ["http://localhost:8001"]
        }

        metadata_response = MagicMock()
        metadata_response.status_code = 200
        metadata_response.json.return_value = {
            "issuer": "http://localhost:8001",
            "authorization_endpoint": "http://localhost:8001/oauth/authorize",
            "token_endpoint": "http://localhost:8001/oauth/token",
            "response_types_supported": ["code"],
            "registration_endpoint": "http://localhost:8001/oauth/register"
        }
        metadata_response.raise_for_status = MagicMock()

        registration_response = MagicMock()
        registration_response.json.return_value = {
            "client_id": "test_client_123",
            "client_secret": "test_secret_456"
        }
        registration_response.raise_for_status = MagicMock()

        token_response = MagicMock()
        token_response.json.return_value = {
            "access_token": "test_access_token_789",
            "token_type": "Bearer",
            "expires_in": 3600,
            "resource": "http://127.0.0.1:8000/mcp"
        }
        token_response.raise_for_status = MagicMock()

        with patch('httpx.AsyncClient') as mock_client, \
             patch('webbrowser.open'), \
             patch('builtins.input', return_value='test_auth_code'):

            mock_instance = mock_client.return_value.__aenter__.return_value
            mock_instance.get.side_effect = [discovery_response, metadata_response]
            mock_instance.post.side_effect = [registration_response, token_response]

            # Execute the full flow
            await client.connect_to_server("http://127.0.0.1:8000/mcp")

            # Verify final state
            assert client.server_url == "http://127.0.0.1:8000/mcp"
            assert client.access_token == "test_access_token_789"
            assert client.token_resource == "http://127.0.0.1:8000/mcp"
            assert client.client_id == "test_client_123"
            assert client.client_secret == "test_secret_456"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])