import asyncio
import secrets
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
import json
import base64
import hashlib

from fastapi import FastAPI, HTTPException, Request, Form, Depends
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
from pydantic import BaseModel

# OAuth 2.1 Server with Dynamic Client Registration for MCP
app = FastAPI(title="MCP OAuth 2.1 Authorization Server")

# In-memory storage (use proper database in production)
clients: Dict[str, Dict] = {}
authorization_codes: Dict[str, Dict] = {}
access_tokens: Dict[str, Dict] = {}
refresh_tokens: Dict[str, Dict] = {}

# Server configuration
ISSUER = "http://localhost:8001"
AUTHORIZATION_ENDPOINT = f"{ISSUER}/oauth/authorize"
TOKEN_ENDPOINT = f"{ISSUER}/oauth/token"
REGISTRATION_ENDPOINT = f"{ISSUER}/oauth/register"
JWKS_URI = f"{ISSUER}/.well-known/jwks.json"

security = HTTPBearer()


class DynamicClientRegistrationRequest(BaseModel):
    client_name: str
    redirect_uris: List[str]
    grant_types: Optional[List[str]] = ["authorization_code"]
    response_types: Optional[List[str]] = ["code"]
    scope: Optional[str] = ""
    token_endpoint_auth_method: Optional[str] = "client_secret_basic"


class TokenRequest(BaseModel):
    grant_type: str
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    code_verifier: Optional[str] = None
    resource: Optional[str] = None


def generate_client_credentials():
    """Generate client ID and secret"""
    client_id = f"mcp_client_{secrets.token_urlsafe(16)}"
    client_secret = secrets.token_urlsafe(32)
    return client_id, client_secret


def generate_authorization_code():
    """Generate authorization code"""
    return secrets.token_urlsafe(32)


def generate_access_token():
    """Generate access token"""
    return secrets.token_urlsafe(64)


def generate_refresh_token():
    """Generate refresh token"""
    return secrets.token_urlsafe(64)


def create_code_challenge_verifier():
    """Create PKCE code verifier and challenge"""
    code_verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    )
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("utf-8")).digest())
        .decode("utf-8")
        .rstrip("=")
    )
    return code_verifier, code_challenge


def verify_code_challenge(code_verifier: str, code_challenge: str) -> bool:
    """Verify PKCE code challenge"""
    expected_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("utf-8")).digest())
        .decode("utf-8")
        .rstrip("=")
    )
    return expected_challenge == code_challenge


@app.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():
    """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
    return JSONResponse(
        {
            "issuer": ISSUER,
            "authorization_endpoint": AUTHORIZATION_ENDPOINT,
            "token_endpoint": TOKEN_ENDPOINT,
            "registration_endpoint": REGISTRATION_ENDPOINT,
            "jwks_uri": JWKS_URI,
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "scopes_supported": ["read", "write", "admin"],
            "resource_parameter_supported": True,
        }
    )


@app.post("/oauth/register")
async def dynamic_client_registration(request: DynamicClientRegistrationRequest):
    """OAuth 2.0 Dynamic Client Registration (RFC 7591)"""
    client_id, client_secret = generate_client_credentials()

    client_data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": request.client_name,
        "redirect_uris": request.redirect_uris,
        "grant_types": request.grant_types,
        "response_types": request.response_types,
        "scope": request.scope,
        "token_endpoint_auth_method": request.token_endpoint_auth_method,
        "client_id_issued_at": int(time.time()),
        "client_secret_expires_at": 0,  # Never expires in this demo
    }

    clients[client_id] = client_data

    return JSONResponse(client_data)


@app.get("/oauth/authorize")
async def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: Optional[str] = "",
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    resource: Optional[str] = None,
):
    """OAuth 2.1 Authorization Endpoint"""

    # Validate client
    if client_id not in clients:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    client = clients[client_id]

    # Validate redirect URI
    if redirect_uri not in client["redirect_uris"]:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    # Validate response type
    if response_type != "code":
        error_params = {
            "error": "unsupported_response_type",
            "error_description": "Only 'code' response type is supported",
        }
        if state:
            error_params["state"] = state
        return RedirectResponse(
            f"{redirect_uri}?" + urllib.parse.urlencode(error_params)
        )

    # For demo purposes, auto-approve the authorization
    # In production, you'd show a consent screen

    code = generate_authorization_code()

    authorization_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "resource": resource,
        "expires_at": time.time() + 600,  # 10 minutes
        "used": False,
    }

    # Build response parameters
    response_params = {"code": code}
    if state:
        response_params["state"] = state

    return RedirectResponse(
        f"{redirect_uri}?" + urllib.parse.urlencode(response_params)
    )


@app.post("/oauth/token")
async def token_endpoint(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    resource: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
):
    """OAuth 2.1 Token Endpoint"""

    if grant_type == "authorization_code":
        return await handle_authorization_code_grant(
            code, redirect_uri, client_id, client_secret, code_verifier, resource
        )
    elif grant_type == "refresh_token":
        return await handle_refresh_token_grant(refresh_token, client_id, client_secret)
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant type")


async def handle_authorization_code_grant(
    code: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str,
    code_verifier: Optional[str],
    resource: Optional[str],
):
    """Handle authorization code grant"""

    if not code or code not in authorization_codes:
        raise HTTPException(
            status_code=400, detail="Invalid or missing authorization code"
        )

    auth_code_data = authorization_codes[code]

    # Check if code is expired or already used
    if auth_code_data["used"] or time.time() > auth_code_data["expires_at"]:
        raise HTTPException(
            status_code=400, detail="Authorization code expired or already used"
        )

    # Validate client
    if client_id != auth_code_data["client_id"]:
        raise HTTPException(status_code=400, detail="Client ID mismatch")

    if client_id not in clients:
        raise HTTPException(status_code=400, detail="Invalid client")

    client = clients[client_id]

    # Validate client secret for confidential clients
    if client["token_endpoint_auth_method"] == "client_secret_basic":
        if not client_secret or client_secret != client["client_secret"]:
            raise HTTPException(status_code=401, detail="Invalid client credentials")

    # Validate redirect URI
    if redirect_uri != auth_code_data["redirect_uri"]:
        raise HTTPException(status_code=400, detail="Redirect URI mismatch")

    # Validate PKCE if used
    if auth_code_data["code_challenge"]:
        if not code_verifier:
            raise HTTPException(status_code=400, detail="Code verifier required")

        if not verify_code_challenge(code_verifier, auth_code_data["code_challenge"]):
            raise HTTPException(status_code=400, detail="Invalid code verifier")

    # Mark code as used
    auth_code_data["used"] = True

    # Generate tokens
    access_token = generate_access_token()
    refresh_token_val = generate_refresh_token()

    # Store access token
    access_tokens[access_token] = {
        "client_id": client_id,
        "scope": auth_code_data["scope"],
        "resource": auth_code_data.get("resource", resource),
        "expires_at": time.time() + 3600,  # 1 hour
        "token_type": "Bearer",
    }

    # Store refresh token
    refresh_tokens[refresh_token_val] = {
        "client_id": client_id,
        "scope": auth_code_data["scope"],
        "resource": auth_code_data.get("resource", resource),
        "expires_at": time.time() + 86400,  # 24 hours
    }

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token_val,
            "scope": auth_code_data["scope"],
            **(
                {"resource": auth_code_data.get("resource", resource)}
                if auth_code_data.get("resource", resource)
                else {}
            ),
        }
    )


async def handle_refresh_token_grant(
    refresh_token: str, client_id: str, client_secret: str
):
    """Handle refresh token grant"""

    if not refresh_token or refresh_token not in refresh_tokens:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    refresh_data = refresh_tokens[refresh_token]

    # Check if refresh token is expired
    if time.time() > refresh_data["expires_at"]:
        raise HTTPException(status_code=400, detail="Refresh token expired")

    # Validate client
    if client_id != refresh_data["client_id"]:
        raise HTTPException(status_code=400, detail="Client ID mismatch")

    if client_id not in clients:
        raise HTTPException(status_code=400, detail="Invalid client")

    client = clients[client_id]

    # Validate client secret
    if client["token_endpoint_auth_method"] == "client_secret_basic":
        if not client_secret or client_secret != client["client_secret"]:
            raise HTTPException(status_code=401, detail="Invalid client credentials")

    # Generate new access token
    access_token = generate_access_token()

    # Store new access token
    access_tokens[access_token] = {
        "client_id": client_id,
        "scope": refresh_data["scope"],
        "resource": refresh_data.get("resource"),
        "expires_at": time.time() + 3600,  # 1 hour
        "token_type": "Bearer",
    }

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": refresh_data["scope"],
            **(
                {"resource": refresh_data.get("resource")}
                if refresh_data.get("resource")
                else {}
            ),
        }
    )


@app.get("/oauth/validate")
async def validate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Token validation endpoint for resource servers"""
    token = credentials.credentials

    if token not in access_tokens:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    token_data = access_tokens[token]

    # Check if token is expired
    if time.time() > token_data["expires_at"]:
        raise HTTPException(status_code=401, detail="Token expired")

    return JSONResponse(
        {
            "active": True,
            "client_id": token_data["client_id"],
            "scope": token_data["scope"],
            "resource": token_data.get("resource"),
            "exp": int(token_data["expires_at"]),
        }
    )


@app.get("/.well-known/jwks.json")
async def jwks():
    """JSON Web Key Set endpoint (minimal implementation)"""
    return JSONResponse({"keys": []})  # In production, include actual public keys


@app.get("/")
async def root():
    """Root endpoint with server information"""
    return HTMLResponse(
        f"""
    <html>
        <body>
            <h1>MCP OAuth 2.1 Authorization Server</h1>
            <p>Issuer: {ISSUER}</p>
            <h2>Endpoints:</h2>
            <ul>
                <li><a href="/.well-known/oauth-authorization-server">Authorization Server Metadata</a></li>
                <li>Authorization: {AUTHORIZATION_ENDPOINT}</li>
                <li>Token: {TOKEN_ENDPOINT}</li>
                <li>Registration: {REGISTRATION_ENDPOINT}</li>
                <li><a href="/.well-known/jwks.json">JWKS</a></li>
            </ul>
            <h2>Features:</h2>
            <ul>
                <li>OAuth 2.1 compliant</li>
                <li>Dynamic Client Registration (RFC 7591)</li>
                <li>PKCE support (RFC 7636)</li>
                <li>Resource Indicators support</li>
                <li>Authorization Server Metadata (RFC 8414)</li>
            </ul>
        </body>
    </html>
    """
    )


if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8001)  # Use port 8001
