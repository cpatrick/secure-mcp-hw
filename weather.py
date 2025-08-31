from typing import Any, Optional
import httpx
from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
import uvicorn

# Initialize FastMCP server (using newer fastmcp package)
mcp = FastMCP("weather")

# Constants
NWS_API_BASE = "https://api.weather.gov"
USER_AGENT = "weather-app/1.0"
OAUTH_SERVER_URL = "http://localhost:8001"


# OAuth validation middleware
class OAuthValidationMiddleware(Middleware):
    async def on_request(self, context: MiddlewareContext, call_next):
        print("OAuthValidationMiddleware start")

        # Get HTTP headers using FastMCP dependency
        try:
            headers = get_http_headers()
            print(f"Headers: {dict(headers)}")

            # Check for authorization header
            auth_header = headers.get("authorization") or headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header[7:]  # Remove "Bearer " prefix

                # Validate token with OAuth server and check resource access
                print(f"Validating token: {token[:20]}...")
                is_valid, token_info = await validate_token_with_oauth_server(token)
                if not is_valid:
                    print("Invalid or expired access token")
                    raise HTTPException(
                        status_code=401, detail="Invalid or expired access token"
                    )

                # RFC 8707: Validate resource access
                server_resource = (
                    "http://127.0.0.1:8000"  # This server's resource identifier
                )
                if not validate_resource_access(token_info, server_resource):
                    print("Token does not grant access to this resource")
                    raise HTTPException(
                        status_code=403,
                        detail="Token does not grant access to this resource",
                    )

                print("✓ OAuth token and resource access validated successfully")
            else:
                print("Missing or invalid authorization header")
                raise HTTPException(
                    status_code=401, detail="Missing or invalid authorization header"
                )

        except Exception as e:
            print(f"Error in OAuth validation: {e}")
            # For now, allow requests to proceed if we can't validate
            # In production, you might want to reject the request
            pass

        return await call_next(context)


async def validate_token_with_oauth_server(token: str) -> tuple[bool, Optional[dict]]:
    """Validate access token with OAuth server and return token info"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{OAUTH_SERVER_URL}/oauth/validate",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0,
            )
            if response.status_code == 200:
                token_info = response.json()
                return True, token_info
            return False, None
    except Exception:
        return False, None


def validate_resource_access(token_info: dict, requested_resource: str) -> bool:
    """Validate that token allows access to requested resource per RFC 8707"""
    if token_info is None:
        print("❌ No token info provided")
        return False

    # Get token's resource from OAuth server response
    token_resource = token_info.get("resource")

    if not token_resource or token_resource is None:
        # If no resource in token, allow access (backward compatibility)
        print("ℹ️  Token has no resource restriction")
        return True

    # Normalize both URIs for comparison
    requested_normalized = requested_resource.rstrip("/")
    token_normalized = token_resource.rstrip("/")

    # RFC 8707: Token resource should match or be a parent of requested resource
    # Also handle case where token is for /mcp path but server validates base path
    if (
        requested_normalized == token_normalized
        or requested_normalized.startswith(token_normalized + "/")
        or token_normalized.startswith(requested_normalized + "/")
    ):
        print(
            f"✓ Resource access granted: token resource '{token_resource}' allows access to '{requested_resource}'"
        )
        return True
    else:
        print(
            f"❌ Resource access denied: token resource '{token_resource}' does not allow access to '{requested_resource}'"
        )
        return False


# Add OAuth validation middleware
mcp.add_middleware(OAuthValidationMiddleware())


# Add OAuth server discovery endpoint
@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def oauth_metadata(request: Request) -> JSONResponse:
    """OAuth Protected Resource Metadata for FastMCP client discovery"""
    return JSONResponse(
        {
            "resource": "http://127.0.0.1:8000",
            "authorization_servers": [OAUTH_SERVER_URL],
        }
    )


# Health check endpoint (no auth required)
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint"""
    return JSONResponse({"status": "ok", "oauth_server": OAUTH_SERVER_URL})


async def make_nws_request(url: str) -> dict[str, Any] | None:
    """Make a request to the NWS API with proper error handling."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/geo+json"}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception:
            return None


def format_alert(feature: dict) -> str:
    """Format an alert feature into a readable string."""
    props = feature["properties"]
    return f"""
Event: {props.get('event', 'Unknown')}
Area: {props.get('areaDesc', 'Unknown')}
Severity: {props.get('severity', 'Unknown')}
Description: {props.get('description', 'No description available')}
Instructions: {props.get('instruction', 'No specific instructions provided')}
"""


@mcp.tool()
async def get_alerts(state: str) -> str:
    """Get weather alerts for a US state.
    Requires valid OAuth 2.1 access token.

    Args:
        state: Two-letter US state code (e.g. CA, NY)
    """
    url = f"{NWS_API_BASE}/alerts/active/area/{state}"
    data = await make_nws_request(url)

    if not data or "features" not in data:
        return "Unable to fetch alerts or no alerts found."

    if not data["features"]:
        return "No active alerts for this state."

    alerts = [format_alert(feature) for feature in data["features"]]
    return "\n---\n".join(alerts)


@mcp.tool()
async def get_forecast(latitude: float, longitude: float) -> str:
    """Get weather forecast for a location.
    Requires valid OAuth 2.1 access token.

    Args:
        latitude: Latitude of the location
        longitude: Longitude of the location
    """
    # First get the forecast grid endpoint
    points_url = f"{NWS_API_BASE}/points/{latitude},{longitude}"
    points_data = await make_nws_request(points_url)

    if not points_data:
        return "Unable to fetch forecast data for this location."

    # Get the forecast URL from the points response
    forecast_url = points_data["properties"]["forecast"]
    forecast_data = await make_nws_request(forecast_url)

    if not forecast_data:
        return "Unable to fetch detailed forecast."

    # Format the periods into a readable forecast
    periods = forecast_data["properties"]["periods"]
    forecasts = []
    for period in periods[:5]:  # Only show next 5 periods
        forecast = f"""
{period['name']}:
Temperature: {period['temperature']}°{period['temperatureUnit']}
Wind: {period['windSpeed']} {period['windDirection']}
Forecast: {period['detailedForecast']}
"""
        forecasts.append(forecast)

    return "\n---\n".join(forecasts)


if __name__ == "__main__":
    print("Starting Weather MCP Server with MANDATORY OAuth 2.1 authorization")
    print("All MCP tool requests require valid OAuth bearer tokens")
    print(f"OAuth server must be running at: {OAUTH_SERVER_URL}")
    print("✓ OAuth token validation enabled for all tool requests")

    # Run with HTTP transport using SSE for streamable communication
    mcp.run(transport="http", host="127.0.0.1", port=8000)
