import copy
import http.server
import logging
import os
import socketserver
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path

import httpx
import requests
from fastmcp import FastMCP
from oauthlib.oauth1 import Client as OAuth1Client
from requests_oauthlib import OAuth1Session

HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
    "trace",
}

LOGGER = logging.getLogger("xmcp.x_api")
OAUTH_LOGGER = logging.getLogger("xmcp.oauth1")

REQUEST_TOKEN_URL = "https://api.x.com/oauth/request_token"
AUTHORIZE_URL = "https://api.x.com/oauth/authorize"
ACCESS_TOKEN_URL = "https://api.x.com/oauth/access_token"


def is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_csv_env(key: str) -> set[str]:
    raw = os.getenv(key, "")
    if not raw.strip():
        return set()
    return {item.strip() for item in raw.split(",") if item.strip()}


def should_join_query_param(param: dict) -> bool:
    if param.get("in") != "query":
        return False
    schema = param.get("schema", {})
    if schema.get("type") != "array":
        return False
    return param.get("explode") is False


def collect_comma_params(spec: dict) -> set[str]:
    comma_params: set[str] = set()
    components = spec.get("components", {}).get("parameters", {})
    for param in components.values():
        if isinstance(param, dict) and should_join_query_param(param):
            name = param.get("name")
            if isinstance(name, str):
                comma_params.add(name)

    for item in spec.get("paths", {}).values():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            for param in operation.get("parameters", []):
                if not isinstance(param, dict) or "$ref" in param:
                    continue
                if should_join_query_param(param):
                    name = param.get("name")
                    if isinstance(name, str):
                        comma_params.add(name)

    return comma_params


def load_openapi_spec() -> dict:
    url = "https://api.x.com/2/openapi.json"
    LOGGER.info("Fetching OpenAPI spec from %s", url)
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()


def _get_env_int(key: str, default: int) -> int:
    raw = os.getenv(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise RuntimeError(f"{key} must be an integer value.")


def _callback_url(host: str, port: int, path: str) -> str:
    return f"http://{host}:{port}{path}"


def _wait_for_callback(host: str, port: int, path: str, timeout_seconds: int) -> tuple[str, str]:
    params: dict[str, str | None] = {"oauth_token": None, "oauth_verifier": None}
    event = threading.Event()

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != path:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not found.")
                return
            query = urllib.parse.parse_qs(parsed.query)
            params["oauth_token"] = (query.get("oauth_token") or [None])[0]
            params["oauth_verifier"] = (query.get("oauth_verifier") or [None])[0]
            event.set()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OAuth complete. You may close this tab.")

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            OAUTH_LOGGER.debug("OAuth1 callback: " + format, *args)

    class _Server(socketserver.TCPServer):
        allow_reuse_address = True

    server = _Server((host, port), _Handler)
    server.timeout = 1

    deadline = time.time() + timeout_seconds
    try:
        while time.time() < deadline:
            server.handle_request()
            if event.is_set():
                break
    finally:
        server.server_close()

    oauth_token = params.get("oauth_token")
    oauth_verifier = params.get("oauth_verifier")
    if not oauth_token or not oauth_verifier:
        raise TimeoutError("OAuth callback not received before timeout.")
    return oauth_token, oauth_verifier


def run_oauth1_flow() -> tuple[str, str]:
    consumer_key = os.getenv("X_OAUTH_CONSUMER_KEY")
    consumer_secret = os.getenv("X_OAUTH_CONSUMER_SECRET")
    if not consumer_key or not consumer_secret:
        raise RuntimeError(
            "Missing X_OAUTH_CONSUMER_KEY or X_OAUTH_CONSUMER_SECRET for OAuth1 flow."
        )

    callback_host = os.getenv("X_OAUTH_CALLBACK_HOST", "127.0.0.1")
    callback_port = _get_env_int("X_OAUTH_CALLBACK_PORT", 8976)
    callback_path = os.getenv("X_OAUTH_CALLBACK_PATH", "/oauth/callback")
    callback_timeout = _get_env_int("X_OAUTH_CALLBACK_TIMEOUT", 300)

    callback_url = _callback_url(callback_host, callback_port, callback_path)

    oauth = OAuth1Session(
        client_key=consumer_key,
        client_secret=consumer_secret,
        callback_uri=callback_url,
    )
    request_token = oauth.fetch_request_token(REQUEST_TOKEN_URL)
    resource_owner_key = request_token.get("oauth_token")
    resource_owner_secret = request_token.get("oauth_token_secret")
    if not resource_owner_key or not resource_owner_secret:
        raise RuntimeError("Failed to obtain OAuth request token.")

    authorization_url = oauth.authorization_url(AUTHORIZE_URL)
    OAUTH_LOGGER.info("Opening browser for OAuth1 consent.")
    webbrowser.open(authorization_url)

    oauth_token, oauth_verifier = _wait_for_callback(
        callback_host, callback_port, callback_path, callback_timeout
    )
    if oauth_token != resource_owner_key:
        raise RuntimeError("OAuth callback token does not match request token.")

    oauth = OAuth1Session(
        client_key=consumer_key,
        client_secret=consumer_secret,
        resource_owner_key=resource_owner_key,
        resource_owner_secret=resource_owner_secret,
        verifier=oauth_verifier,
    )
    access_token = oauth.fetch_access_token(ACCESS_TOKEN_URL)
    access_key = access_token.get("oauth_token")
    access_secret = access_token.get("oauth_token_secret")
    if not access_key or not access_secret:
        raise RuntimeError("Failed to obtain OAuth access token.")
    return access_key, access_secret


def load_env() -> None:
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(env_path, override=True)


def setup_logging() -> bool:
    debug_enabled = is_truthy(os.getenv("X_API_DEBUG", "1"))
    if debug_enabled:
        logging.basicConfig(level=logging.INFO)
        LOGGER.setLevel(logging.INFO)
    return debug_enabled


def should_exclude_operation(path: str, operation: dict) -> bool:
    if "/webhooks" in path or "/stream" in path:
        return True

    tags = [tag.lower() for tag in operation.get("tags", []) if isinstance(tag, str)]
    if "stream" in tags or "webhooks" in tags:
        return True

    if operation.get("x-twitter-streaming") is True:
        return True

    return False


def filter_openapi_spec(spec: dict) -> dict:
    filtered = copy.deepcopy(spec)
    paths = filtered.get("paths", {})
    new_paths = {}
    allow_tags = {tag.lower() for tag in parse_csv_env("X_API_TOOL_TAGS")}
    allow_ops = parse_csv_env("X_API_TOOL_ALLOWLIST")
    deny_ops = parse_csv_env("X_API_TOOL_DENYLIST")

    for path, item in paths.items():
        if not isinstance(item, dict):
            continue

        new_item = {}
        for key, value in item.items():
            if key.lower() in HTTP_METHODS:
                if should_exclude_operation(path, value):
                    continue
                operation_id = value.get("operationId")
                operation_tags = [
                    tag.lower() for tag in value.get("tags", []) if isinstance(tag, str)
                ]
                if allow_tags and not (set(operation_tags) & allow_tags):
                    continue
                if allow_ops and operation_id not in allow_ops:
                    continue
                if deny_ops and operation_id in deny_ops:
                    continue
                new_item[key] = value
            else:
                new_item[key] = value

        if any(method.lower() in HTTP_METHODS for method in new_item.keys()):
            new_paths[path] = new_item

    filtered["paths"] = new_paths
    return filtered


def print_tool_list(spec: dict) -> None:
    tools: list[str] = []
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            op_id = operation.get("operationId")
            if op_id:
                tools.append(op_id)
            else:
                tools.append(f"{method.upper()} {path}")

    tools.sort()
    print(f"Loaded {len(tools)} tools from OpenAPI:")
    for tool in tools:
        print(f"- {tool}")


def get_auth_headers(oauth_token: str | None = None) -> dict:
    env_oauth_token = os.getenv("X_OAUTH_ACCESS_TOKEN", "").strip()
    bearer_token = os.getenv("X_BEARER_TOKEN", "").strip()
    token = oauth_token or env_oauth_token or bearer_token
    if not token:
        raise RuntimeError("Set X_BEARER_TOKEN or provide OAuth1 access token on startup.")
    return {"Authorization": f"Bearer {token}"}


def build_auth_client():
    """
    Build authentication headers preferring OAuth2 over OAuth1.
    Returns a dict of headers to use for API requests.
    Automatically refreshes OAuth2 access tokens using the refresh token.
    """
    # Try OAuth2 first (preferred for persistent auth without browser)
    client_id = os.getenv("CLIENT_ID", "").strip()
    client_secret = os.getenv("CLIENT_SECRET", "").strip()
    oauth2_token = os.getenv("X_OAUTH_ACCESS_TOKEN", "").strip()
    refresh_token = os.getenv("X_OAUTH_REFRESH_TOKEN", "").strip()

    # Diagnostic: Show which credentials are detected
    print("=" * 60)
    print("OAUTH2 CREDENTIALS DETECTION:")
    print(f"  CLIENT_ID present: {bool(client_id)}")
    print(f"  CLIENT_SECRET present: {bool(client_secret)}")
    print(f"  X_OAUTH_REFRESH_TOKEN present: {bool(refresh_token)}")
    print(f"  X_OAUTH_ACCESS_TOKEN present: {bool(oauth2_token)}")
    print("=" * 60)

    # If we have OAuth2 credentials and a refresh token, always try to refresh
    # This ensures we get a fresh token on every startup
    if client_id and client_secret and refresh_token:
        print(">>> ATTEMPTING OAUTH2 TOKEN REFRESH <<<")
        new_access_token = _refresh_oauth2_token(client_id, client_secret, refresh_token)
        if new_access_token:
            oauth2_token = new_access_token
            # Export to environment so Cline can capture it for future launches
            os.environ["X_OAUTH_ACCESS_TOKEN"] = new_access_token
            print("=" * 60)
            print("OAUTH2 TOKEN REFRESHED SUCCESSFULLY")
            print("=" * 60)
            print(f"New X_OAUTH_ACCESS_TOKEN: {new_access_token}")
            print("")
            print("To persist this token across VSCode restarts, add this to your")
            print("Cline MCP settings (cline_mcp_settings.json) under the xmcp env:")
            print(f'  "X_OAUTH_ACCESS_TOKEN": "{new_access_token}"')
            print("=" * 60)
            if is_truthy(os.getenv("X_OAUTH_PRINT_TOKENS", "0")):
                print("Using OAuth2 bearer token authentication")
            LOGGER.info("Using OAuth2 bearer token authentication")
            return {"Authorization": f"Bearer {oauth2_token}"}
        else:
            print(">>> OAUTH2 TOKEN REFRESH FAILED - FALLING BACK TO OAUTH1 <<<")

    # Fall back to OAuth1
    consumer_key = os.getenv("X_OAUTH_CONSUMER_KEY")
    consumer_secret = os.getenv("X_OAUTH_CONSUMER_SECRET")
    if not consumer_key or not consumer_secret:
        raise RuntimeError(
            "Missing X_OAUTH_CONSUMER_KEY or X_OAUTH_CONSUMER_SECRET for OAuth1 signing."
        )

    # Check for pre-existing OAuth1 tokens first (for stdio mode / Cline integration)
    env_access_token = os.getenv("X_OAUTH_ACCESS_TOKEN", "").strip()
    env_access_secret = os.getenv("X_OAUTH_ACCESS_TOKEN_SECRET", "").strip()

    if env_access_token and env_access_secret:
        if is_truthy(os.getenv("X_OAUTH_PRINT_TOKENS", "0")):
            print("Using pre-existing OAuth1 access token:", env_access_token)
        LOGGER.info("Using pre-existing OAuth1 access token: %s", env_access_token)
        return {
            "client_key": consumer_key,
            "client_secret": consumer_secret,
            "resource_owner_key": env_access_token,
            "resource_owner_secret": env_access_secret,
        }

    # Fall back to browser-based OAuth1 flow
    print(">>> TRIGGERING OAUTH1 BROWSER FLOW <<<")
    access_token, access_secret = run_oauth1_flow()
    if is_truthy(os.getenv("X_OAUTH_PRINT_TOKENS", "0")):
        print("OAuth1 access token:", access_token)
        print("OAuth1 access token secret:", access_secret)
    LOGGER.info("OAuth1 access token: %s", access_token)
    return {
        "client_key": consumer_key,
        "client_secret": consumer_secret,
        "resource_owner_key": access_token,
        "resource_owner_secret": access_secret,
    }


def _refresh_oauth2_token(client_id: str, client_secret: str, refresh_token: str) -> str | None:
    """
    Refresh an OAuth2 access token using the refresh token.
    Returns the new access token, or None if refresh failed.
    """
    import base64

    token_url = "https://api.x.com/2/oauth2/token"

    print(f">>> OAUTH2 REFRESH: POST to {token_url}")

    # Create Basic auth header with client credentials
    credentials = f"{client_id}:{client_secret}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()

    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }

    try:
        print(">>> Sending refresh request...")
        response = requests.post(token_url, headers=headers, data=data, timeout=30)
        print(f">>> Response status: {response.status_code}")
        print(f">>> Response body: {response.text[:500]}")  # Print first 500 chars

        response.raise_for_status()
        token_data = response.json()

        new_access_token = token_data.get("access_token")
        new_refresh_token = token_data.get("refresh_token")

        if new_access_token:
            print(">>> Successfully refreshed OAuth2 access token")
            if new_refresh_token:
                print(">>> Received new refresh token (rotation)")
            return new_access_token
        else:
            print(">>> Token refresh response did not contain access_token")
            print(f">>> Full response: {token_data}")
            return None

    except requests.exceptions.RequestException as e:
        print(f">>> Failed to refresh OAuth2 token: {e}")
        LOGGER.error("OAuth2 token refresh failed: %s", e)
        return None
    except Exception as e:
        print(f">>> Unexpected error during refresh: {type(e).__name__}: {e}")
        LOGGER.error("Unexpected error during OAuth2 refresh: %s", e)
        return None


def print_oauth1_header_probe(oauth1_client: OAuth1Client, base_url: str) -> None:
    probe_url = f"{base_url}/2/users/me"
    _, signed_headers, _ = oauth1_client.sign(
        probe_url,
        http_method="GET",
        headers={},
    )
    auth_header = signed_headers.get("Authorization")
    if auth_header:
        print("OAuth1 Authorization header (sample GET /2/users/me):", auth_header)
    else:
        print("OAuth1 Authorization header missing from signed probe request.")


def create_mcp() -> FastMCP:
    load_env()
    debug_enabled = setup_logging()
    parser_flag = os.getenv("FASTMCP_EXPERIMENTAL_ENABLE_NEW_OPENAPI_PARSER")
    if parser_flag is not None:
        os.environ["FASTMCP_EXPERIMENTAL_ENABLE_NEW_OPENAPI_PARSER"] = parser_flag

    base_url = os.getenv("X_API_BASE_URL", "https://api.x.com")
    timeout = float(os.getenv("X_API_TIMEOUT", "30"))

    auth_config = build_auth_client()
    print_oauth_header = is_truthy(os.getenv("X_OAUTH_PRINT_AUTH_HEADER", "0"))

    # Determine if we're using OAuth2 or OAuth1
    is_oauth2 = isinstance(auth_config, dict) and "Authorization" in auth_config and auth_config.get("Authorization", "").startswith("Bearer ")

    if is_oauth2:
        # OAuth2: use bearer token directly
        oauth2_token = auth_config["Authorization"].replace("Bearer ", "")
        client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {oauth2_token}"},
            timeout=timeout,
            event_hooks={
                "request": [normalize_query_params, log_request],
                "response": [log_response],
            },
        )
        return FastMCP.from_openapi(
            openapi_spec=filtered_spec,
            client=client,
            name="X API MCP",
        )
    else:
        # OAuth1: build OAuth1Client from the returned config
        oauth1_client = OAuth1Client(
            client_key=auth_config["client_key"],
            client_secret=auth_config["client_secret"],
            resource_owner_key=auth_config["resource_owner_key"],
            resource_owner_secret=auth_config["resource_owner_secret"],
            signature_type="AUTH_HEADER",
        )
        if print_oauth_header:
            print_oauth1_header_probe(oauth1_client, base_url)

    spec = load_openapi_spec()
    filtered_spec = filter_openapi_spec(spec)
    comma_params = collect_comma_params(filtered_spec)
    print_tool_list(filtered_spec)

    async def normalize_query_params(request: httpx.Request) -> None:
        if not comma_params:
            return
        params = list(request.url.params.multi_items())
        grouped: dict[str, list[str]] = {}
        ordered: list[str] = []
        normalized: list[tuple[str, str]] = []

        for key, value in params:
            if key in comma_params:
                if key not in grouped:
                    ordered.append(key)
                grouped.setdefault(key, []).append(value)
            else:
                normalized.append((key, value))

        if not grouped:
            return

        for key in ordered:
            values: list[str] = []
            for raw in grouped[key]:
                for part in raw.split(","):
                    part = part.strip()
                    if part and part not in values:
                        values.append(part)
            if values:
                normalized.append((key, ",".join(values)))

        request.url = request.url.copy_with(params=normalized)

    b3_flags = os.getenv("X_B3_FLAGS", "1")

    async def sign_oauth1_request(request: httpx.Request) -> None:
        request.headers["X-B3-Flags"] = b3_flags
        headers = dict(request.headers)
        content_type = headers.get("Content-Type", "")
        body: str | None = None
        if content_type.startswith("application/x-www-form-urlencoded"):
            body_bytes = request.content or b""
            body = body_bytes.decode("utf-8")
        signed_url, signed_headers, _ = oauth1_client.sign(
            str(request.url),
            http_method=request.method,
            body=body,
            headers=headers,
        )
        request.url = httpx.URL(signed_url)
        request.headers.update(signed_headers)
        if print_oauth_header:
            auth_header = signed_headers.get("Authorization")
            if auth_header:
                print("OAuth1 Authorization header:", auth_header)
            else:
                print("OAuth1 Authorization header missing from signed request.")

    async def log_request(request: httpx.Request) -> None:
        if not debug_enabled:
            return
        LOGGER.info("X API request %s %s", request.method, request.url)

    async def log_response(response: httpx.Response) -> None:
        if not debug_enabled:
            return
        LOGGER.info(
            "X API response %s %s -> %s",
            response.request.method,
            response.request.url,
            response.status_code,
        )
        if response.status_code >= 400:
            transaction_id = response.headers.get("x-transaction-id")
            if transaction_id:
                LOGGER.warning("X API x-transaction-id: %s", transaction_id)
            body = await response.aread()
            text = body.decode("utf-8", errors="replace")
            if len(text) > 1000:
                text = text[:1000] + "...<truncated>"
            LOGGER.warning("X API error body: %s", text)

    client = httpx.AsyncClient(
        base_url=base_url,
        headers={},
        timeout=timeout,
        event_hooks={
            "request": [normalize_query_params, sign_oauth1_request, log_request],
            "response": [log_response],
        },
    )
    return FastMCP.from_openapi(
        openapi_spec=filtered_spec,
        client=client,
        name="X API MCP",
    )




def main() -> None:
    host = os.getenv("MCP_HOST", "127.0.0.1")
    port = int(os.getenv("MCP_PORT", "8000"))
    transport = os.getenv("MCP_TRANSPORT", "http")
    mcp = create_mcp()
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="http", host=host, port=port)


if __name__ == "__main__":
    main()
