import base64
import copy
import hashlib
import http.server
import logging
import os
import socketserver
import sys
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
AUTHORIZE_URL = "https://api.x.com/oauth/authorize"          # OAuth1
ACCESS_TOKEN_URL = "https://api.x.com/oauth/access_token"

# OAuth2 (Authorization Code + PKCE for user context)
OAUTH2_AUTHORIZE_URL = "https://x.com/i/oauth2/authorize"
OAUTH2_TOKEN_URL = "https://api.x.com/2/oauth2/token"
OAUTH2_SCOPE = "tweet.read tweet.write users.read bookmark.read offline.access"


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


def generate_pkce_pair() -> tuple[str, str]:
    """
    Generate a PKCE code verifier and code challenge (S256).
    Returns (code_verifier, code_challenge).
    """
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def run_oauth2_pkce_flow() -> tuple[str, str | None]:
    """
    Perform the full interactive X API v2 OAuth2 Authorization Code + PKCE flow.

    Opens a browser for the user to authorize, starts a local callback server,
    exchanges the code for an access_token + refresh_token (with offline.access),
    and returns them.

    Uses OAUTH2_CALLBACK_* env vars for the redirect URI (must be registered
    in your X Developer App).
    """
    client_id = os.getenv("CLIENT_ID", "").strip()
    client_secret = os.getenv("CLIENT_SECRET", "").strip()

    if not client_id or not client_secret:
        raise RuntimeError("CLIENT_ID and CLIENT_SECRET are required for the OAuth2 PKCE flow.")

    callback_host = os.getenv("OAUTH2_CALLBACK_HOST", "127.0.0.1")
    callback_port = _get_env_int("OAUTH2_CALLBACK_PORT", 9876)
    callback_path = os.getenv("OAUTH2_CALLBACK_PATH", "/oauth/callback")
    callback_timeout = _get_env_int("X_OAUTH_CALLBACK_TIMEOUT", 300)  # reuse existing timeout var or default 5 min

    callback_url = _callback_url(callback_host, callback_port, callback_path)

    LOGGER.info("=" * 70)
    LOGGER.info("OAUTH2 PKCE AUTHORIZATION FLOW (interactive)")
    LOGGER.info("=" * 70)
    LOGGER.info("Callback URL: %s", callback_url)
    LOGGER.info("IMPORTANT: This URL must be registered exactly in your X Developer App")
    LOGGER.info("under User authentication settings > Redirect URI.")
    LOGGER.info("")

    # PKCE + state
    code_verifier, code_challenge = generate_pkce_pair()
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("ascii")

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": callback_url,
        "scope": OAUTH2_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{OAUTH2_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

    LOGGER.info("Opening browser for X authorization consent...")
    LOGGER.info("Opening OAuth2 authorization URL: %s", auth_url)
    webbrowser.open(auth_url)

    # --- Local callback server (similar pattern to OAuth1 flow) ---
    captured: dict[str, str | None] = {"code": None, "state": None, "error": None}
    event = threading.Event()

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != callback_path:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not found.")
                return
            query = urllib.parse.parse_qs(parsed.query)
            captured["code"] = (query.get("code") or [None])[0]
            captured["state"] = (query.get("state") or [None])[0]
            captured["error"] = (query.get("error") or [None])[0]
            event.set()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                b"Authorization received. You may close this tab and return to the terminal."
            )

        def log_message(self, format: str, *args: object) -> None:
            LOGGER.debug("OAuth2 callback: " + format, *args)

    class _Server(socketserver.TCPServer):
        allow_reuse_address = True

    server = _Server((callback_host, callback_port), _Handler)
    server.timeout = 1
    deadline = time.time() + callback_timeout

    LOGGER.info("Waiting for authorization callback... (timeout: %ss)", callback_timeout)
    try:
        while time.time() < deadline:
            server.handle_request()
            if event.is_set():
                break
    finally:
        server.server_close()

    if captured["error"]:
        raise RuntimeError(f"Authorization denied by user: {captured['error']}")

    auth_code = captured.get("code")
    if not auth_code:
        raise TimeoutError("No authorization code received (timed out or cancelled).")

    if captured.get("state") != state:
        raise RuntimeError("State mismatch — possible CSRF or callback tampering.")

    LOGGER.info(">>> Authorization code received. Exchanging for tokens...")

    # Token exchange — confidential client (Basic auth + code_verifier)
    credentials = f"{client_id}:{client_secret}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()

    token_headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": callback_url,
        "code_verifier": code_verifier,
    }

    response = requests.post(
        OAUTH2_TOKEN_URL,
        headers=token_headers,
        data=token_data,
        timeout=30,
    )
    LOGGER.info(">>> Token endpoint response: %s", response.status_code)

    if not response.ok:
        # Reuse the nice error formatting we added earlier
        try:
            err_json = response.json()
            err_type = err_json.get("error", "unknown_error")
            err_desc = err_json.get("error_description", response.text[:300])
            LOGGER.error(">>> X OAuth2 error: %s", err_type)
            if err_desc:
                LOGGER.error(">>>   Description: %s", err_desc)
        except Exception:
            LOGGER.error(">>> Response body: %s", response.text[:1000])
        response.raise_for_status()

    token_json = response.json()
    access_token = token_json.get("access_token")
    refresh_token = token_json.get("refresh_token")

    if not access_token:
        raise RuntimeError(f"No access_token in response: {token_json}")

    LOGGER.info("")
    LOGGER.info("=" * 60)
    LOGGER.info("OAUTH2 TOKENS RECEIVED SUCCESSFULLY")
    LOGGER.info("  access_token:  %s...", access_token[:30])
    if refresh_token:
        LOGGER.info("  refresh_token: %s...", refresh_token[:30])
    LOGGER.info("  (These have been persisted to .env for future startups)")
    LOGGER.info("=" * 60)

    return access_token, refresh_token


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
    """
    Configure logging to both stderr and server.log.

    - server.log is always cleared on server startup (fresh logs per run).
    - All output goes to stderr (correct for stdio MCP) + the log file.
    - The log file is gitignored.
    """
    debug_enabled = is_truthy(os.getenv("X_API_DEBUG", "1"))
    level = logging.DEBUG if debug_enabled else logging.INFO

    log_path = Path(__file__).resolve().parent / "server.log"

    # Clear the log file on every server start
    try:
        log_path.write_text("", encoding="utf-8")
    except Exception:
        # Non-fatal if we can't write the log file
        pass

    handlers = []

    # stderr handler (visible when running manually + captured by some hosts)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    stderr_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))
    handlers.append(stderr_handler)

    # File handler - always append after we cleared the file above
    try:
        file_handler = logging.FileHandler(str(log_path), mode="a", encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))
        handlers.append(file_handler)
    except Exception as e:
        # If file logging fails, we still have stderr
        print(f"[xmcp] Warning: Could not open server.log for writing: {e}", file=sys.stderr)

    # Apply configuration (force=True to override any previous config)
    logging.basicConfig(
        level=level,
        handlers=handlers,
        force=True,
    )

    # Ensure our loggers respect the level
    LOGGER.setLevel(level)
    OAUTH_LOGGER.setLevel(level)
    logging.getLogger("xmcp.oauth2").setLevel(level)

    LOGGER.info("Logging initialized → %s (cleared on every startup) + stderr", log_path)
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
    LOGGER.info("Loaded %s tools from OpenAPI:", len(tools))
    for tool in tools:
        LOGGER.info("- %s", tool)


def get_auth_headers(oauth_token: str | None = None) -> dict:
    env_oauth_token = os.getenv("X_OAUTH_ACCESS_TOKEN", "").strip()
    bearer_token = os.getenv("X_BEARER_TOKEN", "").strip()
    token = oauth_token or env_oauth_token or bearer_token
    if not token:
        raise RuntimeError("Set X_BEARER_TOKEN or provide OAuth1 access token on startup.")
    return {"Authorization": f"Bearer {token}"}


def _validate_oauth2_token(access_token: str) -> bool:
    """
    Probe the X API to check whether the current OAuth2 access token is valid.
    Returns True if the token works, False otherwise.
    """
    probe_url = "https://api.x.com/2/users/me"
    headers = {"Authorization": f"Bearer {access_token}"}
    LOGGER.info(">>> Validating existing OAuth2 access token...")
    try:
        response = requests.get(probe_url, headers=headers, timeout=10)
        if response.status_code == 200:
            LOGGER.info(">>> Existing OAuth2 token is valid.")
            return True
        else:
            LOGGER.info(">>> OAuth2 token probe returned %s — token is expired or invalid.", response.status_code)
            return False
    except requests.exceptions.RequestException as e:
        LOGGER.warning(">>> OAuth2 token validation probe failed: %s", e)
        return False


def _refresh_oauth2_token(client_id: str, client_secret: str, refresh_token: str) -> tuple[str, str] | None:
    """
    Refresh an OAuth2 access token using the refresh token.
    Returns a tuple of (new_access_token, new_refresh_token), or None if refresh failed.
    """
    import base64

    token_url = "https://api.x.com/2/oauth2/token"

    LOGGER.info(">>> OAUTH2 REFRESH: POST to %s", token_url)

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
        LOGGER.info(">>> Sending refresh request...")
        response = requests.post(token_url, headers=headers, data=data, timeout=30)
        LOGGER.info(">>> Response status: %s", response.status_code)

        if response.status_code >= 400:
            # X returns structured errors — surface them clearly instead of raw body (avoids noise + helps user)
            try:
                err_json = response.json()
                err_type = err_json.get("error", "unknown_error")
                err_desc = err_json.get("error_description", "")
                LOGGER.error(">>> X OAuth2 error: %s", err_type)
                if err_desc:
                    LOGGER.error(">>>   Description: %s", err_desc)
                # Common actionable cases
                if err_type in ("invalid_grant", "invalid_request"):
                    LOGGER.info(">>>   → This usually means your refresh_token is invalid, expired, or revoked.")
                    LOGGER.info(">>>   → Since CLIENT_ID + CLIENT_SECRET are configured, the server will now")
                    LOGGER.info(">>>      automatically start the interactive OAuth2 PKCE flow to get fresh tokens.")
            except Exception:
                LOGGER.error(">>> Response body: %s", response.text[:500])
        else:
            LOGGER.info(">>> Response body: (success; tokens redacted for security)")

        response.raise_for_status()
        token_data = response.json()

        new_access_token = token_data.get("access_token")
        new_refresh_token = token_data.get("refresh_token")

        if new_access_token:
            LOGGER.info(">>> Successfully refreshed OAuth2 access token")
            if new_refresh_token:
                LOGGER.info(">>> Received new refresh token (rotation)")
            return new_access_token, new_refresh_token
        else:
            LOGGER.info(">>> Token refresh response did not contain access_token")
            LOGGER.info(">>> Full response: %s", token_data)
            return None

    except requests.exceptions.RequestException as e:
        # This is recoverable when CLIENT_ID + CLIENT_SECRET are present (we will launch
        # the interactive PKCE flow next). Use warning level.
        LOGGER.warning("OAuth2 token refresh failed (will attempt interactive re-auth if client credentials are configured): %s", e)
        return None
    except Exception as e:
        LOGGER.error("Unexpected error during OAuth2 refresh: %s", e)
        return None


def _persist_tokens_to_env(access_token: str, refresh_token: str | None) -> None:
    """
    Write the OAuth2 tokens into the .env file so they survive server restarts.
    Uses python-dotenv's set_key to update the file in-place.
    """
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        LOGGER.info(">>> .env file not found at %s, creating one.", env_path)
        env_path.write_text("")

    try:
        from dotenv import set_key
    except ImportError:
        LOGGER.warning(">>> dotenv.set_key not available; cannot persist tokens automatically.")
        LOGGER.warning(">>> Set X_OAUTH_ACCESS_TOKEN=%s manually in your .env", access_token)
        return

    LOGGER.info(">>> Persisting OAuth2 tokens to .env ...")
    set_key(str(env_path), "X_OAUTH_ACCESS_TOKEN", access_token)
    if refresh_token:
        set_key(str(env_path), "X_OAUTH_REFRESH_TOKEN", refresh_token)
        LOGGER.info(">>> Persisted new X_OAUTH_ACCESS_TOKEN and X_OAUTH_REFRESH_TOKEN to .env")
    else:
        LOGGER.info(">>> Persisted new X_OAUTH_ACCESS_TOKEN to .env (no refresh token rotation)")


def print_oauth1_header_probe(oauth1_client: OAuth1Client, base_url: str) -> None:
    probe_url = f"{base_url}/2/users/me"
    _, signed_headers, _ = oauth1_client.sign(
        probe_url,
        http_method="GET",
        headers={},
    )
    auth_header = signed_headers.get("Authorization")
    if auth_header:
        LOGGER.debug("OAuth1 Authorization header (sample GET /2/users/me): %s", auth_header)
    else:
        LOGGER.debug("OAuth1 Authorization header missing from signed probe request.")


def build_auth_client():
    """
    Build authentication headers preferring OAuth2 over OAuth1.

    New automatic OAuth2 flow (when CLIENT_ID + CLIENT_SECRET are configured):
    1. If we have an existing X_OAUTH_ACCESS_TOKEN, probe /2/users/me to validate it.
    2. If valid → use it immediately (no browser, no refresh).
    3. If invalid/missing + we have a refresh_token → attempt refresh + auto-persist to .env.
    4. If no usable token/refresh but CLIENT_ID + CLIENT_SECRET exist → automatically
       run the full interactive OAuth2 Authorization Code + PKCE flow (browser popup,
       local callback server, token exchange). On success the new tokens are persisted
       to .env so future starts are automatic.
    5. Only if no CLIENT_ID/CLIENT_SECRET at all do we fall back to the legacy OAuth1 paths.

    If the interactive OAuth2 flow is started but fails/cancelled/times out, the server
    raises a clear error (no silent OAuth1 fallback when modern OAuth2 creds are present).

    Returns a dict of headers to use for API requests.
    """
    # Try OAuth2 first (preferred for persistent auth without browser)
    client_id = os.getenv("CLIENT_ID", "").strip()
    client_secret = os.getenv("CLIENT_SECRET", "").strip()
    oauth2_token = os.getenv("X_OAUTH_ACCESS_TOKEN", "").strip()
    refresh_token = os.getenv("X_OAUTH_REFRESH_TOKEN", "").strip()

    # Diagnostic: Show which credentials are detected (goes to stderr via logger)
    LOGGER.info("=" * 60)
    LOGGER.info("OAUTH2 CREDENTIALS DETECTION:")
    LOGGER.info(f"  CLIENT_ID present: {bool(client_id)} (len={len(client_id)})")
    LOGGER.info(f"  CLIENT_SECRET present: {bool(client_secret)} (len={len(client_secret)})")
    LOGGER.info(f"  X_OAUTH_REFRESH_TOKEN present: {bool(refresh_token)} (len={len(refresh_token)})")
    LOGGER.info(f"  X_OAUTH_ACCESS_TOKEN present: {bool(oauth2_token)} (len={len(oauth2_token)})")
    LOGGER.info("=" * 60)

    # --- Step 1: If we already have an access token, validate it first ---
    if oauth2_token:
        if _validate_oauth2_token(oauth2_token):
            LOGGER.info(">>> Using existing OAuth2 access token (valid).")
            LOGGER.info("Using existing OAuth2 bearer token authentication")
            return {"Authorization": f"Bearer {oauth2_token}"}
        else:
            LOGGER.info(">>> Existing OAuth2 token is invalid — will try to refresh.")

    # --- Step 2: Attempt token refresh if we have the credentials ---
    if client_id and client_secret and refresh_token:
        LOGGER.info(">>> ATTEMPTING OAUTH2 TOKEN REFRESH <<<")
        result = _refresh_oauth2_token(client_id, client_secret, refresh_token)
        if result:
            new_access_token, new_refresh_token = result
            # Export to environment so the current process can use it
            os.environ["X_OAUTH_ACCESS_TOKEN"] = new_access_token
            # Persist to .env so future startups skip the refresh
            _persist_tokens_to_env(new_access_token, new_refresh_token)
            LOGGER.info("=" * 60)
            LOGGER.info("OAUTH2 TOKEN REFRESHED SUCCESSFULLY")
            LOGGER.info("=" * 60)
            LOGGER.info("Using OAuth2 bearer token authentication")
            return {"Authorization": f"Bearer {new_access_token}"}
        else:
            LOGGER.info(">>> OAUTH2 TOKEN REFRESH FAILED — will attempt automatic re-authorization via PKCE")

    # --- Step 3: If we have CLIENT_ID + CLIENT_SECRET, run the full interactive OAuth2 PKCE flow ---
    # This is now the automatic way to obtain a fresh OAuth2 user token on startup.
    if client_id and client_secret:
        LOGGER.info(">>> NO VALID OAUTH2 TOKEN/REFRESH — STARTING AUTOMATIC OAUTH2 PKCE FLOW <<<")
        LOGGER.info(">>> If the browser shows 'something went wrong', the #1 cause is that the")
        LOGGER.info(">>> Callback URL printed below is NOT registered exactly in your X app.")
        try:
            access_token, refresh_token = run_oauth2_pkce_flow()
            os.environ["X_OAUTH_ACCESS_TOKEN"] = access_token
            if refresh_token:
                os.environ["X_OAUTH_REFRESH_TOKEN"] = refresh_token
            _persist_tokens_to_env(access_token, refresh_token)
            LOGGER.info("Using freshly obtained OAuth2 bearer token authentication")
            return {"Authorization": f"Bearer {access_token}"}
        except Exception as flow_err:
            LOGGER.error(">>> OAuth2 PKCE authorization flow failed: %s", flow_err)
            raise RuntimeError(
                "OAuth2 authorization is required (CLIENT_ID/CLIENT_SECRET provided) "
                "but the interactive browser flow did not complete successfully.\n\n"
                "Most common cause: The 'Callback URL' shown above does not exactly match\n"
                "a Redirect URI registered in your X Developer App (User authentication settings).\n"
                "X is extremely strict — it must match character-for-character (use 127.0.0.1, not localhost).\n\n"
                "Other causes: user cancelled/denied, timeout, or network error.\n"
                "After fixing the redirect URI registration, run the server again."
            ) from flow_err

    # --- Step 4: Pure OAuth1 path (no CLIENT_ID/CLIENT_SECRET configured at all) ---
    consumer_key = os.getenv("X_OAUTH_CONSUMER_KEY")
    consumer_secret = os.getenv("X_OAUTH_CONSUMER_SECRET")
    if not consumer_key or not consumer_secret:
        raise RuntimeError(
            "No usable OAuth2 credentials (CLIENT_ID/CLIENT_SECRET + token or refresh) and "
            "no X_OAUTH_CONSUMER_KEY / X_OAUTH_CONSUMER_SECRET provided for OAuth1 fallback."
        )

    # Check for pre-existing OAuth1 tokens first (for stdio mode / Cline integration)
    env_access_token = os.getenv("X_OAUTH_ACCESS_TOKEN", "").strip()
    env_access_secret = os.getenv("X_OAUTH_ACCESS_TOKEN_SECRET", "").strip()

    if env_access_token and env_access_secret:
        if is_truthy(os.getenv("X_OAUTH_PRINT_TOKENS", "0")):
            LOGGER.info("Using pre-existing OAuth1 access token: %s", env_access_token)
        LOGGER.info("Using pre-existing OAuth1 access token: %s", env_access_token)
        return {
            "client_key": consumer_key,
            "client_secret": consumer_secret,
            "resource_owner_key": env_access_token,
            "resource_owner_secret": env_access_secret,
        }

    # Fall back to browser-based OAuth1 flow (legacy path)
    LOGGER.info(">>> TRIGGERING OAUTH1 BROWSER FLOW <<<")
    access_token, access_secret = run_oauth1_flow()
    if is_truthy(os.getenv("X_OAUTH_PRINT_TOKENS", "0")):
        LOGGER.info("OAuth1 access token: %s", access_token)
        LOGGER.info("OAuth1 access token secret: %s", access_secret)
    LOGGER.info("OAuth1 access token: %s", access_token)
    return {
        "client_key": consumer_key,
        "client_secret": consumer_secret,
        "resource_owner_key": access_token,
        "resource_owner_secret": access_secret,
    }


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

    # Load the OpenAPI spec before branching (needed by both paths)
    spec = load_openapi_spec()
    filtered_spec = filter_openapi_spec(spec)
    comma_params = collect_comma_params(filtered_spec)
    print_tool_list(filtered_spec)

    # Define request/response hooks used by both paths
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

    if is_oauth2:
        # OAuth2: use bearer token directly (no signature hook needed)
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
                    LOGGER.debug("OAuth1 Authorization header: %s", auth_header)
                else:
                    LOGGER.debug("OAuth1 Authorization header missing from signed request.")

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