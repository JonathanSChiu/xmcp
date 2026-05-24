"""
Standalone script to generate an OAuth 2.0 Bearer Token (access_token) and
refresh_token for the X API v2 using the Authorization Code Flow with PKCE.

This is useful for pre-populating tokens before starting the MCP server.

Note: Starting with recent changes, `python server.py` (or your MCP client launching it)
will now automatically run the exact same interactive PKCE flow on startup if
CLIENT_ID + CLIENT_SECRET are set but no valid/refreshable token exists.
You can often skip running this script separately.

Usage (when you want to pre-generate tokens manually):
    1. Ensure CLIENT_ID and CLIENT_SECRET are set in your .env file.
    2. Optionally set OAUTH2_CALLBACK_HOST, OAUTH2_CALLBACK_PORT, OAUTH2_CALLBACK_PATH
       (defaults: 127.0.0.1:9876/oauth/callback).
       Register this exact URL in your X Developer App settings under
       "App Settings > User authentication settings > Redirect URI".
    3. Run:  python generate_authtoken.py
    4. A browser will open for you to authorize the app.
       The script will capture the callback, exchange the code for tokens,
       and write them to .env automatically.

Dependencies:
    - requests
    - python-dotenv
    (Both are already in requirements.txt)
"""

import base64
import hashlib
import http.server
import json
import logging
import os
import socketserver
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path

import requests

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger("generate_authtoken")

AUTHORIZE_URL = "https://x.com/i/oauth2/authorize"
TOKEN_URL = "https://api.x.com/2/oauth2/token"

SCOPE = "tweet.read tweet.write users.read bookmark.read offline.access"


def load_env() -> None:
    """Load variables from .env file if present."""
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(env_path, override=True)


def _persist_tokens(access_token: str, refresh_token: str | None) -> None:
    """Write OAuth2 tokens into .env so server.py can pick them up."""
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        print(f">>> .env file not found at {env_path}, creating one.")
        env_path.write_text("")

    try:
        from dotenv import set_key
    except ImportError:
        print(">>> python-dotenv not installed. Install it with: pip install python-dotenv")
        print(f">>> Set these manually in .env:")
        print(f"    X_OAUTH_ACCESS_TOKEN={access_token}")
        if refresh_token:
            print(f"    X_OAUTH_REFRESH_TOKEN={refresh_token}")
        return

    print(">>> Persisting tokens to .env ...")
    set_key(str(env_path), "X_OAUTH_ACCESS_TOKEN", access_token)
    if refresh_token:
        set_key(str(env_path), "X_OAUTH_REFRESH_TOKEN", refresh_token)
        print(">>> Done! X_OAUTH_ACCESS_TOKEN and X_OAUTH_REFRESH_TOKEN written to .env")
    else:
        print(">>> Done! X_OAUTH_ACCESS_TOKEN written to .env (no refresh token)")


def generate_pkce_pair() -> tuple[str, str]:
    """
    Generate a PKCE code verifier and code challenge (S256).
    Returns (code_verifier, code_challenge).
    """
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def main() -> None:
    load_env()

    client_id = os.getenv("CLIENT_ID", "").strip()
    client_secret = os.getenv("CLIENT_SECRET", "").strip()

    if not client_id or not client_secret:
        print("ERROR: CLIENT_ID and CLIENT_SECRET must be set in .env")
        print("Add these to your .env file:")
        print("  CLIENT_ID=<your-client-id>")
        print("  CLIENT_SECRET=<your-client-secret>")
        return

    callback_host = os.getenv("OAUTH2_CALLBACK_HOST", "127.0.0.1")
    callback_port = int(os.getenv("OAUTH2_CALLBACK_PORT", "9876"))
    callback_path = os.getenv("OAUTH2_CALLBACK_PATH", "/oauth/callback")
    callback_url = f"http://{callback_host}:{callback_port}{callback_path}"

    print("=" * 60)
    print("X API v2 OAuth 2.0 Token Generator")
    print("=" * 60)
    print(f"Callback URL: {callback_url}")
    print(f"Make sure this URL is registered in your X Developer App settings.")
    print("")

    # Generate PKCE challenge
    code_verifier, code_challenge = generate_pkce_pair()
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("ascii")

    # Build authorization URL
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": callback_url,
        "scope": SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

    print(f"Opening browser for authorization...")
    LOGGER.info("Opening %s", auth_url)
    webbrowser.open(auth_url)

    # --- Start local callback server to capture the authorization code ---
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
            LOGGER.debug("Callback: " + format, *args)

    class _Server(socketserver.TCPServer):
        allow_reuse_address = True

    server = _Server((callback_host, callback_port), _Handler)
    server.timeout = 1
    deadline = time.time() + 300  # 5 minute timeout

    print("Waiting for authorization callback... (timeout: 5 minutes)")
    try:
        while time.time() < deadline:
            server.handle_request()
            if event.is_set():
                break
    finally:
        server.server_close()

    if captured["error"]:
        print(f">>> Authorization denied: {captured['error']}")
        return

    auth_code = captured.get("code")
    if not auth_code:
        print(">>> No authorization code received. Timed out or cancelled.")
        return

    # Verify state matches
    if captured.get("state") != state:
        print(">>> State mismatch! Possible CSRF attack.")
        return

    print(">>> Authorization code received. Exchanging for tokens...")

    # Exchange the authorization code for tokens
    # Per X API docs: use Basic auth with client_id:client_secret
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

    try:
        response = requests.post(
            TOKEN_URL,
            headers=token_headers,
            data=token_data,
            timeout=30,
        )
        print(f">>> Token endpoint response: {response.status_code}")
        if not response.ok:
            try:
                err_json = response.json()
                err_type = err_json.get("error", "unknown_error")
                err_desc = err_json.get("error_description", response.text[:300])
                print(f">>> X OAuth2 error: {err_type}")
                if err_desc:
                    print(f">>>   Description: {err_desc}")
                if err_type in ("invalid_client", "invalid_grant", "invalid_request"):
                    print(">>>   Common causes:")
                    print(">>>     - CLIENT_ID / CLIENT_SECRET do not match your X Developer App (check for typos/whitespace)")
                    print(">>>     - The redirect_uri you used does not exactly match what is registered in the app settings")
                    print(">>>     - authorization code expired or already used (try running the script again)")
            except Exception:
                print(f">>> Response body: {response.text[:1000]}")
            response.raise_for_status()

        token_json = response.json()
        access_token = token_json.get("access_token")
        refresh_token = token_json.get("refresh_token")
        expires_in = token_json.get("expires_in")

        if not access_token:
            print(f">>> No access_token in response: {json.dumps(token_json, indent=2)}")
            return

        print("")
        print("=" * 60)
        print("TOKENS RECEIVED")
        print(f"  access_token:  {access_token[:30]}...")
        if refresh_token:
            print(f"  refresh_token: {refresh_token[:30]}...")
        if expires_in:
            print(f"  expires in:    {expires_in} seconds")
        print("=" * 60)

        _persist_tokens(access_token, refresh_token)

    except requests.exceptions.RequestException as e:
        print(f">>> Failed to exchange authorization code: {e}")
        return


if __name__ == "__main__":
    main()