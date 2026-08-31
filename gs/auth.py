"""Google API authentication for gs (Gmail, Calendar, Drive).

A single OAuth consent covers all three APIs via the combined SCOPES. The cached
token is reused across `gs gmail`, `gs calendar`, and `gs drive`. Interactive
login happens only through `gs auth login`; other commands require an existing
token and raise NotAuthenticatedError otherwise.
"""

import json
import os
import pickle
import platform
import sys
import threading
import urllib.request
import webbrowser
import wsgiref.simple_server
import wsgiref.util
from urllib.parse import parse_qs, urlencode, urlparse

from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from oauthlib.oauth2 import OAuth2Error

from .config import Config


class NotAuthenticatedError(Exception):
    """Raised when a command needs auth but no valid token is available."""


class GoogleAuth:
    """Authenticate to Google APIs and build per-API service clients."""

    # Combined scopes — one consent for Gmail (full), Calendar, and Drive.
    SCOPES = [
        "https://mail.google.com/",
        "https://www.googleapis.com/auth/calendar",
        "https://www.googleapis.com/auth/drive",
    ]

    # Any localhost port is a valid redirect for a Desktop OAuth client. We
    # never listen on it — the browser's failure to connect is expected, and
    # the code is read off the address bar. Picked high and odd so a paste-back
    # mistake is unlikely to hand the code to a real local service.
    HEADLESS_REDIRECT_URI = "http://localhost:47893/"

    def __init__(self, config: Config):
        self.config = config

    # -- token cache ------------------------------------------------------

    def _load_cached(self):
        token_file = self.config.auth.cached_auth_token
        if self.config.auth.ignore_token:
            return None
        if os.path.exists(token_file):
            with open(token_file, "rb") as fh:
                return pickle.load(fh)
        return None

    def _save(self, creds):
        token_file = self.config.auth.cached_auth_token
        os.makedirs(os.path.dirname(token_file), exist_ok=True)
        with open(token_file, "wb") as fh:
            pickle.dump(creds, fh)

    def logout(self) -> bool:
        """Delete the cached token. Returns True if a token was removed."""
        token_file = self.config.auth.cached_auth_token
        self._clear_pending()
        if os.path.exists(token_file):
            os.remove(token_file)
            return True
        return False

    # -- credentials ------------------------------------------------------

    def credentials(self, allow_login: bool = False) -> Credentials:
        """Return valid credentials.

        Uses the cached token (refreshing if expired). Falls back to a service
        account key if configured. Runs the interactive OAuth flow only when
        ``allow_login`` is True; otherwise raises NotAuthenticatedError.
        """
        creds = self._load_cached()

        if creds and creds.valid:
            return creds

        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                self._save(creds)
                return creds
            except Exception as e:
                if not self.config.quiet:
                    print(f"Failed to refresh token: {e}")

        # Service accounts are non-interactive.
        if self.config.auth.auth_token:
            return self._service_account_credentials()

        if allow_login:
            creds = self._oauth_login()
            self._save(creds)
            return creds

        raise NotAuthenticatedError(
            "Not authenticated. Run: gs auth login --credentials <file.json>"
        )

    def login(self) -> Credentials:
        """Force interactive (or service-account) login and cache the token."""
        if self.config.auth.auth_token:
            creds = self._service_account_credentials()
        else:
            creds = self._oauth_login()
        self._save(creds)
        return creds

    def status(self):
        """Return valid credentials without logging in, or None if unavailable."""
        try:
            return self.credentials(allow_login=False)
        except NotAuthenticatedError:
            return None

    # -- service builders -------------------------------------------------

    def service(self, api: str, version: str, allow_login: bool = False):
        """Build a googleapiclient resource for the given API."""
        return build(api, version, credentials=self.credentials(allow_login))

    # -- credential acquisition -------------------------------------------

    def _service_account_credentials(self) -> Credentials:
        path = self.config.auth.auth_token
        if not os.path.exists(path):
            raise NotAuthenticatedError(f"Service account file not found: {path}")
        return service_account.Credentials.from_service_account_file(
            path, scopes=self.SCOPES
        )

    def _is_headless_environment(self) -> bool:
        if os.environ.get("SSH_CLIENT") or os.environ.get("SSH_TTY"):
            return True
        if (
            os.name == "posix"
            and platform.system() == "Linux"
            and not os.environ.get("DISPLAY")
            and not os.environ.get("WAYLAND_DISPLAY")
        ):
            return True
        if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
            return True
        if os.path.exists("/.dockerenv"):
            return True
        return False

    def _oauth_login(self) -> Credentials:
        credentials_file = self.config.auth.credentials
        if not credentials_file or not os.path.exists(credentials_file):
            raise NotAuthenticatedError(
                "No OAuth2 credentials file. Provide --credentials <file.json> "
                "(or --auth-token for a service account)."
            )

        flow = InstalledAppFlow.from_client_secrets_file(credentials_file, self.SCOPES)
        use_headless = (
            self.config.auth.force_headless or self._is_headless_environment()
        )

        if use_headless:
            return self._headless_login(flow)
        return self._browser_login(flow)

    def _browser_login(self, flow) -> Credentials:
        """Serve the OAuth callback locally, but accept a pasted URL too.

        ``run_local_server`` alone hangs forever when the browser lives on
        another machine (SSH, container, remote desktop): Google redirects to
        *that* machine's localhost and nothing ever reaches us. So while the
        server waits, a reader thread also watches stdin — a pasted callback
        URL is replayed against our own server, which means both routes end up
        in exactly the same code path.
        """
        app = _CallbackApp()
        try:
            server = wsgiref.simple_server.make_server(
                "localhost", 0, app, handler_class=_QuietRequestHandler
            )
        except OSError:
            # Can't bind at all — the paste is the only route left.
            return self._headless_login(flow)

        port = server.server_port
        flow.redirect_uri = f"http://localhost:{port}/"
        auth_url, state = flow.authorization_url(
            access_type="offline", prompt="consent"
        )
        self._save_pending(state, flow.code_verifier, flow.redirect_uri)

        try:
            webbrowser.open(auth_url, new=1, autoraise=True)
        except Exception:
            pass

        print("Please visit this URL to authorize this application:")
        print("")
        print(f"   {auth_url}")
        print("")
        print("Waiting for the browser to come back...")
        if sys.stdin.isatty():
            print(
                "If you authorized on another machine, paste the URL it was "
                "redirected to here and press Enter:"
            )
            reader = threading.Thread(
                target=self._paste_watcher,
                args=(port, state),
                daemon=True,
            )
            reader.start()

        try:
            server.handle_request()
            if not app.last_request_uri:
                raise NotAuthenticatedError("Authorization was not completed.")
            # oauthlib insists OAuth 2.0 only happen over https.
            self._fetch_token(
                flow,
                authorization_response=app.last_request_uri.replace("http", "https", 1),
            )
        finally:
            server.server_close()

        self._clear_pending()
        return flow.credentials

    def _paste_watcher(self, port: int, expected_state: str) -> None:
        """Replay a pasted callback URL against our own local server.

        Runs on a daemon thread; if the browser gets there first this is simply
        abandoned at exit.
        """
        while True:
            try:
                response = sys.stdin.readline()
            except Exception:
                return
            if not response:  # stdin closed
                return
            response = response.strip()
            if not response:
                continue
            try:
                code = self._extract_code(response, expected_state=expected_state)
            except NotAuthenticatedError as e:
                print(f"{e}\nTry pasting the URL again:")
                continue
            query = urlencode({"state": expected_state, "code": code})
            try:
                urllib.request.urlopen(
                    f"http://localhost:{port}/?{query}", timeout=10
                ).read()
            except Exception as e:
                print(f"Could not hand off the pasted code: {e}")
            return

    def _headless_login(self, flow) -> Credentials:
        """Copy-and-paste OAuth flow for machines with no usable browser.

        Google retired the out-of-band redirect, so authorization still lands on
        a localhost URL — but on whichever machine ran the browser, not this
        one. Rather than listening for a callback that will never arrive, we
        print the URL and read the redirected address back from the operator.

        The flow's state and PKCE verifier are also written to a pending file so
        the paste can arrive in a *later* invocation via
        ``gs auth login --callback-url <url>`` — useful when this process can't
        stay attached to a terminal.
        """
        flow.redirect_uri = self.HEADLESS_REDIRECT_URI
        auth_url, state = flow.authorization_url(
            access_type="offline", prompt="consent"
        )
        self._save_pending(state, flow.code_verifier)

        print("Headless mode - console-based authentication")
        print("")
        print("1. Open this URL in a browser (any machine):")
        print("")
        print(f"   {auth_url}")
        print("")
        print("2. Authorize the application. The browser will then fail to load")
        print(f"   a {self.HEADLESS_REDIRECT_URI} page - that is expected.")
        print("3. Copy that failed page's full address from the address bar.")
        print("")
        sys.stdout.flush()  # keep the instructions ahead of anything on stderr

        if not sys.stdin.isatty():
            raise NotAuthenticatedError(
                "No terminal to paste into. Once authorized, finish with:\n"
                "  gs auth login --callback-url '<the redirected URL>'"
            )

        try:
            response = input("Paste the redirected URL (or just the code): ").strip()
        except (EOFError, KeyboardInterrupt):
            raise NotAuthenticatedError(
                "No authorization code provided. Once authorized, finish with:\n"
                "  gs auth login --callback-url '<the redirected URL>'"
            )

        code = self._extract_code(response, expected_state=state)
        self._fetch_token(flow, code=code)
        self._clear_pending()
        return flow.credentials

    # -- pending headless flow --------------------------------------------

    @property
    def _pending_file(self) -> str:
        return os.path.join(
            os.path.dirname(self.config.auth.cached_auth_token), "pending_auth.json"
        )

    def _save_pending(
        self, state: str, code_verifier: str, redirect_uri: str = None
    ) -> None:
        """Persist just enough of the in-flight flow to finish it later."""
        path = self._pending_file
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = {
            "state": state,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri or self.HEADLESS_REDIRECT_URI,
            "credentials_file": self.config.auth.credentials,
        }
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(payload, fh)

    def _clear_pending(self) -> None:
        try:
            os.remove(self._pending_file)
        except OSError:
            pass

    def complete_login(self, callback_url: str) -> Credentials:
        """Finish a headless login from the pasted callback URL (or bare code).

        Resumes the flow started by an earlier ``gs auth login`` on this machine,
        reusing its PKCE verifier and validating its state.
        """
        path = self._pending_file
        if not os.path.exists(path):
            raise NotAuthenticatedError(
                "No login in progress. Start one with: "
                "gs auth login --credentials <file.json>"
            )
        with open(path) as fh:
            pending = json.load(fh)

        code = self._extract_code(callback_url, expected_state=pending["state"])

        credentials_file = (
            pending.get("credentials_file") or self.config.auth.credentials
        )
        if not credentials_file or not os.path.exists(credentials_file):
            raise NotAuthenticatedError(
                f"OAuth2 credentials file is gone: {credentials_file}"
            )

        flow = InstalledAppFlow.from_client_secrets_file(
            credentials_file,
            self.SCOPES,
            autogenerate_code_verifier=False,
            code_verifier=pending["code_verifier"],
        )
        flow.redirect_uri = pending["redirect_uri"]
        self._fetch_token(flow, code=code)

        self._clear_pending()
        self._save(flow.credentials)
        return flow.credentials

    @staticmethod
    def _fetch_token(flow, **kwargs) -> None:
        """Exchange the code, reporting rejections without a traceback.

        The pending file is deliberately left in place so a bad paste can be
        retried with --callback-url rather than restarting the whole consent.
        """
        try:
            flow.fetch_token(**kwargs)
        except OAuth2Error as e:
            hint = ""
            if getattr(e, "error", None) == "invalid_grant":
                hint = (
                    " (the code was already used, expired, or belongs to a "
                    "different login attempt)"
                )
            raise NotAuthenticatedError(f"Authorization failed: {e}{hint}")

    @staticmethod
    def _extract_code(response: str, expected_state: str = None) -> str:
        """Pull the authorization code out of a pasted redirect URL or raw code."""
        if not response:
            raise NotAuthenticatedError("No authorization code provided.")

        if "://" not in response and "code=" not in response:
            return response  # already a bare code

        query = urlparse(response).query if "://" in response else response
        params = parse_qs(query)

        error = params.get("error", [None])[0]
        if error:
            raise NotAuthenticatedError(f"Authorization failed: {error}")

        code = params.get("code", [None])[0]
        if not code:
            raise NotAuthenticatedError(
                "Could not find a 'code' parameter in the pasted URL."
            )

        state = params.get("state", [None])[0]
        if expected_state and state and state != expected_state:
            raise NotAuthenticatedError(
                "State mismatch - the pasted URL is from a different login attempt."
            )
        return code


class _QuietRequestHandler(wsgiref.simple_server.WSGIRequestHandler):
    """Suppress the access log — its request line contains the auth code."""

    def log_message(self, format, *args):
        pass


class _CallbackApp:
    """WSGI app that records the OAuth redirect and thanks the browser."""

    def __init__(self):
        self.last_request_uri = None

    def __call__(self, environ, start_response):
        start_response("200 OK", [("Content-type", "text/plain; charset=utf-8")])
        self.last_request_uri = wsgiref.util.request_uri(environ)
        return [b"The authentication flow has completed. You may close this window."]
