#!/usr/bin/env python3
"""Tests for the headless (copy-and-paste) OAuth login path."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from gs.auth import GoogleAuth, NotAuthenticatedError
from gs.config import Config


def make_auth(tmp_path, credentials_file=None):
    config = Config()
    config.auth.cached_auth_token = str(tmp_path / "tokens")
    config.auth.credentials = credentials_file
    return GoogleAuth(config)


# --------------------------------------------------------------------------
# _extract_code
# --------------------------------------------------------------------------


def test_extract_code_from_full_callback_url():
    url = (
        "http://localhost:47893/?state=abc123&iss=https://accounts.google.com"
        "&code=4/0ATsMZqB-token&scope=https://mail.google.com/"
    )
    assert GoogleAuth._extract_code(url, expected_state="abc123") == "4/0ATsMZqB-token"


def test_extract_code_accepts_bare_code():
    assert GoogleAuth._extract_code("4/0ATsMZqB-token") == "4/0ATsMZqB-token"


def test_extract_code_accepts_bare_query_string():
    assert GoogleAuth._extract_code("state=s&code=xyz", expected_state="s") == "xyz"


def test_extract_code_rejects_state_mismatch():
    url = "http://localhost:47893/?state=other&code=xyz"
    with pytest.raises(NotAuthenticatedError, match="State mismatch"):
        GoogleAuth._extract_code(url, expected_state="abc123")


def test_extract_code_surfaces_authorization_error():
    url = "http://localhost:47893/?error=access_denied&state=abc123"
    with pytest.raises(NotAuthenticatedError, match="access_denied"):
        GoogleAuth._extract_code(url, expected_state="abc123")


def test_extract_code_without_code_param():
    with pytest.raises(NotAuthenticatedError, match="Could not find a 'code'"):
        GoogleAuth._extract_code("http://localhost:47893/?state=abc123")


def test_extract_code_rejects_empty():
    with pytest.raises(NotAuthenticatedError, match="No authorization code"):
        GoogleAuth._extract_code("")


# --------------------------------------------------------------------------
# pending flow: _headless_login writes it, complete_login consumes it
# --------------------------------------------------------------------------


def test_headless_login_persists_pending_flow(tmp_path, capsys):
    auth = make_auth(tmp_path, credentials_file=str(tmp_path / "creds.json"))
    flow = MagicMock()
    flow.authorization_url.return_value = ("https://accounts.google.com/auth", "st8")
    flow.code_verifier = "verifier-value"

    # No TTY to paste into: the flow is saved and the user is told how to finish.
    with patch("gs.auth.sys.stdin.isatty", return_value=False):
        with pytest.raises(NotAuthenticatedError, match="--callback-url"):
            auth._headless_login(flow)

    assert flow.redirect_uri == GoogleAuth.HEADLESS_REDIRECT_URI
    assert "https://accounts.google.com/auth" in capsys.readouterr().out

    pending = json.loads((tmp_path / "pending_auth.json").read_text())
    assert pending["state"] == "st8"
    assert pending["code_verifier"] == "verifier-value"
    assert pending["redirect_uri"] == GoogleAuth.HEADLESS_REDIRECT_URI


def test_pending_file_is_owner_only(tmp_path):
    auth = make_auth(tmp_path)
    auth._save_pending("st8", "verifier-value")
    mode = os.stat(tmp_path / "pending_auth.json").st_mode & 0o777
    assert mode == 0o600


def test_complete_login_resumes_pending_flow(tmp_path):
    creds_file = tmp_path / "creds.json"
    creds_file.write_text("{}")
    auth = make_auth(tmp_path, credentials_file=str(creds_file))
    auth._save_pending("st8", "verifier-value")

    flow = MagicMock()
    flow.credentials = "picklable-stand-in-credentials"  # _save() pickles this
    with patch(
        "gs.auth.InstalledAppFlow.from_client_secrets_file", return_value=flow
    ) as from_file:
        auth.complete_login("http://localhost:47893/?state=st8&code=the-code")

    # The PKCE verifier from the earlier invocation is reused, not regenerated.
    _, kwargs = from_file.call_args
    assert kwargs["code_verifier"] == "verifier-value"
    assert kwargs["autogenerate_code_verifier"] is False
    flow.fetch_token.assert_called_once_with(code="the-code")

    # Token cached, pending state cleaned up.
    assert os.path.exists(tmp_path / "tokens")
    assert not os.path.exists(tmp_path / "pending_auth.json")


def test_complete_login_without_pending_flow(tmp_path):
    auth = make_auth(tmp_path)
    with pytest.raises(NotAuthenticatedError, match="No login in progress"):
        auth.complete_login("http://localhost:47893/?code=the-code")


def test_complete_login_rejects_mismatched_state(tmp_path):
    auth = make_auth(tmp_path, credentials_file=str(tmp_path / "creds.json"))
    auth._save_pending("st8", "verifier-value")
    with pytest.raises(NotAuthenticatedError, match="State mismatch"):
        auth.complete_login("http://localhost:47893/?state=wrong&code=the-code")
    # A stale attempt must not discard the in-flight login.
    assert os.path.exists(tmp_path / "pending_auth.json")


def test_logout_clears_pending_flow(tmp_path):
    auth = make_auth(tmp_path)
    auth._save_pending("st8", "verifier-value")
    auth.logout()
    assert not os.path.exists(tmp_path / "pending_auth.json")


# --------------------------------------------------------------------------
# headless detection
# --------------------------------------------------------------------------


def test_wayland_desktop_is_not_headless(tmp_path):
    auth = make_auth(tmp_path)
    env = {"WAYLAND_DISPLAY": "wayland-1"}
    with patch.dict(os.environ, env, clear=True):
        with patch("gs.auth.platform.system", return_value="Linux"):
            assert auth._is_headless_environment() is False


def test_bare_linux_console_is_headless(tmp_path):
    auth = make_auth(tmp_path)
    with patch.dict(os.environ, {}, clear=True):
        with patch("gs.auth.platform.system", return_value="Linux"):
            assert auth._is_headless_environment() is True


# --------------------------------------------------------------------------
# browser login: the local server and a pasted URL are interchangeable
# --------------------------------------------------------------------------


def make_flow(state="st8"):
    flow = MagicMock()
    flow.authorization_url.return_value = ("https://accounts.google.com/auth", state)
    flow.code_verifier = "verifier-value"
    flow.credentials = "picklable-stand-in-credentials"
    return flow


def run_browser_login(tmp_path, pasted_lines):
    """Drive _browser_login with `pasted_lines` arriving on stdin."""
    auth = make_auth(tmp_path, credentials_file=str(tmp_path / "creds.json"))
    flow = make_flow()
    lines = list(pasted_lines)

    def readline():
        return lines.pop(0) if lines else ""

    with patch("gs.auth.webbrowser.open"), patch(
        "gs.auth.sys.stdin.isatty", return_value=True
    ), patch("gs.auth.sys.stdin.readline", side_effect=readline):
        auth._browser_login(flow)
    return auth, flow


def test_pasted_callback_url_completes_the_waiting_login(tmp_path):
    _, flow = run_browser_login(
        tmp_path,
        ["http://localhost:47893/?state=st8&code=pasted-code\n"],
    )

    # The paste is replayed through the local server, so the flow finishes the
    # same way a real browser redirect would.
    response = flow.fetch_token.call_args.kwargs["authorization_response"]
    assert response.startswith("https://localhost:")
    assert "code=pasted-code" in response
    assert "state=st8" in response


def test_pasted_bare_code_is_accepted(tmp_path):
    _, flow = run_browser_login(tmp_path, ["4/0ATsMZqB-bare-code\n"])
    response = flow.fetch_token.call_args.kwargs["authorization_response"]
    assert "code=4%2F0ATsMZqB-bare-code" in response


def test_bad_paste_is_reprompted_not_fatal(tmp_path, capsys):
    _, flow = run_browser_login(
        tmp_path,
        [
            "http://localhost:47893/?state=WRONG&code=nope\n",
            "http://localhost:47893/?state=st8&code=good-code\n",
        ],
    )
    assert "State mismatch" in capsys.readouterr().out
    response = flow.fetch_token.call_args.kwargs["authorization_response"]
    assert "code=good-code" in response


def test_browser_login_clears_pending_on_success(tmp_path):
    auth, _ = run_browser_login(
        tmp_path, ["http://localhost:47893/?state=st8&code=c\n"]
    )
    assert not os.path.exists(tmp_path / "pending_auth.json")


def test_browser_login_records_its_real_redirect_uri(tmp_path):
    """The pending file must hold the port actually used, not the headless one."""
    auth = make_auth(tmp_path, credentials_file=str(tmp_path / "creds.json"))
    flow = make_flow()
    captured = {}

    def readline():
        captured["redirect_uri"] = flow.redirect_uri
        captured["pending"] = json.loads((tmp_path / "pending_auth.json").read_text())
        return "http://localhost:47893/?state=st8&code=c\n"

    with patch("gs.auth.webbrowser.open"), patch(
        "gs.auth.sys.stdin.isatty", return_value=True
    ), patch("gs.auth.sys.stdin.readline", side_effect=readline):
        auth._browser_login(flow)

    assert captured["pending"]["redirect_uri"] == captured["redirect_uri"]
    assert captured["redirect_uri"].startswith("http://localhost:")
    assert captured["redirect_uri"] != GoogleAuth.HEADLESS_REDIRECT_URI


# --------------------------------------------------------------------------
# token exchange failures
# --------------------------------------------------------------------------


def test_rejected_code_reports_cleanly_and_keeps_pending(tmp_path):
    """A bad paste must be retryable, not a traceback that loses the consent."""
    from oauthlib.oauth2 import InvalidGrantError

    creds_file = tmp_path / "creds.json"
    creds_file.write_text("{}")
    auth = make_auth(tmp_path, credentials_file=str(creds_file))
    auth._save_pending("st8", "verifier-value")

    flow = MagicMock()
    flow.fetch_token.side_effect = InvalidGrantError()
    with patch("gs.auth.InstalledAppFlow.from_client_secrets_file", return_value=flow):
        with pytest.raises(NotAuthenticatedError, match="already used, expired"):
            auth.complete_login("http://localhost:47893/?state=st8&code=stale")

    assert os.path.exists(tmp_path / "pending_auth.json")
