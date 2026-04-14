#!/usr/bin/env python3
"""
session_authenticator.py — Headless Browser Authentication for ITP Demo

This module handles the "victim" side of the Okta Identity Threat Protection (ITP)
session hijacking demo. It uses Playwright (a headless Chromium browser) to perform
a real Okta login, capture the resulting session cookie (typically the ``idx`` cookie),
and optionally keep the browser open for continuous video recording.

How it fits in the ITP demo flow
--------------------------------
1. **Victim authenticates** (this module) — Playwright logs in as the demo user,
   captures the ``idx`` session cookie, and optionally records a video.
2. **Attacker replays** (session_replayer.py) — The stolen cookie is sent to a
   Lambda function in a different AWS region (e.g., eu-west-1) which replays it
   against the Okta dashboard, triggering Okta ITP's session-hijacking detection.
3. **Okta ITP detects anomaly** — IP/geo/device mismatch triggers a risk event
   and Universal Logout (ULO) terminates the session.
4. **Monitor observes** (monitor_itp_events.py) — Watches the Okta system log
   for the risk event and session revocation.

Session modes
-------------
- **One-time** (``authenticate``): Opens a browser, logs in, captures the cookie,
  closes the browser. The cookie is returned for use by the attacker Lambda.
  Video is finalized immediately.
- **Persistent** (``authenticate_persistent``): Opens a browser, logs in, and
  returns a ``BrowserSession`` with the browser *still running*. This lets the
  video capture the entire demo lifecycle: login -> dashboard -> attacker replay
  -> ULO session termination (redirect back to login page). The caller is
  responsible for calling ``BrowserSession.close()`` to finalize the video.

MFA / TOTP handling
-------------------
Supports Okta Identity Engine (OIE) TOTP MFA. When a ``totp_secret`` (base32) is
provided, the module generates a time-based code via ``pyotp`` and fills it into
the OIE authenticator challenge form. Handles both direct TOTP prompts and the
OIE authenticator-selection screen (where the user must first click "Select" next
to Okta Verify TOTP before the code input appears).

Fallback
--------
If Playwright browser-based auth fails (e.g., DOM changes, timeout), the module
falls back to Okta's Authn API (``/api/v1/authn``) to obtain a ``sid`` cookie.
Note: the ``sid`` cookie may not trigger ITP detection as reliably as ``idx``.

Requirements:
    pip install playwright pyotp
    playwright install chromium

Usage (as module):
    from itp.session_authenticator import SessionAuthenticator
    auth = SessionAuthenticator("yourorg", "okta.com")
    result = auth.authenticate("user@example.com", "password", totp_secret="BASE32SECRET")
    print(result["cookie"])  # idx cookie value

Usage (standalone):
    python3 -m itp.session_authenticator \\
        --username user@example.com \\
        --password-ssm /demo/itp/password \\
        --totp-ssm /demo/itp/totp-secret
"""

import os
import sys
import json
import time
import argparse
from typing import Dict, Optional


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class AuthenticationError(Exception):
    """Raised when browser authentication fails.

    Carries an optional ``video_path`` so callers can retrieve the recording
    even when authentication does not succeed (useful for debugging).
    """

    def __init__(self, message, video_path=None):
        super().__init__(message)
        self.video_path = video_path


# ---------------------------------------------------------------------------
# Persistent Browser Session (keeps browser alive for continuous recording)
# ---------------------------------------------------------------------------

class BrowserSession:
    """Wraps an open Playwright browser session for continuous video recording.

    Keeps the browser alive so the video captures the full demo flow:
    login -> dashboard -> attacker replay -> ULO session termination.

    The caller is responsible for closing the session via ``close()`` or by
    using it as a context manager (``with session: ...``).  Closing finalizes
    the Playwright video file (written as ``.webm``).
    """

    # -----------------------------------------------------------------------
    # ULO (Universal Logout) detection constants
    # -----------------------------------------------------------------------
    # URL path fragments that indicate the user has been redirected back to
    # the Okta login page — i.e., the session was terminated by ULO.
    LOGIN_URL_PATTERNS = ["/login/", "/signin/", "/login/login.htm"]

    # Body-text patterns that indicate session expiry.  This is a fallback
    # for OIE sign-in widgets that render client-side at the same URL (no
    # server-side redirect), so URL pattern checks alone would miss them.
    SESSION_EXPIRED_TEXT = [
        "session expired", "signed out", "session has ended",
        # OIE sign-in widget renders client-side at the same URL (no redirect),
        # so URL pattern checks don't fire. Detect the login page by its text.
        "sign in with your account",
    ]

    def __init__(self, pw, browser, context, page, auth_result: Dict,
                 owns_pw: bool = True):
        """
        Args:
            pw: The Playwright sync API instance.
            browser: The Chromium browser instance.
            context: The browser context (holds cookies, user-agent, video config).
            page: The active page/tab.
            auth_result: Dict with cookie info from authentication.
            owns_pw: If True, ``close()`` will also stop the Playwright instance.
                     Set to False for attacker sessions that share the victim's
                     Playwright instance (only one sync instance allowed per process).
        """
        self._pw = pw
        self._browser = browser
        self._context = context
        self._page = page
        self._auth_result = auth_result
        self._owns_pw = owns_pw  # Only stop pw on close if we own it
        self._closed = False

    # -- Property accessors for cookie details --------------------------------

    @property
    def cookie_name(self) -> str:
        return self._auth_result["cookie_name"]

    @property
    def cookie(self) -> str:
        return self._auth_result["cookie"]

    @property
    def domain(self) -> str:
        return self._auth_result["domain"]

    @property
    def auth_result(self) -> Dict:
        return self._auth_result

    @property
    def page(self):
        return self._page

    # -----------------------------------------------------------------------
    # ULO / Session Termination Detection
    # -----------------------------------------------------------------------

    def wait_for_session_termination(self, timeout: int = 120,
                                     poll_interval: int = 5) -> Dict:
        """Reload the page periodically, watching for session termination.

        After the attacker replays the stolen cookie from a different location,
        Okta ITP should detect the anomaly and revoke the session via Universal
        Logout (ULO).  This method polls the page to detect when that happens.

        Detection methods (checked in order on each poll cycle):
        1. **URL redirect** — page.reload() lands on a login URL pattern.
        2. **Page content** — body text contains session-expired phrases
           (catches OIE widgets that re-render at the same URL).
        3. **Reload failure** — navigation itself fails, which may indicate
           the session was invalidated server-side.

        Args:
            timeout: Maximum seconds to wait before giving up.
            poll_interval: Seconds between page reload cycles.

        Returns:
            Dict with keys: terminated (bool), elapsed (int), final_url (str),
            reason (str).
        """
        print(f"  Watching browser for session termination ({timeout}s, every {poll_interval}s)...")
        start = time.time()

        while time.time() - start < timeout:
            time.sleep(poll_interval)
            elapsed = int(time.time() - start)

            # Reload the page — if the session is still valid, the user stays
            # on the dashboard.  If revoked, Okta redirects to login.
            try:
                self._page.reload(wait_until="domcontentloaded", timeout=15000)
            except Exception as e:
                # Navigation failure may itself indicate session invalidation
                print(f"  [{elapsed}s] Page reload failed: {e}")
                return {
                    "terminated": True,
                    "elapsed": elapsed,
                    "final_url": self._page.url,
                    "reason": f"reload_error: {e}",
                }

            current_url = self._page.url.lower()

            # Check 1: URL contains a login-page path fragment
            for pattern in self.LOGIN_URL_PATTERNS:
                if pattern in current_url:
                    print(f"  [{elapsed}s] Session terminated — redirected to login")
                    # Brief pause so the login page fully renders in the video
                    time.sleep(3)
                    return {
                        "terminated": True,
                        "elapsed": elapsed,
                        "final_url": self._page.url,
                        "reason": "login_redirect",
                    }

            # Check 2: Page body text indicates session expiry (OIE fallback)
            try:
                body_text = self._page.text_content("body", timeout=3000) or ""
                body_lower = body_text.lower()
                for text in self.SESSION_EXPIRED_TEXT:
                    if text in body_lower:
                        print(f"  [{elapsed}s] Session terminated — page says '{text}'")
                        # Brief pause so the message is visible in the video
                        time.sleep(3)
                        return {
                            "terminated": True,
                            "elapsed": elapsed,
                            "final_url": self._page.url,
                            "reason": f"page_content: {text}",
                        }
            except Exception:
                pass

            print(f"  [{elapsed}s] Session still active — {self._page.url}")

        print(f"  Timeout reached ({timeout}s) — session was NOT terminated")
        return {
            "terminated": False,
            "elapsed": timeout,
            "final_url": self._page.url,
            "reason": "timeout",
        }

    # -----------------------------------------------------------------------
    # Cleanup
    # -----------------------------------------------------------------------

    def close(self) -> Optional[str]:
        """Close browser and finalize video. Returns video file path or None.

        Playwright writes the video file only when the browser context is closed,
        so this method must be called to get a usable ``.webm`` file.
        """
        if self._closed:
            return None
        self._closed = True

        # Capture the video path *before* closing the context (closing
        # finalizes the file but the path object may become invalid after).
        video_path = None
        try:
            if self._page.video:
                video_path = self._page.video.path()
        except Exception:
            pass

        # Close in order: context (finalizes video), browser, playwright
        try:
            self._context.close()
        except Exception:
            pass
        try:
            self._browser.close()
        except Exception:
            pass
        # Only stop the Playwright instance if this session owns it.
        # Attacker sessions share the victim's Playwright instance.
        if self._owns_pw:
            try:
                self._pw.stop()
            except Exception:
                pass

        if video_path:
            print(f"  Video saved: {video_path}")
        return str(video_path) if video_path else None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# ---------------------------------------------------------------------------
# AWS SSM Parameter Store Helper
# ---------------------------------------------------------------------------

def get_ssm_parameter(name: str, region: str = "us-east-2", profile: str = None) -> str:
    """Retrieve a SecureString parameter from AWS SSM Parameter Store.

    Used to fetch the demo user's password and TOTP secret at runtime,
    avoiding hardcoded credentials.

    Args:
        name: SSM parameter name (e.g., "/demo/itp/password").
        region: AWS region where the parameter is stored.
        profile: Optional AWS CLI profile name for cross-account access.
    """
    import boto3
    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(region_name=region, **session_kwargs)
    ssm = session.client("ssm")

    response = ssm.get_parameter(Name=name, WithDecryption=True)
    return response["Parameter"]["Value"]


# ---------------------------------------------------------------------------
# Main Authenticator Class
# ---------------------------------------------------------------------------

class SessionAuthenticator:
    """Authenticates to Okta via headless browser and captures session cookies.

    This class encapsulates the full victim-side authentication flow for the
    ITP demo, including one-time and persistent session modes, video recording,
    and an attacker-browser simulation.
    """

    # -- User-Agent strings ---------------------------------------------------
    # The victim and attacker use distinctly different user-agents so that
    # Okta ITP can detect the device mismatch as part of the anomaly signal.

    # Victim user-agent (Mac Chrome — represents the legitimate user's device)
    VICTIM_UA = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    # Attacker user-agent (Windows Firefox — visibly different from victim,
    # representing a different OS + browser combination from another location)
    ATTACKER_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
        "Gecko/20100101 Firefox/121.0"
    )

    def __init__(self, org_name: str, base_url: str = "okta.com"):
        """
        Args:
            org_name: Okta org subdomain (e.g., "yourorg" for yourorg.okta.com).
            base_url: Okta base domain (e.g., "okta.com" or "oktapreview.com").
        """
        self.org_name = org_name
        self.base_url = base_url
        self.okta_url = f"https://{org_name}.{base_url}"

    # ===================================================================
    # PUBLIC API — Authentication Entry Points
    # ===================================================================

    def authenticate(self, username: str, password: str,
                     totp_secret: Optional[str] = None,
                     timeout: int = 30000,
                     record_video: Optional[str] = None) -> Dict:
        """
        Authenticate to Okta and capture session cookie (one-time mode).

        Prefers browser-based auth (captures ``idx`` cookie needed for ITP
        detection). Falls back to API-based auth (captures ``sid`` only) if
        the browser flow fails.

        The browser is closed after the cookie is captured; the video (if
        recorded) is finalized immediately.

        Args:
            username: Okta username (email).
            password: User's password.
            totp_secret: Base32-encoded TOTP secret for MFA (optional).
            timeout: Playwright default timeout in milliseconds.
            record_video: Directory path to save video recording of the browser
                          session. If None, no video is recorded.

        Returns:
            Dict with keys: status, cookie_name, cookie, domain, user_agent,
            url, and optionally video_path.
        """
        # Try browser-based auth first (captures idx -- required for ITP detection)
        result = self._authenticate_via_browser(
            username, password, totp_secret, timeout, record_video=record_video
        )
        if result["status"] == "success":
            return result

        # Fallback: API-based auth produces a sid cookie, which is less
        # reliable for triggering ITP but still usable.
        print("  Browser auth failed, falling back to API-based auth...")
        api_result = self._authenticate_via_api(username, password, totp_secret)
        # Preserve video_path from the browser attempt (video was saved even on failure)
        if result.get("video_path") and not api_result.get("video_path"):
            api_result["video_path"] = result["video_path"]
        return api_result

    # ===================================================================
    # FALLBACK — API-Based Authentication (sid cookie)
    # ===================================================================

    def _authenticate_via_api(self, username: str, password: str,
                               totp_secret: Optional[str] = None) -> Dict:
        """
        Authenticate via Okta Authn API and capture session cookie via redirect.

        This is the fallback path when browser-based auth fails. It uses the
        classic Okta authentication flow:

        1. POST to ``/api/v1/authn`` with username/password to get a sessionToken.
        2. Handle MFA if required (TOTP via ``/api/v1/authn/factors/{id}/verify``).
        3. Exchange the sessionToken for a ``sid`` cookie via
           ``/login/sessionCookieRedirect``.

        Note: This produces a ``sid`` cookie, not ``idx``. The ``sid`` cookie
        may not trigger ITP session-hijacking detection as reliably because
        ``idx`` is the OIE-specific session token that ITP monitors.
        """
        import requests as req

        print(f"Authenticating as {username} to {self.okta_url} (API mode)...")

        # ----- Step 1: Primary authentication --------------------------------
        print("  Authenticating with Authn API...")
        authn_resp = req.post(
            f"{self.okta_url}/api/v1/authn",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )

        if authn_resp.status_code != 200:
            error = authn_resp.json().get("errorSummary", authn_resp.text)
            print(f"  Authentication failed: {error}")
            return {"status": "error", "error": error}

        authn_data = authn_resp.json()
        status = authn_data.get("status")

        # ----- Step 2: Handle MFA if the org requires it ---------------------
        if status == "MFA_REQUIRED":
            if not totp_secret:
                return {"status": "error", "error": "MFA required but no TOTP secret provided"}

            try:
                import pyotp
            except ImportError:
                return {"status": "error", "error": "pyotp not installed"}

            state_token = authn_data["stateToken"]
            factors = authn_data.get("_embedded", {}).get("factors", [])

            # Find the TOTP factor among all enrolled factors
            totp_factor = None
            for f in factors:
                # "token:software:totp" covers Okta Verify TOTP and Google Authenticator
                if f.get("factorType") == "token:software:totp":
                    totp_factor = f
                    break

            if not totp_factor:
                return {"status": "error", "error": "No TOTP factor enrolled"}

            print("  Verifying TOTP factor...")
            code = pyotp.TOTP(totp_secret).now()
            # The factor's verify URL is provided via HAL _links
            verify_url = totp_factor["_links"]["verify"]["href"]
            verify_resp = req.post(
                verify_url,
                json={"stateToken": state_token, "passCode": code},
                headers={"Content-Type": "application/json"},
            )

            if verify_resp.status_code != 200:
                error = verify_resp.json().get("errorSummary", verify_resp.text)
                return {"status": "error", "error": f"MFA verification failed: {error}"}

            authn_data = verify_resp.json()
            status = authn_data.get("status")

        if status != "SUCCESS":
            return {"status": "error", "error": f"Unexpected auth status: {status}"}

        session_token = authn_data["sessionToken"]
        print(f"  Got session token ({len(session_token)} chars)")

        # ----- Step 3: Exchange sessionToken for sid cookie ------------------
        # The sessionCookieRedirect endpoint sets the sid cookie via a 302
        # redirect chain.  We follow the redirects and extract the cookie.
        print("  Exchanging token for session cookie...")
        redirect_url = (
            f"{self.okta_url}/login/sessionCookieRedirect"
            f"?token={session_token}"
            f"&redirectUrl={self.okta_url}/app/UserHome"
        )

        session = req.Session()
        # Use the victim's user-agent so the session looks consistent
        session.headers.update({"User-Agent": self.VICTIM_UA})
        resp = session.get(redirect_url, allow_redirects=True)

        # Extract sid cookie — try with domain filter first, then without
        sid = session.cookies.get("sid", domain=f"{self.org_name}.{self.base_url}")
        if not sid:
            # Some Okta configurations set cookies on a different domain variant
            for cookie in session.cookies:
                if cookie.name == "sid":
                    sid = cookie.value
                    break

        if not sid:
            print("  No sid cookie found in response")
            return {"status": "error", "error": "No sid cookie after redirect"}

        result = {
            "status": "success",
            "cookie_name": "sid",
            "cookie": sid,
            "domain": f"{self.org_name}.{self.base_url}",
            "user_agent": self.VICTIM_UA,
            "url": str(resp.url),
        }

        print(f"  Captured sid cookie ({len(sid)} chars)")
        print(f"     Domain: {result['domain']}")
        return result

    # ===================================================================
    # BROWSER LOGIN — Shared Playwright Login Logic
    # ===================================================================

    def _do_browser_login(self, page, context, username: str, password: str,
                          totp_secret: Optional[str] = None) -> Optional[Dict]:
        """Shared browser login logic: username -> password -> TOTP -> cookie capture.

        This method drives the Okta Identity Engine (OIE) sign-in widget through
        each step of the authentication flow.  It is called by both one-time
        (``_authenticate_via_browser``) and persistent (``authenticate_persistent``)
        modes.

        Returns:
            The captured cookie dict (from Playwright's ``context.cookies()``)
            containing name, value, domain, etc.  Returns None if no session
            cookie was found after login.
        """
        # ----- Navigate to Okta login page -----------------------------------
        print("  Navigating to login page...")
        page.goto(self.okta_url)

        # ----- Username entry ------------------------------------------------
        # OIE sign-in widget: the username field uses name="identifier"
        print("  Entering username...")
        page.wait_for_selector('input[name="identifier"]', state="visible")
        page.fill('input[name="identifier"]', username)
        # Click the submit button to advance to the next step (password or
        # authenticator selection, depending on org config)
        page.click('input[type="submit"], button[type="submit"]')

        # ----- Password entry ------------------------------------------------
        # Wait for the password field to appear.  OIE has multiple possible
        # selectors depending on whether the org uses authenticator selection:
        #   - input[name="credentials.passcode"] — direct password prompt
        #   - input[type="password"] — classic password field
        #   - [data-se="okta_password"] — authenticator selection screen
        print("  Waiting for password prompt...")
        page.wait_for_selector(
            'input[name="credentials.passcode"], input[type="password"], '
            '[data-se="okta_password"]',
            state="visible",
            timeout=10000
        )

        # OIE authenticator selection screen — if present, the user must first
        # click "Select" next to the Password authenticator before the password
        # input appears.  The data-se="okta_password" attribute identifies the
        # Password authenticator card in the selection list.
        password_select = page.query_selector('[data-se="okta_password"]')
        if password_select:
            print("  Selecting Password authenticator...")
            # Look for a "Select" button within the authenticator card
            select_btn = password_select.query_selector('button, [data-se="select-button"]')
            if select_btn:
                select_btn.click()
            else:
                # Fallback: click the card itself
                password_select.click()
            # Wait for the actual password input to appear after selection
            page.wait_for_selector(
                'input[name="credentials.passcode"], input[type="password"]',
                state="visible"
            )

        print("  Entering password...")
        # Try the OIE-specific field name first, fall back to generic type selector
        password_input = page.query_selector(
            'input[name="credentials.passcode"]'
        ) or page.query_selector('input[type="password"]')
        password_input.fill(password)
        page.click('input[type="submit"], button[type="submit"]')

        # ----- TOTP MFA handling (if secret provided) ------------------------
        if totp_secret:
            self._handle_totp(page, totp_secret)

        # ----- Cookie capture ------------------------------------------------
        # After successful auth, OIE performs an OAuth/OIDC redirect flow that
        # sets the idx cookie.  We poll for up to 30 seconds waiting for it.
        print("  Waiting for authentication to complete...")
        idx_cookie = None
        for i in range(30):
            time.sleep(1)  # 1-second poll interval
            cookies = context.cookies()
            # Primary target: the idx cookie (OIE session token used by ITP)
            for cookie in cookies:
                if cookie["name"] == "idx":
                    idx_cookie = cookie
                    break
            if idx_cookie:
                print(f"  idx cookie captured after {i+1}s")
                break

            # If we've landed on the dashboard but idx hasn't appeared yet,
            # grab sid or JSESSIONID as a fallback (less ideal for ITP but
            # still represents a valid session).
            current_url = page.url
            if "/enduser/" in current_url or "/app/UserHome" in current_url:
                # On dashboard but no idx yet — grab what we can
                for name in ["sid", "JSESSIONID"]:
                    for cookie in cookies:
                        if cookie["name"] == name:
                            idx_cookie = cookie
                            break
                    if idx_cookie:
                        break
                break

        if not idx_cookie:
            # Debug: list all cookies so we can diagnose what went wrong
            cookies = context.cookies()
            print("  No IDX/SID cookie found. Available cookies:")
            for c in cookies:
                print(f"     {c['name']}: {c['domain']}")
            return None

        print(f"  Captured {idx_cookie['name']} cookie ({len(idx_cookie['value'])} chars)")
        print(f"     Domain: {idx_cookie['domain']}")
        return idx_cookie

    # ===================================================================
    # MFA HANDLING — TOTP Challenge in the Browser
    # ===================================================================

    def _handle_totp(self, page, totp_secret: str):
        """Handle TOTP MFA challenge in the browser.

        OIE has a multi-step TOTP flow:
        1. The password field disappears after submission.
        2. Either a TOTP input appears directly, or an authenticator selection
           screen appears where the user must click "Select" next to Okta Verify
           TOTP before the code input shows.
        3. The TOTP code is filled in and submitted.
        """
        print("  Handling TOTP MFA challenge...")
        import pyotp

        totp = pyotp.TOTP(totp_secret)

        # Wait for the password field to disappear before looking for the TOTP
        # input.  OIE reuses input[name="credentials.passcode"] for the password
        # but uses input[name="credentials.totp"] for the TOTP code.  If we
        # don't wait for the password field to go away, we might accidentally
        # fill the TOTP code into the password field.
        try:
            page.wait_for_selector(
                'input[name="credentials.passcode"]',
                state="hidden",
                timeout=5000
            )
        except Exception:
            pass  # May already be gone

        # Wait for either the TOTP input or the authenticator selection screen.
        # data-se="okta_verify-totp" is the OIE authenticator card for TOTP.
        page.wait_for_selector(
            'input[name="credentials.totp"], '
            '[data-se="okta_verify-totp"]',
            state="visible",
            timeout=15000  # 15s — allows time for OIE transitions/animations
        )

        # If the authenticator selector is shown, click "Select" to proceed
        # to the actual TOTP code input.
        totp_select = page.query_selector('[data-se="okta_verify-totp"]')
        if totp_select:
            print("  Selecting Okta Verify TOTP authenticator...")
            select_btn = totp_select.query_selector('button, [data-se="select-button"]')
            if select_btn:
                select_btn.click()
            else:
                totp_select.click()
            # Wait for the TOTP input to appear after authenticator selection
            page.wait_for_selector(
                'input[name="credentials.totp"]',
                state="visible",
                timeout=10000
            )

        # Generate the current TOTP code
        code = totp.now()
        print(f"  Entering TOTP code: {code}")

        # Fill the TOTP input field
        totp_input = page.query_selector('input[name="credentials.totp"]')
        if totp_input:
            totp_input.fill(code)
        else:
            # Fallback: find any visible text/tel/number input that is not the
            # username field.  This handles edge cases where OIE uses a different
            # input name than expected.
            for inp in page.query_selector_all('input'):
                inp_type = inp.evaluate('el => el.type')
                inp_vis = inp.evaluate('el => el.offsetParent !== null')
                inp_name = inp.evaluate('el => el.name')
                if inp_vis and inp_type in ('text', 'tel', 'number') and inp_name != 'identifier':
                    print(f"  Fallback: filling input name={inp_name!r}")
                    inp.fill(code)
                    break

        # Submit the TOTP code.  OIE may use different button types depending
        # on the widget version: input[type=submit], button[type=submit], or
        # button[data-type=save].
        page.click('input[type="submit"], button[type="submit"], button[data-type="save"]')

    # ===================================================================
    # ONE-TIME BROWSER AUTH (captures cookie, closes browser)
    # ===================================================================

    def _authenticate_via_browser(self, username: str, password: str,
                                   totp_secret: Optional[str] = None,
                                   timeout: int = 30000,
                                   record_video: Optional[str] = None) -> Dict:
        """Authenticate via Playwright headless browser (one-time mode).

        Opens a headless Chromium browser, performs the full Okta login flow,
        captures the session cookie, and closes the browser.  If ``record_video``
        is set, Playwright records the session as a ``.webm`` file (finalized
        when the browser context closes).

        Args:
            username: Okta username.
            password: User's password.
            totp_secret: Base32 TOTP secret for MFA (optional).
            timeout: Playwright default timeout in milliseconds.
            record_video: Directory path to save video recording. If provided,
                          Playwright records the browser session as a .webm file.

        Returns:
            Dict with status, cookie info, and optionally video_path.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            print("Error: playwright is required. Install with:")
            print("  pip install playwright && playwright install chromium")
            return {"status": "error", "error": "playwright not installed"}

        print(f"Authenticating as {username} to {self.okta_url}...")
        if record_video:
            print(f"  Recording video to: {record_video}")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context_opts = {"user_agent": self.VICTIM_UA}
            if record_video:
                os.makedirs(record_video, exist_ok=True)
                # Playwright video recording config — 720p gives a good balance
                # between readability and file size for demo videos.
                context_opts["record_video_dir"] = record_video
                context_opts["record_video_size"] = {"width": 1280, "height": 720}
            context = browser.new_context(**context_opts)
            page = context.new_page()
            page.set_default_timeout(timeout)

            try:
                idx_cookie = self._do_browser_login(
                    page, context, username, password, totp_secret
                )

                if not idx_cookie:
                    # Auth succeeded but no usable cookie — capture video path
                    # before closing for debugging purposes.
                    video_path = None
                    if record_video:
                        try:
                            if page.video:
                                video_path = page.video.path()
                        except Exception:
                            pass
                    # Close context first (finalizes video), then browser
                    context.close()
                    browser.close()
                    if video_path:
                        print(f"  Video saved: {video_path}")
                    return {
                        "status": "error",
                        "error": "Session cookie not found",
                        "video_path": str(video_path) if video_path else None,
                    }

                result = {
                    "status": "success",
                    "cookie_name": idx_cookie["name"],
                    "cookie": idx_cookie["value"],
                    "domain": idx_cookie["domain"],
                    "user_agent": self.VICTIM_UA,
                    "url": page.url,
                }

                # Capture video path before closing — Playwright finalizes the
                # video file when context.close() is called.
                video_path = None
                if record_video and page.video:
                    video_path = page.video.path()
                context.close()
                browser.close()
                if video_path:
                    print(f"  Video saved: {video_path}")
                    result["video_path"] = str(video_path)
                return result

            except Exception as e:
                print(f"  Authentication failed: {e}")
                # Save a screenshot for debugging (helps diagnose DOM changes)
                try:
                    page.screenshot(path="/tmp/itp-auth-failure.png")
                    print("     Screenshot saved to /tmp/itp-auth-failure.png")
                except Exception:
                    pass
                video_path = None
                if record_video:
                    try:
                        if page.video:
                            video_path = page.video.path()
                    except Exception:
                        pass
                context.close()
                browser.close()
                if video_path:
                    print(f"  Video saved: {video_path}")
                return {
                    "status": "error",
                    "error": str(e),
                    "video_path": str(video_path) if video_path else None,
                }

    # ===================================================================
    # PERSISTENT BROWSER AUTH (keeps browser open for continuous recording)
    # ===================================================================

    def authenticate_persistent(self, username: str, password: str,
                                totp_secret: Optional[str] = None,
                                timeout: int = 30000,
                                record_video: Optional[str] = None) -> "BrowserSession":
        """Authenticate and return a BrowserSession with the browser still open.

        Unlike ``authenticate()``, the browser stays open so the video captures
        the full demo lifecycle: login -> dashboard -> attacker replay -> ULO
        session termination (redirect back to login page).

        After authentication, the browser navigates to the Okta dashboard
        (``/app/UserHome``) so the video shows the user is logged in.

        Args:
            username: Okta username.
            password: User's password.
            totp_secret: Base32 TOTP secret for MFA (optional).
            timeout: Playwright default timeout in milliseconds.
            record_video: Directory path for video recording (required for
                          continuous video capture).

        Returns:
            BrowserSession wrapping the open browser.

        Raises:
            AuthenticationError: If browser auth fails.
            ImportError: If playwright is not installed.
        """
        from playwright.sync_api import sync_playwright

        print(f"Authenticating as {username} to {self.okta_url} (persistent session)...")
        if record_video:
            print(f"  Recording video to: {record_video}")

        # Start Playwright *without* the context manager so it stays alive
        # after this method returns.  The BrowserSession.close() method will
        # stop it later when the demo is complete.
        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=True)
        context_opts = {"user_agent": self.VICTIM_UA}
        if record_video:
            os.makedirs(record_video, exist_ok=True)
            context_opts["record_video_dir"] = record_video
            context_opts["record_video_size"] = {"width": 1280, "height": 720}
        context = browser.new_context(**context_opts)
        page = context.new_page()
        page.set_default_timeout(timeout)

        try:
            idx_cookie = self._do_browser_login(
                page, context, username, password, totp_secret
            )

            if not idx_cookie:
                # Clean up all resources and raise
                video_path = None
                try:
                    if page.video:
                        video_path = page.video.path()
                except Exception:
                    pass
                context.close()
                browser.close()
                pw.stop()
                raise AuthenticationError(
                    "Session cookie not found",
                    video_path=str(video_path) if video_path else None,
                )

            # Navigate to the Okta dashboard so the video shows the logged-in
            # state before the attacker replay happens.
            print("  Navigating to dashboard...")
            try:
                page.goto(f"{self.okta_url}/app/UserHome", wait_until="domcontentloaded")
                # Brief pause to let the dashboard render fully in the video
                time.sleep(2)
                print(f"  Dashboard loaded: {page.url}")
            except Exception as e:
                print(f"  Dashboard navigation note: {e}")

            auth_result = {
                "status": "success",
                "cookie_name": idx_cookie["name"],
                "cookie": idx_cookie["value"],
                "domain": idx_cookie["domain"],
                "user_agent": self.VICTIM_UA,
                "url": page.url,
            }

            return BrowserSession(pw, browser, context, page, auth_result)

        except AuthenticationError:
            raise
        except Exception as e:
            print(f"  Authentication failed: {e}")
            # Save screenshot for debugging
            try:
                page.screenshot(path="/tmp/itp-auth-failure.png")
                print("     Screenshot saved to /tmp/itp-auth-failure.png")
            except Exception:
                pass
            video_path = None
            try:
                if page.video:
                    video_path = page.video.path()
            except Exception:
                pass
            context.close()
            browser.close()
            pw.stop()
            raise AuthenticationError(
                str(e),
                video_path=str(video_path) if video_path else None,
            )

    # ===================================================================
    # VIDEO RECORDING — Attacker Terminal Animation & Cookie Inspector
    # ===================================================================

    def _build_terminal_html(self, cookie_name: str, cookie_value: str,
                             domain: str) -> str:
        """Build an HTML page that animates the attacker injecting a stolen cookie.

        Renders a terminal-style UI with typed-out commands showing the cookie
        being pasted into the browser's cookie jar. Designed to be visually
        compelling in demo recordings.

        The animation uses CSS opacity transitions with data-delay attributes
        on each line to simulate typing. The full animation runs ~8 seconds
        (last line appears at 7.4s delay).

        Args:
            cookie_name: Name of the stolen cookie (e.g., "idx").
            cookie_value: Full cookie value (truncated for display).
            domain: Cookie domain (e.g., "yourorg.okta.com").

        Returns:
            Complete HTML document string.
        """
        # Truncate cookie for display — full value is too long and unreadable
        display_cookie = cookie_value[:40] + "..." + cookie_value[-12:]
        import html as html_mod
        safe_cookie = html_mod.escape(display_cookie)
        safe_domain = html_mod.escape(domain)
        safe_name = html_mod.escape(cookie_name)
        safe_full_cookie = html_mod.escape(cookie_value[:60]) + "..."

        return f'''<!DOCTYPE html>
<html><head><style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #0a0a0a; color: #00ff41; font-family: 'Courier New', monospace;
       font-size: 15px; padding: 30px 40px; line-height: 1.7; }}
.prompt {{ color: #ff3333; }}
.cmd {{ color: #00ff41; }}
.comment {{ color: #666; }}
.output {{ color: #ccc; }}
.success {{ color: #00ff41; font-weight: bold; }}
.warn {{ color: #ffaa00; }}
.cookie-val {{ color: #00ccff; word-break: break-all; }}
.cursor {{ display: inline-block; width: 8px; height: 16px; background: #00ff41;
           animation: blink 0.7s step-end infinite; vertical-align: text-bottom; }}
@keyframes blink {{ 50% {{ opacity: 0; }} }}
.line {{ opacity: 0; white-space: pre-wrap; }}
.line.visible {{ opacity: 1; }}
.header {{ color: #ff3333; font-size: 13px; margin-bottom: 20px; border-bottom: 1px solid #333;
           padding-bottom: 10px; }}
.badge {{ display: inline-block; background: #ff3333; color: #fff; padding: 2px 8px;
          border-radius: 3px; font-size: 11px; margin-left: 10px; }}
</style></head><body>
<div class="header">
  ATTACKER WORKSTATION<span class="badge">SESSION HIJACK</span>
  <span style="float:right; color:#666">Firefox 121.0 / Windows 10 / EU-WEST-1</span>
</div>
<div id="terminal">
<div class="line" data-delay="300"><span class="comment"># Stolen session cookie received from malware C2 callback</span></div>
<div class="line" data-delay="800"><span class="comment"># Target: {safe_domain}</span></div>
<div class="line" data-delay="1400"><span class="prompt">attacker@eu-west-1:~$ </span><span class="cmd">echo $STOLEN_COOKIE</span></div>
<div class="line" data-delay="2200"><span class="cookie-val">{safe_cookie}</span></div>
<div class="line" data-delay="3200">&nbsp;</div>
<div class="line" data-delay="3400"><span class="comment"># Injecting cookie into browser storage...</span></div>
<div class="line" data-delay="4000"><span class="prompt">attacker@eu-west-1:~$ </span><span class="cmd">document.cookie = "{safe_name}={safe_full_cookie}; domain={safe_domain}; path=/; secure"</span></div>
<div class="line" data-delay="5200"><span class="success">✓ Cookie injected successfully</span></div>
<div class="line" data-delay="5800">&nbsp;</div>
<div class="line" data-delay="6000"><span class="comment"># Navigating to target — no credentials needed</span></div>
<div class="line" data-delay="6600"><span class="prompt">attacker@eu-west-1:~$ </span><span class="cmd">open https://{safe_domain}/app/UserHome</span></div>
<div class="line" data-delay="7400"><span class="warn">⏳ Redirecting to Okta dashboard...</span></div>
</div>
<script>
const lines = document.querySelectorAll('.line');
lines.forEach(line => {{
  const delay = parseInt(line.dataset.delay) || 0;
  setTimeout(() => line.classList.add('visible'), delay);
}});
</script>
</body></html>'''

    def _build_cookie_inspector_js(self, cookie_name: str, cookie_value: str,
                                    domain: str) -> str:
        """Build an HTML page that renders a DevTools-style cookie inspector overlay.

        Shown after the attacker lands on the Okta dashboard, proving the
        stolen cookie is present in the browser.  Styled to resemble Chrome
        DevTools "Application > Cookies" panel.

        This is rendered as a separate page (not an overlay on Okta's page)
        because Playwright's headless video capture cannot reliably render
        injected overlays on Okta's page (Okta's CSS strips custom styles,
        and iframes/shadow DOM don't appear in the video).  A standalone page
        gives full CSS control and tells a clear "attacker opened DevTools" story.

        Args:
            cookie_name: Name of the stolen cookie (e.g., "idx").
            cookie_value: Full cookie value (truncated for display).
            domain: Cookie domain (e.g., "yourorg.okta.com").

        Returns:
            Complete HTML document string styled like Chrome DevTools.
        """
        import html as html_mod
        # Show enough of the cookie to be recognizable but not overwhelming
        display_val = cookie_value[:64] + "..." + cookie_value[-16:]
        safe_val = html_mod.escape(display_val).replace("'", "\\'")
        safe_name = html_mod.escape(cookie_name).replace("'", "\\'")
        safe_domain = html_mod.escape(domain).replace("'", "\\'")

        # Return a full HTML page (not JS) — rendered via set_content() after
        # the attacker visits the dashboard. Overlays on Okta's page don't work
        # in Playwright video (Okta's CSS strips styles, iframes/shadow DOM
        # don't render in headless video capture). A separate page gives us full
        # CSS control and tells a clear "attacker opened DevTools" story.
        return f'''<!DOCTYPE html>
<html><head><style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:#1e1e1e; font-family:'Courier New',monospace; font-size:13px; color:#d4d4d4; }}
.toolbar {{ background:#2d2d2d; padding:8px 16px; display:flex; align-items:center;
            border-bottom:1px solid #404040; font-size:12px; }}
.toolbar .tab {{ background:#1e1e1e; color:#fff; padding:6px 16px; border-radius:4px 4px 0 0;
                margin-right:4px; font-size:11px; }}
.toolbar .tab.active {{ border-bottom:2px solid #3b82f6; }}
.toolbar .tab.dim {{ color:#666; background:transparent; }}
.panel-header {{ background:#252525; padding:8px 16px; display:flex; align-items:center;
                 border-bottom:1px solid #404040; }}
.panel-header .title {{ color:#ff3333; font-weight:bold; margin-right:10px; font-size:13px; }}
.panel-header .path {{ color:#888; margin-right:4px; }}
.panel-header .domain {{ color:#fff; }}
.badge {{ margin-left:auto; background:#ff3333; color:#fff; padding:3px 10px;
          border-radius:3px; font-size:11px; font-weight:bold; letter-spacing:0.5px; }}
.url-bar {{ background:#1a1a1a; padding:6px 16px; color:#888; border-bottom:1px solid #333;
            font-size:11px; }}
.url-bar span {{ color:#00ff41; }}
table {{ width:100%; border-collapse:collapse; margin-top:0; }}
th {{ padding:8px 14px; border-bottom:1px solid #404040; text-align:left;
     color:#888; background:#252525; font-weight:normal; font-size:12px; }}
td {{ padding:8px 14px; color:#777; font-size:12px; }}
tr.stolen {{ background:#1a2332; border-left:3px solid #ff3333; }}
tr.stolen td:first-child {{ color:#ff3333; font-weight:bold; }}
tr.stolen .val {{ color:#00ccff; word-break:break-all; }}
tr.stolen .dm {{ color:#d4d4d4; }}
.ok {{ color:#00ff41; }}
tr:not(.stolen) {{ border-bottom:1px solid #2a2a2a; }}
</style></head><body>
<div class="toolbar">
  <span class="tab dim">Elements</span>
  <span class="tab dim">Console</span>
  <span class="tab dim">Network</span>
  <span class="tab active">Application</span>
  <span class="tab dim">Security</span>
</div>
<div class="panel-header">
  <span class="title">Cookies</span>
  <span class="path">https://</span><span class="domain">{safe_domain}</span>
  <span class="badge">STOLEN SESSION</span>
</div>
<div class="url-bar">Accessed <span>https://{safe_domain}/app/UserHome</span> &mdash; no credentials required</div>
<table>
  <thead><tr>
    <th style="width:90px">Name</th><th>Value</th><th style="width:170px">Domain</th>
    <th style="width:50px">Path</th><th style="width:65px">Secure</th><th style="width:75px">HttpOnly</th>
  </tr></thead>
  <tbody>
    <tr class="stolen">
      <td>{safe_name}</td><td class="val">{safe_val}</td>
      <td class="dm">{safe_domain}</td><td class="dm">/</td>
      <td class="ok">&#10003;</td><td class="ok">&#10003;</td>
    </tr>
    <tr><td>JSESSIONID</td><td>&mdash;</td><td>{safe_domain}</td><td>/</td>
      <td>&#10003;</td><td>&#10003;</td></tr>
    <tr><td>t</td><td>&mdash;</td><td>{safe_domain}</td><td>/</td>
      <td>&#10003;</td><td>&#10007;</td></tr>
    <tr><td>_okta_throttle</td><td>&mdash;</td><td>{safe_domain}</td><td>/</td>
      <td>&#10003;</td><td>&#10007;</td></tr>
  </tbody>
</table>
</body></html>'''

    # ===================================================================
    # ATTACKER BROWSER — Cookie Injection & Session Replay
    # ===================================================================

    def open_attacker_session(self, cookie_name: str, cookie_value: str,
                              domain: str,
                              victim_session: "BrowserSession",
                              record_video: Optional[str] = None) -> "BrowserSession":
        """Open a browser as the attacker: inject stolen cookie, navigate to Okta.

        Simulates what a real attacker does — paste the stolen session cookie
        into a browser and navigate to the target site. No credentials needed.
        The attacker lands directly on the dashboard.

        When recording video, the flow is:
        1. Terminal animation showing the cookie injection command
        2. Navigate to Okta dashboard (attacker is "in" without credentials)
        3. DevTools-style cookie inspector overlay (shows stolen cookie)
        4. Return to Okta dashboard (for ULO detection in the video)

        Uses the same Playwright instance as the victim session because
        Playwright only allows one sync instance per process.

        Args:
            cookie_name: Name of the stolen cookie (e.g., "idx").
            cookie_value: Value of the stolen cookie.
            domain: Cookie domain (e.g., "yourorg.okta.com").
            victim_session: The victim's BrowserSession (shares Playwright instance).
            record_video: Directory path for video recording.

        Returns:
            BrowserSession wrapping the attacker's browser.  The returned session
            has ``owns_pw=False`` so closing it does not stop the shared Playwright
            instance.
        """
        print(f"  Opening attacker browser (cookie injection)...")
        if record_video:
            print(f"  Recording attacker video to: {record_video}")

        # Reuse the victim's Playwright instance — Playwright only allows one
        # sync API instance per process.  The attacker gets its own browser
        # and context (with a different user-agent) but shares the pw runtime.
        pw = victim_session._pw
        browser = pw.chromium.launch(headless=True)
        context_opts = {"user_agent": self.ATTACKER_UA}
        if record_video:
            os.makedirs(record_video, exist_ok=True)
            context_opts["record_video_dir"] = record_video
            context_opts["record_video_size"] = {"width": 1280, "height": 720}
        context = browser.new_context(**context_opts)

        # Inject the stolen cookie into the attacker's browser context.
        # This is exactly what a real attacker does — no login required.
        context.add_cookies([{
            "name": cookie_name,
            "value": cookie_value,
            "domain": domain,
            "path": "/",
        }])
        print(f"  Injected stolen {cookie_name} cookie into attacker browser")

        page = context.new_page()
        page.set_default_timeout(30000)

        # ----- Video: Terminal animation of cookie injection -----------------
        # Show a cinematic terminal UI that "types out" the cookie injection
        # commands, making the attack visible in the demo recording.
        if record_video:
            try:
                print(f"  Playing cookie injection terminal animation...")
                terminal_html = self._build_terminal_html(
                    cookie_name, cookie_value, domain
                )
                # Use set_content (not a data: URL) because data: URLs truncate
                # large HTML payloads in Playwright.
                page.set_content(terminal_html, wait_until="domcontentloaded")
                # Wait 9 seconds for the full animation to play out.
                # The last line in the terminal appears at 7.4s delay, plus
                # ~1.5s buffer for the viewer to read the final line.
                time.sleep(9)
            except Exception as e:
                print(f"  Terminal animation note: {e}")

        # ----- Navigate to Okta dashboard as the attacker --------------------
        # With the stolen cookie injected, the attacker should land directly
        # on the dashboard without any login prompt.
        try:
            print(f"  Attacker navigating to {self.okta_url}/app/UserHome...")
            page.goto(f"{self.okta_url}/app/UserHome", wait_until="domcontentloaded")
            # Brief pause to let the dashboard render in the video
            time.sleep(2)
            current_url = page.url
            print(f"  Attacker landed on: {current_url}")

            # Verify the attacker got in (not redirected to login)
            if "/login/" in current_url.lower() or "/signin/" in current_url.lower():
                print(f"  Attacker was redirected to login — cookie may already be invalid")
            else:
                print(f"  Attacker is IN — no credentials needed!")

                # ----- Video: DevTools cookie inspector ----------------------
                # Show a DevTools-style page proving the stolen cookie is in
                # the browser.  This is rendered as a separate page because
                # overlays on Okta's page don't render in Playwright's headless
                # video capture (Okta's CSS strips injected styles, and
                # iframes/shadow DOM are not captured).
                if record_video:
                    try:
                        # Pause on dashboard so the viewer sees the attacker is in
                        time.sleep(3)
                        print(f"  Showing cookie inspector (DevTools view)...")
                        inspector_html = self._build_cookie_inspector_js(
                            cookie_name, cookie_value, domain
                        )
                        # Navigate to about:blank first to clear Okta's CSS,
                        # then set_content with our own styles
                        page.goto("about:blank")
                        page.set_content(inspector_html,
                                         wait_until="domcontentloaded")
                        # 4-second pause for the viewer to read cookie details
                        time.sleep(4)

                        # Navigate back to Okta dashboard so the video can
                        # capture the session termination / ULO redirect.
                        # Without this, the page stays on about:blank and
                        # wait_for_all_terminated() cannot detect the logout.
                        print(f"  Returning to Okta dashboard for ULO detection...")
                        page.goto(f"{self.okta_url}/app/UserHome",
                                  wait_until="domcontentloaded")
                        # Brief pause to let the page settle
                        time.sleep(2)
                    except Exception as e:
                        print(f"  Cookie inspector note: {e}")
        except Exception as e:
            print(f"  Attacker navigation note: {e}")

        auth_result = {
            "status": "success",
            "cookie_name": cookie_name,
            "cookie": cookie_value,
            "domain": domain,
            "user_agent": self.ATTACKER_UA,
            "url": page.url,
            "role": "attacker",
        }

        # owns_pw=False — the attacker session shares the victim's Playwright
        # instance, so closing this session should NOT stop Playwright.
        return BrowserSession(pw, browser, context, page, auth_result, owns_pw=False)


# ---------------------------------------------------------------------------
# Multi-Session ULO Termination Watcher
# ---------------------------------------------------------------------------

def wait_for_all_terminated(sessions: dict, timeout: int = 120,
                            poll_interval: int = 5) -> Dict:
    """Watch multiple BrowserSessions for session termination (ULO detection).

    After the attacker replays the stolen cookie, Okta ITP should detect the
    anomaly and issue a Universal Logout (ULO) that terminates ALL sessions
    for the user.  This function monitors both the victim and attacker browsers
    simultaneously, detecting when each is redirected to the login page.

    Each poll cycle reloads every active session's page and checks for:
    1. URL redirect to a login page pattern
    2. Body text containing session-expired phrases
    3. Page reload failure (may indicate server-side invalidation)

    Sessions are removed from the active set as they terminate, so the
    function returns as soon as all sessions are terminated (or timeout).

    Args:
        sessions: Dict mapping label -> BrowserSession
                  (e.g., {"victim": ..., "attacker": ...})
        timeout: Max seconds to wait before giving up.
        poll_interval: Seconds between reload cycles.

    Returns:
        Dict mapping label -> termination result dict, each containing:
        terminated (bool), elapsed (int), final_url (str), reason (str).
    """
    print(f"\n  Watching {len(sessions)} browsers for session termination "
          f"({timeout}s, every {poll_interval}s)...")

    results = {}
    active = dict(sessions)  # Copy — we remove sessions as they terminate
    start = time.time()

    while time.time() - start < timeout and active:
        time.sleep(poll_interval)
        elapsed = int(time.time() - start)

        # Check each still-active session
        for label, session in list(active.items()):
            terminated = False
            reason = None

            # Reload the page to see if the session is still valid
            try:
                session.page.reload(wait_until="domcontentloaded", timeout=15000)
            except Exception as e:
                print(f"  [{elapsed}s] {label}: reload failed — {e}")
                terminated = True
                reason = f"reload_error: {e}"

            # Check 1: URL contains a login-page path fragment
            if not terminated:
                current_url = session.page.url.lower()
                for pattern in BrowserSession.LOGIN_URL_PATTERNS:
                    if pattern in current_url:
                        terminated = True
                        reason = "login_redirect"
                        break

            # Check 2: Body text indicates session expiry (OIE fallback)
            if not terminated:
                try:
                    body = session.page.text_content("body", timeout=3000) or ""
                    body_lower = body.lower()
                    for text in BrowserSession.SESSION_EXPIRED_TEXT:
                        if text in body_lower:
                            terminated = True
                            reason = f"page_content: {text}"
                            break
                except Exception:
                    pass

            if terminated:
                print(f"  [{elapsed}s] {label}: SESSION TERMINATED ({reason})")
                # Brief pause to let the login page render for the video
                time.sleep(3)
                results[label] = {
                    "terminated": True,
                    "elapsed": elapsed,
                    "final_url": session.page.url,
                    "reason": reason,
                }
                del active[label]
            else:
                print(f"  [{elapsed}s] {label}: still active")

    # Record timeout for any sessions that never terminated
    for label in active:
        print(f"  Timeout — {label}: session was NOT terminated")
        results[label] = {
            "terminated": False,
            "elapsed": timeout,
            "final_url": active[label].page.url,
            "reason": "timeout",
        }

    return results


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    """Standalone CLI for authenticating to Okta and capturing a session cookie.

    Supports fetching credentials from AWS SSM Parameter Store (for CI/CD or
    demo environments where secrets are stored centrally) or passing them
    directly via CLI arguments.
    """
    parser = argparse.ArgumentParser(
        description="Authenticate to Okta and capture session cookie"
    )
    parser.add_argument(
        "--org-name",
        default=os.environ.get("OKTA_ORG_NAME"),
        help="Okta organization name"
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("OKTA_BASE_URL", "okta.com"),
        help="Okta base URL"
    )
    parser.add_argument("--username", required=True, help="Okta username")
    parser.add_argument("--password", help="User password (or use --password-ssm)")
    parser.add_argument("--password-ssm", help="SSM parameter name for password")
    parser.add_argument("--totp-secret", help="TOTP secret (base32)")
    parser.add_argument("--totp-ssm", help="SSM parameter name for TOTP secret")
    parser.add_argument(
        "--aws-profile",
        default=os.environ.get("AWS_PROFILE"),
        help="AWS profile for SSM access"
    )
    parser.add_argument(
        "--aws-region",
        default="us-east-2",
        help="AWS region for SSM (default: us-east-2)"
    )
    parser.add_argument("--output", help="Write result JSON to file")

    args = parser.parse_args()

    if not args.org_name:
        print("Error: --org-name or OKTA_ORG_NAME must be set")
        sys.exit(1)

    # Resolve password — prefer direct arg, fall back to SSM
    password = args.password
    if not password and args.password_ssm:
        print(f"Retrieving password from SSM: {args.password_ssm}")
        password = get_ssm_parameter(args.password_ssm, args.aws_region, args.aws_profile)
    if not password:
        print("Error: --password or --password-ssm is required")
        sys.exit(1)

    # Resolve TOTP secret — prefer direct arg, fall back to SSM
    totp_secret = args.totp_secret
    if not totp_secret and args.totp_ssm:
        print(f"Retrieving TOTP secret from SSM: {args.totp_ssm}")
        totp_secret = get_ssm_parameter(args.totp_ssm, args.aws_region, args.aws_profile)

    auth = SessionAuthenticator(args.org_name, args.base_url)
    result = auth.authenticate(args.username, password, totp_secret=totp_secret)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\nResult written to {args.output}")

    if result["status"] == "success":
        print(f"\nCookie: {result['cookie'][:20]}...")
    else:
        print(f"\nError: {result.get('error')}")

    sys.exit(0 if result["status"] == "success" else 1)


if __name__ == "__main__":
    main()
