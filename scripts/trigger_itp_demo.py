#!/usr/bin/env python3
"""
trigger_itp_demo.py — Main Orchestrator for Okta ITP Demo Automation

This is the single entry point for all three Identity Threat Protection (ITP)
demo modes. It coordinates authentication, risk signal delivery, event
monitoring, and automatic cleanup across three distinct demonstration paths.

Architecture Overview
---------------------
The orchestrator (ITPDemoTrigger class) wraps the Okta admin API and delegates
to specialized modules in the ``itp/`` package:

    trigger_itp_demo.py          <-- YOU ARE HERE (CLI + orchestration)
        |
        +-- itp/session_authenticator.py   (Playwright headless login for Real mode)
        +-- itp/session_replayer.py        (Cookie replay via Lambda or local HTTP)
        +-- itp/ssf_provider.py            (JWT/SET signing and delivery for SSF mode)
        +-- monitor_itp_events.py          (Real-time Okta system log polling)

Demo Modes
----------
1. **Quick Mode** (``--mode quick``)
   - Calls ``PUT /api/v1/users/{id}/risk`` to set the user's risk score directly.
   - No extra infrastructure required — works with just an Okta API token.
   - Produces Okta system log event: ``user.risk.change``
     ("Admin reported user risk").
   - Useful for rapid policy-trigger demos without simulating real threats.

2. **Real Mode** (``--mode real``)
   - Performs a genuine session-hijacking simulation in three steps:
       (a) Authenticate as the victim via headless Playwright browser
           (captures the ``idx`` session cookie).
       (b) Replay the stolen cookie from a geographically distant AWS Lambda
           (or locally with a different User-Agent as a fallback).
       (c) Okta's ITP engine detects the impossible-travel / session anomaly.
   - Produces Okta system log event: ``security.session.detect``
     ("Session hijacking detected").
   - Optionally records side-by-side browser videos (victim + attacker)
     showing ULO (Universal Logout) terminating both sessions in real time.
   - Requires: user credentials (password + optional TOTP) stored in SSM or
     env vars, and ideally an attacker Lambda deployed in a remote AWS region.

3. **SSF Mode** (``--mode ssf``)
   - Sends a signed Security Event Token (SET / RFC 8417) to Okta's
     ``/security/api/v1/security-events`` endpoint.
   - The SET is a JWT signed with an RSA private key whose public JWKS is
     registered with Okta as an SSF provider (via ``setup_ssf_provider.py``).
   - Produces Okta system log event: ``security.events.provider.receive``
     ("Security events provider reported risk").
   - Requires: SSF provider registered, RSA key pair, config stored in SSM.

Common Features (all modes)
---------------------------
- ``--monitor``: After triggering, poll the Okta system log for ITP-related
  events and print them in real time.
- ``--auto-reset``: After the demo completes (and optional monitoring), reset
  the user's risk back to LOW so the account is ready for the next run.
- ``--monitor-duration``: Control how long the event monitor runs (seconds).

Usage Examples
--------------
    # Quick mode -- raise risk instantly
    python3 scripts/trigger_itp_demo.py --mode quick \\
        --user demo@example.com --risk-level HIGH --monitor

    # Quick mode -- reset risk back to LOW
    python3 scripts/trigger_itp_demo.py --mode quick \\
        --user demo@example.com --risk-level LOW

    # Real mode -- full session hijacking simulation with video
    python3 scripts/trigger_itp_demo.py --mode real \\
        --user demo@example.com \\
        --password-ssm /itp-demo/password \\
        --totp-ssm /itp-demo/totp-secret \\
        --attacker-lambda itp-demo-session-replayer \\
        --attacker-region eu-west-1 \\
        --record-video /tmp/itp-videos --upload-s3 my-demo-bucket \\
        --monitor --auto-reset

    # SSF mode -- external security signal
    python3 scripts/trigger_itp_demo.py --mode ssf \\
        --user demo@example.com --risk-level HIGH \\
        --monitor --auto-reset
"""

import os
import sys
import json
import time
import requests
import argparse
from datetime import datetime
from typing import Dict, Optional


class ITPDemoTrigger:
    """
    Central orchestrator for ITP demo scenarios.

    Wraps the Okta admin REST API and delegates to mode-specific helpers.
    Each ``run_*_mode()`` method implements one complete demo flow including
    user resolution, risk manipulation, optional monitoring, and cleanup.
    """

    def __init__(self, org_name: str, base_url: str, api_token: str):
        # org_name: Okta org subdomain (e.g. "myorg")
        # base_url: Domain suffix (e.g. "okta.com" or "oktapreview.com")
        # api_token: SSWS-style admin API token
        self.org_name = org_name
        self.base_url = base_url
        self.api_token = api_token
        self.okta_url = f"https://{org_name}.{base_url}"
        self.api_base = f"{self.okta_url}/api/v1"
        # All requests use SSWS auth header; Content-Type is JSON throughout
        self.headers = {
            "Authorization": f"SSWS {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        # Persistent session so TCP connections are reused across API calls
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    # =========================================================================
    # User Resolution — shared by all modes
    # =========================================================================

    def resolve_user(self, user_identifier: str) -> Optional[Dict]:
        """
        Resolve a user email/login to a full Okta user object.

        Used at the start of every mode to (a) validate the user exists, and
        (b) obtain the Okta user ID needed for risk API calls.
        """
        print(f"\nResolving user: {user_identifier}...")

        # The /users/{login} endpoint accepts email, login, or user ID
        url = f"{self.api_base}/users/{user_identifier}"
        try:
            response = self.session.get(url)
            response.raise_for_status()
            user = response.json()
            print(f"  ✅ User: {user.get('profile', {}).get('firstName')} "
                  f"{user.get('profile', {}).get('lastName')} "
                  f"(ID: {user.get('id')})")
            return user
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(f"  ❌ User not found: {user_identifier}")
            else:
                print(f"  ❌ Error resolving user: {e}")
            return None

    # =========================================================================
    # QUICK MODE — Set user risk via Okta admin API
    # =========================================================================
    #
    # The simplest demo path. Calls PUT /api/v1/users/{id}/risk to directly
    # set the user's entity risk score. No simulation infrastructure needed.
    #
    # Expected Okta system log events:
    #   - user.risk.change ("Admin reported user risk")
    #   - Any downstream policy actions (e.g. session revocation, MFA step-up)
    #     configured in the entity risk policy
    # =========================================================================

    def get_user_risk(self, user_id: str) -> Optional[Dict]:
        """Get current risk level for a user via GET /api/v1/users/{id}/risk"""
        url = f"{self.api_base}/users/{user_id}/risk"
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            error_msg = str(e)
            try:
                error_msg = e.response.json().get("errorSummary", error_msg)
            except Exception:
                pass
            print(f"  ❌ Error getting user risk: {error_msg}")
            return None

    def set_user_risk(self, user_id: str, risk_level: str) -> Dict:
        """
        Set user risk level via PUT /api/v1/users/{id}/risk.

        The Okta API only accepts "HIGH" or "LOW" as valid risk levels.
        Setting "NONE" is not supported; use "LOW" to clear elevated risk.
        """
        url = f"{self.api_base}/users/{user_id}/risk"
        payload = {"riskLevel": risk_level}

        try:
            response = self.session.put(url, json=payload)
            response.raise_for_status()

            result = response.json()
            print(f"  ✅ User risk set to: {result.get('riskLevel')}")
            return {"status": "success", "risk": result}

        except requests.exceptions.HTTPError as e:
            error_msg = str(e)
            try:
                error_msg = e.response.json().get("errorSummary", error_msg)
            except Exception:
                pass
            print(f"  ❌ Error setting user risk: {error_msg}")
            return {"status": "error", "error": error_msg}

    def run_quick_mode(self, user_email: str, risk_level: str,
                       monitor: bool = False, auto_reset: bool = False,
                       monitor_duration: int = 60) -> bool:
        """
        Quick mode: Set user risk via admin API.

        Flow:
          1. Resolve user email -> Okta user ID
          2. Read and display current risk level (for context)
          3. Set new risk level via PUT
          4. (Optional) Monitor system log for resulting ITP events
          5. (Optional) Auto-reset risk back to LOW

        Args:
            user_email: User email/login to target
            risk_level: "HIGH" or "LOW" (Okta API constraint)
            monitor: If True, poll system log after setting risk
            auto_reset: If True, reset to LOW after monitoring completes
            monitor_duration: How long to monitor the system log (seconds)

        Returns:
            True if risk was set successfully, False otherwise
        """
        print("=" * 80)
        print("ITP DEMO — QUICK MODE (Admin Risk API)")
        print("=" * 80)

        # Step 1: Resolve user — validates the user exists before proceeding
        user = self.resolve_user(user_email)
        if not user:
            return False
        user_id = user["id"]

        # Step 2: Show current risk — useful for demos to show before/after
        current_risk = self.get_user_risk(user_id)
        if current_risk:
            print(f"  Current risk level: {current_risk.get('riskLevel')}")

        # Step 3: Set the new risk level
        print(f"\nSetting risk to {risk_level}...")
        result = self.set_user_risk(user_id, risk_level)
        if result["status"] != "success":
            return False

        # Step 4: Monitor — skip if we just reset to LOW (no ITP events expected)
        if monitor and risk_level != "NONE":
            print(f"\nMonitoring for ITP events ({monitor_duration}s)...")
            self._monitor_events(user_email, monitor_duration)

        # Step 5: Auto-reset — only meaningful when we just raised risk to HIGH.
        # The Okta API does not accept "NONE", so we reset to "LOW" instead.
        if auto_reset and risk_level == "HIGH":
            print(f"\nResetting risk to LOW...")
            self.set_user_risk(user_id, "LOW")

        print("\n✅ Quick mode complete")
        return True

    # =========================================================================
    # REAL MODE — Two-region session hijacking simulation
    # =========================================================================
    #
    # Simulates a real session hijacking attack to trigger Okta's native
    # detection engine. The flow has three phases:
    #
    #   Phase 1 (Victim): Log in via headless Playwright browser, capture the
    #       session cookie (typically "idx").
    #   Phase 2 (Attacker): Replay the stolen cookie from a different geographic
    #       location (Lambda in eu-west-1 or another region). This creates the
    #       "impossible travel" signal Okta's ITP engine detects.
    #   Phase 3 (Detection): Okta detects the anomaly and (if entity risk policy
    #       is configured) terminates sessions via Universal Logout (ULO).
    #
    # Expected Okta system log events:
    #   - user.authentication.auth_via_IDP (victim login)
    #   - security.session.detect ("Session hijacking detected")
    #   - user.risk.change (risk elevated automatically by Okta)
    #   - user.session.clear (if ULO policy is active — sessions terminated)
    #
    # Two sub-paths exist:
    #   - Standard: Browser closes after auth; cookie replay + API monitoring
    #   - Persistent (--record-video): Both victim and attacker browsers stay
    #     open so video captures the full ULO termination visually
    # =========================================================================

    def run_real_mode(self, user_email: str, password: Optional[str] = None,
                      totp_secret: Optional[str] = None,
                      password_ssm: Optional[str] = None,
                      totp_ssm: Optional[str] = None,
                      attacker_region: str = "eu-west-1",
                      attacker_lambda: Optional[str] = None,
                      aws_profile: Optional[str] = None,
                      monitor: bool = False, auto_reset: bool = False,
                      monitor_duration: int = 120,
                      record_video: Optional[str] = None,
                      upload_s3: Optional[str] = None) -> bool:
        """
        Real mode: Two-region session hijacking simulation.

        Step 1: Authenticate as user (victim side) — capture IDX cookie
        Step 2: Replay cookie from different region (attacker side)
        Step 3: Monitor for genuine session hijacking detection

        When record_video is set, uses a persistent browser session so the
        video captures the full flow: login -> dashboard -> ULO termination.

        Args:
            user_email: The victim user's Okta login/email
            password: Plaintext password (prefer SSM over this)
            totp_secret: Base32 TOTP seed for MFA (if user has TOTP enrolled)
            password_ssm: AWS SSM parameter name containing the password
            totp_ssm: AWS SSM parameter name containing the TOTP secret
            attacker_region: AWS region where the attacker Lambda is deployed;
                must be geographically distant from the victim's login location
                to trigger impossible-travel detection (default: eu-west-1)
            attacker_lambda: Name of the Lambda function that replays cookies;
                if None, falls back to local replay (same IP, won't trigger
                geo-based detection)
            aws_profile: AWS CLI profile for SSM/Lambda access
            monitor: Poll system log for detection events after replay
            auto_reset: Reset user risk to LOW after the demo
            monitor_duration: How long to wait for detection (seconds);
                defaults to 120 because Okta's detection can take 30-90s
            record_video: Directory path to save browser recording .webm files
            upload_s3: S3 bucket name to upload video recordings to
        """
        print("=" * 80)
        print("ITP DEMO — REAL MODE (Session Hijacking Simulation)")
        print("=" * 80)
        print(f"  Target user: {user_email}")
        print(f"  Attacker region: {attacker_region}")
        if record_video:
            print(f"  Video recording: {record_video} (persistent browser)")
        print()

        # Import ITP modules lazily — they have heavy dependencies (Playwright,
        # boto3) that aren't needed for Quick mode
        try:
            from itp.session_authenticator import (
                SessionAuthenticator, AuthenticationError, get_ssm_parameter
            )
            from itp.session_replayer import replay_cookie
        except ImportError as e:
            print(f"Failed to import ITP modules: {e}")
            print("  Ensure scripts/itp/ package exists")
            return False

        # Resolve credentials from multiple possible sources in priority order:
        # 1. CLI --password/--totp-secret flags
        # 2. SSM Parameter Store (--password-ssm/--totp-ssm)
        # 3. Environment variables (ITP_DEMO_PASSWORD/ITP_DEMO_TOTP_SECRET)
        actual_password, actual_totp = self._resolve_credentials(
            password, totp_secret, password_ssm, totp_ssm, aws_profile
        )
        if not actual_password:
            print("Password is required for real mode")
            print("   Use --password, --password-ssm, or ITP_DEMO_PASSWORD env var")
            return False

        # Dispatch to the appropriate sub-path based on whether video recording
        # is requested. The persistent path keeps browsers open for ULO capture;
        # the standard path closes the browser after extracting the cookie.
        if record_video:
            return self._run_real_mode_persistent(
                user_email, actual_password, actual_totp,
                attacker_region, attacker_lambda, aws_profile,
                monitor, auto_reset, monitor_duration,
                record_video, upload_s3,
            )
        else:
            return self._run_real_mode_standard(
                user_email, actual_password, actual_totp,
                attacker_region, attacker_lambda, aws_profile,
                monitor, auto_reset, monitor_duration,
            )

    def _resolve_credentials(self, password, totp_secret, password_ssm,
                             totp_ssm, aws_profile):
        """
        Resolve password and TOTP secret from direct args or AWS SSM.

        Falls back gracefully: if SSM retrieval fails, the caller will still
        check whether a password was provided (it's required for real mode;
        TOTP is optional and only needed if the user has TOTP MFA enrolled).
        """
        from itp.session_authenticator import get_ssm_parameter

        actual_password = password
        actual_totp = totp_secret

        # Try SSM for password if not provided directly
        if not actual_password and password_ssm:
            print(f"Retrieving password from SSM: {password_ssm}")
            try:
                actual_password = get_ssm_parameter(
                    password_ssm, region="us-east-2", profile=aws_profile
                )
            except Exception as e:
                print(f"  Failed to get password from SSM: {e}")

        # Try SSM for TOTP secret if not provided directly
        if not actual_totp and totp_ssm:
            print(f"Retrieving TOTP secret from SSM: {totp_ssm}")
            try:
                actual_totp = get_ssm_parameter(
                    totp_ssm, region="us-east-2", profile=aws_profile
                )
            except Exception as e:
                print(f"  Failed to get TOTP secret from SSM: {e}")

        return actual_password, actual_totp

    def _do_cookie_replay(self, cookie_name: str, cookie_value: str,
                          okta_domain: str, attacker_lambda: Optional[str],
                          attacker_region: str,
                          aws_profile: Optional[str]) -> Dict:
        """
        Execute cookie replay via Lambda (preferred) or direct HTTP.

        Lambda replay is preferred because it originates from a different AWS
        region, creating the geographic separation needed for Okta's
        impossible-travel detection. Direct replay (fallback) uses the same
        IP but a different User-Agent, which may trigger weaker signals.
        """
        from itp.session_replayer import replay_cookie

        if attacker_lambda:
            # Preferred path: invoke Lambda in a remote region for geo separation
            return self._invoke_attacker_lambda(
                attacker_lambda, attacker_region,
                cookie_name, cookie_value, okta_domain,
                aws_profile
            )
        else:
            # Fallback: replay from this host — same IP, different User-Agent.
            # This won't trigger geo-based detection but may still trigger
            # user-agent anomaly signals depending on Okta's config.
            print("  No attacker Lambda configured — replaying from this host")
            print("     (Same IP, different User-Agent. For full geo separation, deploy Lambda)")
            return replay_cookie(cookie_name, cookie_value, okta_domain)

    # --- Real Mode: Standard Path (no video) ---

    def _run_real_mode_standard(self, user_email, actual_password, actual_totp,
                                attacker_region, attacker_lambda, aws_profile,
                                monitor, auto_reset, monitor_duration) -> bool:
        """
        Standard real mode path — browser closes after auth cookie extraction.

        This is the lightweight path: authenticate, grab cookie, close browser,
        replay cookie, then monitor via API polling. No video recording.
        """
        from itp.session_authenticator import SessionAuthenticator

        # ------------------------------------------------------------------
        # STEP 1: Victim Authentication
        # Log in via headless Playwright to obtain the idx session cookie.
        # The browser is closed immediately after cookie extraction.
        # ------------------------------------------------------------------
        print("\n" + "-" * 60)
        print("STEP 1: Victim Authentication")
        print("-" * 60)

        auth = SessionAuthenticator(self.org_name, self.base_url)
        auth_result = auth.authenticate(
            user_email, actual_password, totp_secret=actual_totp,
        )

        if auth_result["status"] != "success":
            print(f"\nAuthentication failed: {auth_result.get('error')}")
            return False

        cookie_name = auth_result["cookie_name"]
        cookie_value = auth_result["cookie"]
        okta_domain = f"{self.org_name}.{self.base_url}"

        print(f"\n  Got {cookie_name} cookie from {auth_result.get('url', 'Okta')}")

        # Brief pause: Okta needs a moment to fully register the session
        # before it can detect a replay as anomalous
        print("\n  Waiting 3s for session to register...")
        time.sleep(3)

        # ------------------------------------------------------------------
        # STEP 2: Attacker Cookie Replay
        # Replay the captured cookie from a different geographic context.
        # This is the action that triggers Okta's session hijacking detection.
        # ------------------------------------------------------------------
        print("\n" + "-" * 60)
        print("STEP 2: Attacker Cookie Replay")
        print("-" * 60)

        replay_result = self._do_cookie_replay(
            cookie_name, cookie_value, okta_domain,
            attacker_lambda, attacker_region, aws_profile
        )

        if replay_result["status"] != "success":
            print(f"\nCookie replay failed: {replay_result.get('error')}")
            return False

        print(f"\n  Cookie replayed — HTTP {replay_result.get('http_code')}")
        if replay_result.get("lambda_region"):
            print(f"     From region: {replay_result['lambda_region']}")

        # ------------------------------------------------------------------
        # STEP 3: Monitor for Detection
        # Poll the Okta system log for session hijacking detection events.
        # Detection typically takes 30-90 seconds after the replay.
        # ------------------------------------------------------------------
        if monitor:
            print("\n" + "-" * 60)
            print("STEP 3: Monitoring for Session Hijacking Detection")
            print("-" * 60)
            print(f"  Waiting for Okta to detect the anomaly ({monitor_duration}s)...")
            self._monitor_events(user_email, monitor_duration)

        # Auto-reset: bring risk back to LOW so the demo user is ready for
        # the next run. Uses "LOW" because the Okta API doesn't accept "NONE".
        if auto_reset:
            print("\nResetting user risk to LOW...")
            user = self.resolve_user(user_email)
            if user:
                self.set_user_risk(user["id"], "LOW")

        print("\nReal mode complete")
        return True

    # --- Real Mode: Persistent Browser Path (with video recording) ---

    def _run_real_mode_persistent(self, user_email, actual_password, actual_totp,
                                  attacker_region, attacker_lambda, aws_profile,
                                  monitor, auto_reset, monitor_duration,
                                  record_video, upload_s3) -> bool:
        """
        Persistent browser path — video captures full demo flow.

        Two browsers record simultaneously:
          - Victim: login -> dashboard -> session terminated by ULO
          - Attacker: stolen cookie injected -> dashboard (no login!) -> kicked out

        This creates compelling demo footage showing Okta detecting the hijack
        and terminating BOTH sessions in real time via Universal Logout.

        Falls back to the standard (no-video) path if Playwright is unavailable
        or if the persistent browser auth fails.
        """
        from itp.session_authenticator import (
            SessionAuthenticator, AuthenticationError, wait_for_all_terminated,
        )

        # ------------------------------------------------------------------
        # STEP 1: Victim Authentication with Persistent Browser
        # Unlike standard mode, the browser stays open after login so video
        # can capture the full lifecycle including ULO session termination.
        # ------------------------------------------------------------------
        print("\n" + "-" * 60)
        print("STEP 1: Victim Authentication (persistent browser)")
        print("-" * 60)

        auth = SessionAuthenticator(self.org_name, self.base_url)
        try:
            victim_session = auth.authenticate_persistent(
                user_email, actual_password, totp_secret=actual_totp,
                record_video=os.path.join(record_video, "victim"),
            )
        except AuthenticationError as e:
            # Persistent auth failed — fall back to standard (no-video) path
            # rather than failing the entire demo
            print(f"\nBrowser auth failed: {e}")
            print("  Falling back to standard path (no continuous video)...")
            return self._run_real_mode_standard(
                user_email, actual_password, actual_totp,
                attacker_region, attacker_lambda, aws_profile,
                monitor, auto_reset, monitor_duration,
            )
        except ImportError as e:
            # Playwright not installed — graceful degradation
            print(f"\nPlaywright not available: {e}")
            print("  Falling back to standard path...")
            return self._run_real_mode_standard(
                user_email, actual_password, actual_totp,
                attacker_region, attacker_lambda, aws_profile,
                monitor, auto_reset, monitor_duration,
            )

        # Track attacker session and video paths for cleanup in the finally block
        attacker_session = None
        victim_video = None
        attacker_video = None

        try:
            okta_domain = f"{self.org_name}.{self.base_url}"
            print(f"\n  Got {victim_session.cookie_name} cookie "
                  f"from {victim_session.auth_result.get('url', 'Okta')}")

            # Brief pause for session registration (same rationale as standard path)
            print("\n  Waiting 3s for session to register...")
            time.sleep(3)

            # ------------------------------------------------------------------
            # STEP 2: Attacker Opens Browser with Stolen Cookie
            # Opens a SECOND Playwright browser, injects the victim's cookie,
            # and navigates to the Okta dashboard — no login required.
            # This browser also records video to show the attacker's perspective.
            # ------------------------------------------------------------------
            print("\n" + "-" * 60)
            print("STEP 2: Attacker Uses Stolen Cookie")
            print("-" * 60)

            attacker_session = auth.open_attacker_session(
                cookie_name=victim_session.cookie_name,
                cookie_value=victim_session.cookie,
                domain=victim_session.domain,
                victim_session=victim_session,
                record_video=os.path.join(record_video, "attacker"),
            )

            # ------------------------------------------------------------------
            # STEP 3: Geo-Separated Lambda Replay
            # The browser-based attacker above is on the same host (same IP).
            # This Lambda invocation creates the actual geographic separation
            # that triggers Okta's impossible-travel detection engine.
            # Both the browser replay (for visual demo) and Lambda replay
            # (for detection trigger) are needed for a complete demo.
            # ------------------------------------------------------------------
            print("\n" + "-" * 60)
            print("STEP 3: Geo-Separated Replay (triggers Okta detection)")
            print("-" * 60)

            replay_result = self._do_cookie_replay(
                victim_session.cookie_name, victim_session.cookie, okta_domain,
                attacker_lambda, attacker_region, aws_profile,
            )

            if replay_result["status"] != "success":
                print(f"\nCookie replay failed: {replay_result.get('error')}")
            else:
                print(f"\n  Cookie replayed — HTTP {replay_result.get('http_code')}")
                if replay_result.get("lambda_region"):
                    print(f"     From region: {replay_result['lambda_region']}")

            # ------------------------------------------------------------------
            # STEP 4: Watch Both Browsers for ULO Session Termination
            # Polls both browser sessions to detect when Okta's Universal Logout
            # kicks in — typically redirecting the page to /login or showing an
            # error. This is the money shot for demo videos.
            # ------------------------------------------------------------------
            print("\n" + "-" * 60)
            print("STEP 4: Watching Both Browsers for Session Termination (ULO)")
            print("-" * 60)

            terminations = wait_for_all_terminated(
                {"victim": victim_session, "attacker": attacker_session},
                timeout=monitor_duration,
                poll_interval=5,
            )

            # Report termination results for each browser
            for label, result in terminations.items():
                if result["terminated"]:
                    print(f"\n  {label}: terminated after {result['elapsed']}s")
                    print(f"     Final URL: {result['final_url']}")
                    print(f"     Reason: {result['reason']}")
                else:
                    print(f"\n  {label}: NOT terminated within {monitor_duration}s")

        finally:
            # Cleanup: close browsers in the correct order.
            # Attacker session must close FIRST because it borrows the victim's
            # Playwright instance (shared browser context). Closing victim first
            # would destroy the shared Playwright process and orphan the attacker.
            if attacker_session:
                attacker_video = attacker_session.close()
            # Victim session owns the Playwright instance and stops it on close
            victim_video = victim_session.close()

        # Upload finalized .webm video files to S3 for sharing/archiving
        if upload_s3:
            if victim_video:
                print("\n  Uploading victim video...")
                self._upload_video_to_s3(victim_video, upload_s3, user_email, aws_profile)
            if attacker_video:
                print("\n  Uploading attacker video...")
                self._upload_video_to_s3(attacker_video, upload_s3, user_email, aws_profile)

        # Optional: quick API event log summary after browsers are closed
        if monitor:
            print("\n" + "-" * 60)
            print("Event Log Summary")
            print("-" * 60)
            # Shorter duration (30s) since we already waited during ULO monitoring
            self._monitor_events(user_email, 30)

        # Auto-reset risk for next demo run
        if auto_reset:
            print("\nResetting user risk to LOW...")
            user = self.resolve_user(user_email)
            if user:
                self.set_user_risk(user["id"], "LOW")

        print("\nReal mode complete")
        return True

    # =========================================================================
    # SSF MODE — Shared Signals Framework (signed JWT security event)
    # =========================================================================
    #
    # Sends a Security Event Token (SET) per RFC 8417 to Okta's security
    # events ingestion endpoint. The SET is a JWT signed with an RSA private
    # key whose corresponding public JWKS is hosted on a Lambda Function URL
    # and registered with Okta as an SSF provider.
    #
    # Prerequisites:
    #   - Run setup_ssf_provider.py once to register the provider with Okta
    #   - RSA key pair and provider config must be stored in AWS SSM
    #
    # Expected Okta system log events:
    #   - security.events.provider.receive
    #     ("Security events provider reported risk")
    #   - user.risk.change (risk level changed based on the signal)
    #   - Any downstream policy actions from the entity risk policy
    # =========================================================================

    def run_ssf_mode(self, user_email: str, risk_level: str = "HIGH",
                     ssf_config_ssm: str = "/taskvantage-prod/ssf-demo/provider-config",
                     private_key_ssm: str = "/taskvantage-prod/ssf-demo/private-key",
                     aws_profile: str = None,
                     monitor: bool = False, auto_reset: bool = False,
                     monitor_duration: int = 60) -> bool:
        """
        SSF mode: Send a security event via Shared Signals Framework.

        Sends a signed Security Event Token (SET) to Okta's security events
        endpoint. The SET contains a CAEP risk-level-changed event identifying
        the target user and the new risk level.

        Flow:
          1. Resolve user to validate they exist in Okta
          2. Load SSF provider config (issuer, key ID) and RSA private key
             from AWS SSM Parameter Store
          3. Build and sign a SET JWT with the risk signal
          4. POST the SET to Okta's /security/api/v1/security-events endpoint
          5. (Optional) Monitor system log for the resulting events
          6. (Optional) Auto-reset risk by sending a LOW signal

        Requires one-time setup via setup_ssf_provider.py first.

        Args:
            user_email: Target user's Okta login/email
            risk_level: Risk level to signal ("HIGH" or "LOW")
            ssf_config_ssm: SSM parameter path for provider config JSON
            private_key_ssm: SSM parameter path for RSA private key PEM
            aws_profile: AWS CLI profile for SSM access
            monitor: Poll system log after sending the signal
            auto_reset: Send a follow-up LOW signal after monitoring
            monitor_duration: How long to monitor (seconds)
        """
        print("=" * 80)
        print("ITP DEMO — SSF MODE (Security Events Provider Signal)")
        print("=" * 80)
        print(f"  Target user:  {user_email}")
        print(f"  Risk level:   {risk_level}")
        print()

        # Validate user exists before sending signal (avoids wasting a SET
        # on a non-existent user, which Okta would silently ignore)
        user = self.resolve_user(user_email)
        if not user:
            return False
        user_id = user["id"]

        # Import SSF module lazily — requires pyjwt and cryptography
        try:
            from itp.ssf_provider import SSFProvider, get_ssf_config_from_ssm
        except ImportError as e:
            print(f"❌ Failed to import SSF module: {e}")
            print("  Ensure scripts/itp/ssf_provider.py exists")
            return False

        # Load provider config from SSM. The config contains the issuer URL,
        # key ID, and provider name that were registered with Okta during
        # setup_ssf_provider.py execution.
        print("\nLoading SSF provider config from SSM...")
        try:
            config, private_key_pem = get_ssf_config_from_ssm(
                # Extract the SSM prefix (everything before the last path segment)
                ssm_prefix=ssf_config_ssm.rsplit("/", 1)[0],
                profile=aws_profile,
            )
            print(f"  Provider: {config.get('provider_name', config.get('issuer'))}")
            print(f"  Issuer:   {config['issuer']}")
            print(f"  Key ID:   {config['key_id']}")
        except Exception as e:
            print(f"  ❌ Failed to load SSF config from SSM: {e}")
            print("  Run setup_ssf_provider.py first to register a provider.")
            return False

        # Build the SSF provider client and send the risk signal.
        # The SSFProvider handles JWT construction, RS256 signing, and HTTP delivery.
        print(f"\nSending risk signal ({risk_level})...")
        provider = SSFProvider(
            org_name=self.org_name,
            base_url=self.base_url,
            api_token=self.api_token,
            issuer=config["issuer"],
            private_key_pem=private_key_pem,
            key_id=config["key_id"],
        )

        result = provider.send_risk_signal(user_email, risk_level)

        if result["status"] != "success":
            print(f"  ❌ Signal failed: {result.get('error')}")
            print(f"     HTTP {result.get('http_code')}")
            return False

        print(f"  ✅ Signal accepted — HTTP {result.get('http_code')}")
        # JTI (JWT ID) is useful for correlating with Okta system log entries
        print(f"     JTI: {result.get('jti')}")

        # Monitor for the "Security events provider reported risk" event
        if monitor:
            print(f"\nMonitoring for ITP events ({monitor_duration}s)...")
            print("  Looking for: 'Security events provider reported risk'")
            self._monitor_events(user_email, monitor_duration)

        # Auto-reset: send a follow-up LOW signal via SSF (same channel).
        # If the SSF reset fails, fall back to the admin API as a safety net.
        if auto_reset and risk_level.upper() == "HIGH":
            print("\nResetting risk to LOW via SSF signal...")
            reset_result = provider.send_risk_signal(user_email, "LOW")
            if reset_result["status"] == "success":
                print(f"  ✅ Reset signal accepted — HTTP {reset_result.get('http_code')}")
            else:
                print(f"  ⚠️  Reset signal failed: {reset_result.get('error')}")
                print("     Falling back to admin API reset...")
                self.set_user_risk(user_id, "LOW")

        print("\n✅ SSF mode complete")
        return True

    # =========================================================================
    # Real Mode Helpers — Lambda invocation and video upload
    # =========================================================================

    def _invoke_attacker_lambda(self, function_name: str, region: str,
                                cookie_name: str, cookie_value: str,
                                okta_domain: str,
                                aws_profile: Optional[str] = None) -> Dict:
        """
        Invoke the attacker Lambda function in a remote AWS region.

        The Lambda receives the stolen cookie and replays it against the Okta
        domain from the Lambda's IP address (in the specified region). This
        geographic separation is what triggers Okta's impossible-travel
        detection — the same cookie is seen from two vastly different locations
        within seconds.

        The Lambda payload includes a user_agent_index to select from a pool
        of common browser User-Agent strings, adding realism to the replay.
        """
        print(f"  Invoking Lambda: {function_name} in {region}...")

        try:
            import boto3

            session_kwargs = {}
            if aws_profile:
                session_kwargs["profile_name"] = aws_profile
            # Create a boto3 session targeting the attacker's region
            boto_session = boto3.Session(region_name=region, **session_kwargs)
            lambda_client = boto_session.client("lambda")

            payload = {
                "cookie_name": cookie_name,
                "cookie": cookie_value,
                "okta_domain": okta_domain,
                # user_agent_index: selects which User-Agent string the Lambda
                # uses; index 0 is typically Chrome on Windows
                "user_agent_index": 0,
            }

            # Synchronous invocation — wait for the replay result
            response = lambda_client.invoke(
                FunctionName=function_name,
                InvocationType="RequestResponse",
                Payload=json.dumps(payload),
            )

            response_payload = json.loads(response["Payload"].read().decode())

            # Check for Lambda execution errors (unhandled exceptions, timeouts)
            if response.get("FunctionError"):
                return {"status": "error", "error": f"Lambda error: {response_payload}"}

            return response_payload

        except ImportError:
            return {"status": "error", "error": "boto3 not installed"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _upload_video_to_s3(self, video_path: str, bucket: str,
                              user_email: str,
                              aws_profile: Optional[str] = None):
        """
        Upload recorded browser video (.webm) to S3 and print a presigned URL.

        Video files are organized in S3 by date and username:
            s3://{bucket}/{YYYY-MM-DD}/{username}_{HH-MM-SS}_{filename}.webm

        A 7-day presigned URL is generated for easy sharing without requiring
        AWS credentials (useful for sending demo links to stakeholders).
        """
        print(f"\n  Uploading video to s3://{bucket}/...")
        try:
            import boto3
            import glob as glob_mod

            # video_path may be a single .webm file or a directory containing them
            if os.path.isfile(video_path) and video_path.endswith(".webm"):
                webm_files = [video_path]
            else:
                pattern = os.path.join(video_path, "*.webm")
                webm_files = glob_mod.glob(pattern)
            if not webm_files:
                print(f"  ⚠️  No .webm files found in {video_path}")
                return

            session_kwargs = {}
            if aws_profile:
                session_kwargs["profile_name"] = aws_profile
            boto_session = boto3.Session(region_name="us-east-2", **session_kwargs)
            s3_client = boto_session.client("s3")

            for webm_file in webm_files:
                # Build S3 key: {date}/{user}_{timestamp}_{original_filename}.webm
                now = datetime.now()
                date_prefix = now.strftime("%Y-%m-%d")
                user_prefix = user_email.split("@")[0]
                timestamp = now.strftime("%H-%M-%S")
                filename = os.path.basename(webm_file)
                s3_key = f"{date_prefix}/{user_prefix}_{timestamp}_{filename}"

                s3_client.upload_file(webm_file, bucket, s3_key)
                print(f"  ✅ Uploaded: s3://{bucket}/{s3_key}")

                # Generate a presigned URL valid for 7 days — allows anyone
                # with the link to download without AWS credentials
                presigned_url = s3_client.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": bucket, "Key": s3_key},
                    ExpiresIn=7 * 24 * 3600,
                )
                print(f"  🔗 Presigned URL (7 days): {presigned_url}")

        except ImportError:
            print("  ⚠️  boto3 not installed — skipping S3 upload")
        except Exception as e:
            print(f"  ⚠️  S3 upload failed: {e}")

    # =========================================================================
    # Event Monitoring — shared by all modes
    # =========================================================================

    def _monitor_events(self, user_email: str, duration: int):
        """
        Monitor ITP-related events in the Okta system log.

        Delegates to the standalone ITPEventMonitor (monitor_itp_events.py),
        which polls the system log API and filters for ITP-related event types:
          - user.risk.change
          - security.session.detect
          - security.events.provider.receive
          - user.session.clear (ULO)
        """
        try:
            from monitor_itp_events import ITPEventMonitor
        except ImportError:
            # If direct import fails, add the scripts directory to sys.path.
            # This handles the case where trigger_itp_demo.py is invoked from
            # a different working directory than scripts/.
            script_dir = os.path.dirname(os.path.abspath(__file__))
            sys.path.insert(0, script_dir)
            from monitor_itp_events import ITPEventMonitor

        monitor = ITPEventMonitor(
            self.org_name,
            self.base_url,
            # Extract the raw token from the SSWS header for the monitor
            self.session.headers.get("Authorization", "").replace("SSWS ", "")
        )
        monitor.monitor(duration=duration, user=user_email)


# =============================================================================
# CLI Entry Point — Argument Parsing and Mode Dispatch
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Trigger ITP demo scenarios"
    )

    # --- Okta connection settings ---
    # These can be provided via CLI flags or environment variables.
    # Environment variables are the preferred approach for CI/CD and
    # GitHub Actions workflows.
    parser.add_argument(
        "--org-name",
        default=os.environ.get("OKTA_ORG_NAME"),
        help="Okta organization name (subdomain). Env: OKTA_ORG_NAME"
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("OKTA_BASE_URL", "okta.com"),
        help="Okta base URL domain (default: okta.com). Env: OKTA_BASE_URL"
    )
    parser.add_argument(
        "--api-token",
        default=os.environ.get("OKTA_API_TOKEN"),
        help="Okta API token (SSWS format). Env: OKTA_API_TOKEN"
    )

    # --- Mode selection ---
    # Each mode produces different Okta system log events and requires
    # different infrastructure. See module docstring for details.
    parser.add_argument(
        "--mode",
        choices=["quick", "real", "ssf"],
        default="quick",
        help=(
            "Demo mode: "
            "quick = set risk via admin API (no infra needed), "
            "real = session hijacking simulation (needs Lambda + credentials), "
            "ssf = signed JWT security event (needs SSF provider setup)"
        )
    )

    # --- Common options (apply to all modes) ---
    parser.add_argument("--user", required=True,
                        help="Target user email/login in Okta")
    parser.add_argument("--monitor", action="store_true",
                        help="Poll Okta system log for ITP events after triggering")
    parser.add_argument("--auto-reset", action="store_true",
                        help="Reset user risk to LOW after demo completes")
    parser.add_argument(
        "--monitor-duration",
        type=int,
        default=60,
        help="How long to poll the system log, in seconds (default: 60)"
    )

    # --- Quick mode options ---
    # Also used by SSF mode for the risk level in the SET payload.
    parser.add_argument(
        "--risk-level",
        choices=["HIGH", "LOW"],
        default="HIGH",
        help=(
            "Risk level to set (default: HIGH). "
            "The Okta admin API only accepts HIGH or LOW — NONE is not valid."
        )
    )

    # --- Real mode options ---
    # Credentials: multiple sources supported for flexibility across local dev,
    # CI/CD, and demo environments. Priority: CLI flag > env var > SSM.
    parser.add_argument("--password", default=os.environ.get("ITP_DEMO_PASSWORD"),
                        help="User password (or set ITP_DEMO_PASSWORD env var)")
    parser.add_argument("--password-ssm",
                        help="AWS SSM parameter name containing the password")
    parser.add_argument("--totp-secret", default=os.environ.get("ITP_DEMO_TOTP_SECRET"),
                        help="TOTP MFA secret key (or set ITP_DEMO_TOTP_SECRET env var)")
    parser.add_argument("--totp-ssm",
                        help="AWS SSM parameter name containing the TOTP secret")
    # Attacker Lambda: deployed in a geographically distant region to create
    # the impossible-travel signal Okta's ITP engine detects.
    parser.add_argument("--attacker-region", default="eu-west-1",
                        help="AWS region for attacker Lambda (default: eu-west-1, Ireland)")
    parser.add_argument("--attacker-lambda",
                        help="Lambda function name for geo-separated cookie replay")
    # Video recording: captures the full demo flow including ULO termination
    # for stakeholder presentations and training materials.
    parser.add_argument("--record-video", metavar="DIR",
                        help="Record browser session video to DIR (real mode only, requires Playwright)")
    parser.add_argument("--upload-s3", metavar="BUCKET",
                        help="Upload recorded video to S3 bucket (requires --record-video)")
    # AWS profile: needed for SSM parameter retrieval and Lambda invocation
    parser.add_argument("--aws-profile", default=os.environ.get("AWS_PROFILE"),
                        help="AWS CLI profile for SSM/Lambda access. Env: AWS_PROFILE")

    # --- SSF mode options ---
    # SSM paths for the SSF provider configuration and RSA private key.
    # These are populated by setup_ssf_provider.py during one-time setup.
    parser.add_argument("--ssf-config-ssm",
                        default="/taskvantage-prod/ssf-demo/provider-config",
                        help="SSM parameter path for SSF provider config JSON")
    parser.add_argument("--private-key-ssm",
                        default="/taskvantage-prod/ssf-demo/private-key",
                        help="SSM parameter path for SSF RSA private key PEM")

    args = parser.parse_args()

    # Validate required connection parameters
    if not args.org_name or not args.api_token:
        print("Error: OKTA_ORG_NAME and OKTA_API_TOKEN must be set")
        sys.exit(1)

    # Create the orchestrator instance with Okta connection details
    trigger = ITPDemoTrigger(args.org_name, args.base_url, args.api_token)

    # Dispatch to the selected mode. Each mode method returns True on success,
    # False on failure, which maps to exit code 0 or 1.
    if args.mode == "quick":
        success = trigger.run_quick_mode(
            user_email=args.user,
            risk_level=args.risk_level,
            monitor=args.monitor,
            auto_reset=args.auto_reset,
            monitor_duration=args.monitor_duration,
        )
    elif args.mode == "real":
        success = trigger.run_real_mode(
            user_email=args.user,
            password=args.password,
            totp_secret=args.totp_secret,
            password_ssm=args.password_ssm,
            totp_ssm=args.totp_ssm,
            attacker_region=args.attacker_region,
            attacker_lambda=args.attacker_lambda,
            aws_profile=args.aws_profile,
            monitor=args.monitor,
            auto_reset=args.auto_reset,
            monitor_duration=args.monitor_duration,
            record_video=args.record_video,
            upload_s3=args.upload_s3,
        )
    elif args.mode == "ssf":
        success = trigger.run_ssf_mode(
            user_email=args.user,
            risk_level=args.risk_level,
            ssf_config_ssm=args.ssf_config_ssm,
            private_key_ssm=args.private_key_ssm,
            aws_profile=args.aws_profile,
            monitor=args.monitor,
            auto_reset=args.auto_reset,
            monitor_duration=args.monitor_duration,
        )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
