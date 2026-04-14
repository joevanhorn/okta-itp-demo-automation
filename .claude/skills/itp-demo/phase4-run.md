# Phase 4: Run Demo

This is the phase users return to most often. Execute any of the three demo modes.

## Before Running

Confirm the environment is set:

```bash
echo "Org: $OKTA_ORG_NAME.$OKTA_BASE_URL"
echo "Token: ${OKTA_API_TOKEN:0:10}..."
```

If empty, set them (see Phase 3.1).

## Quick Mode

**When to use:** Fast policy-trigger demo. No infrastructure needed. Shows "Admin reported user risk" in the system log.

**Prerequisites:** Just an Okta API token.

```bash
python3 scripts/trigger_itp_demo.py --mode quick \
  --user <email> --risk-level HIGH --monitor --auto-reset
```

**What happens:**
1. Script calls `PUT /api/v1/users/{id}/risk` with `riskLevel: HIGH`
2. Okta logs `user.risk.change` ("Admin reported user risk")
3. Entity risk policy evaluates and triggers the configured action
4. `--monitor` watches the system log for 120 seconds, showing events in real-time
5. `--auto-reset` sets risk back to LOW when done

**Variations:**
- `--risk-level LOW` — sets risk without triggering HIGH-risk actions
- `--risk-level NONE` — resets risk to baseline (no monitoring, just cleanup)
- Remove `--auto-reset` to leave the user in a risky state for further demo

**Expected Okta system log events:**
```
user.risk.change                   "Admin reported user risk"
policy.entity_risk.evaluate        "Entity risk policy evaluated"
policy.entity_risk.action          "Entity risk policy action taken" (if rule matches)
user.session.end                   "User session terminated" (if UNIVERSAL_LOGOUT)
```

## Real Mode

**When to use:** Session hijacking simulation. Most realistic. Shows "Session hijacking detected" — a genuine Okta detection, not admin-reported.

**Prerequisites:** Test user credentials in SSM, attacker Lambda deployed in a remote region.

```bash
python3 scripts/trigger_itp_demo.py --mode real \
  --user <test-user-email> \
  --password-ssm /itp-demo/password \
  --totp-ssm /itp-demo/totp-secret \
  --attacker-lambda itp-demo-session-replayer \
  --attacker-region eu-west-1 \
  --monitor --auto-reset
```

**What happens:**
1. Playwright opens a headless browser and authenticates as the victim
2. Captures the `idx` session cookie
3. Waits 3 seconds for Okta to register the session
4. Invokes the attacker Lambda in eu-west-1 with the stolen cookie
5. Lambda replays the cookie from a different IP/geo/User-Agent
6. Okta ITP detects the impossible-travel anomaly
7. System log shows `security.session.detect` ("Session hijacking detected")
8. Entity risk policy triggers (e.g., UNIVERSAL_LOGOUT)
9. `--monitor` shows events in real-time
10. `--auto-reset` resets the user's risk level

**Optional: Record video of ULO (Universal Logout):**
```bash
python3 scripts/trigger_itp_demo.py --mode real \
  --user <test-user-email> \
  --password-ssm /itp-demo/password \
  --totp-ssm /itp-demo/totp-secret \
  --attacker-lambda itp-demo-session-replayer \
  --attacker-region eu-west-1 \
  --record-video --upload-s3 itp-demo-videos-demo \
  --monitor --auto-reset
```

This records side-by-side browser videos showing:
- Victim's browser: logged into Okta dashboard → session suddenly terminates (redirected to login page)
- Attacker's browser: replaying the cookie → sees the hijacked session → gets kicked out

Videos are uploaded to S3 with a 7-day presigned URL printed to the terminal.

**Without Lambda (local fallback):**
```bash
python3 scripts/trigger_itp_demo.py --mode real \
  --user <test-user-email> \
  --password-ssm /itp-demo/password \
  --monitor --auto-reset
```

Without `--attacker-lambda`, the script replays the cookie locally. This still triggers detection if your machine's IP/UA differs from Playwright's, but the geo-distance signal is weaker.

**Expected Okta system log events:**
```
security.session.detect            "Session hijacking detected"
user.risk.detect                   "User risk detected"
policy.entity_risk.evaluate        "Entity risk policy evaluated"
policy.entity_risk.action          "Entity risk policy action taken"
user.session.end                   "User session terminated"
user.authentication.universal_logout  "Universal logout initiated"
```

## SSF Mode

**When to use:** Demonstrate third-party security signal integration. Shows that external tools (SIEMs, EDRs) can feed risk signals into Okta.

**Prerequisites:** SSF provider registered (Phase 3.2), JWKS Lambda deployed (Phase 2).

```bash
python3 scripts/trigger_itp_demo.py --mode ssf \
  --user <email> --risk-level HIGH \
  --monitor --auto-reset
```

**What happens:**
1. Script loads the SSF provider config and private key from SSM
2. Builds a Security Event Token (SET) per RFC 8417 with a `user-risk-change` event
3. Signs the SET with RS256 using the private key
4. POSTs the signed JWT to `https://<org>.okta.com/security/api/v1/security-events`
5. Okta verifies the JWT signature against the published JWKS
6. Okta logs `security.events.provider.receive` ("Security events provider reported risk")
7. Entity risk policy evaluates and triggers the configured action

**Expected Okta system log events:**
```
security.events.provider.receive   "Security events provider reported risk"
user.risk.change                   "User risk level changed"
policy.entity_risk.evaluate        "Entity risk policy evaluated"
policy.entity_risk.action          "Entity risk policy action taken"
```

## Standalone Event Monitor

Watch for ITP events without triggering a demo:

```bash
python3 scripts/monitor_itp_events.py \
  --duration 300 \
  --user <email>
```

Useful for:
- Watching events during a live customer demo (run in a separate terminal)
- Verifying that a demo trigger actually produced the expected events
- Debugging: "I ran the demo but nothing happened — are events showing up?"

## Troubleshooting

| Symptom | Mode | Cause | Fix |
|---|---|---|---|
| "User not found" | All | Wrong email format | Use the Okta login, not display name |
| No events after quick mode | Quick | Entity risk policy has no rules | Phase 3.4 — add rules |
| "Cookie rejected (401)" | Real | Session already expired/revoked | Wait a few minutes and try again |
| "TOTP code rejected" | Real | Clock drift or wrong secret | Verify TOTP secret in SSM; check system clock |
| "Lambda invoke failed" | Real | Lambda not deployed or wrong region | Phase 2.5 — check `terraform output` |
| "SET rejected (400)" | SSF | Provider not registered or JWKS unreachable | Phase 3.2 — re-register; check JWKS URL |
| "SET rejected (401)" | SSF | JWT signature mismatch | Re-deploy Terraform to regenerate keys |
| Events appear but no action | All | Entity risk policy rule doesn't match risk level | Phase 3.4 — check rule conditions |

## Reset Between Demo Runs

After each demo, the user's risk level should be reset:

```bash
# If --auto-reset was used, it's already done
# Otherwise, reset manually:
python3 scripts/trigger_itp_demo.py --mode quick \
  --user <email> --risk-level NONE
```

For real mode, the test user's password may also need to be re-verified if MFA state changed during the demo.
