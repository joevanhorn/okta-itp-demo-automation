# ITP (Identity Threat Protection) Automation

Complete guide to the ITP demo automation module for Okta Identity Threat Protection demonstrations.

---

## Overview

This module provides three ways to trigger Okta ITP risk events for demos, each producing a different system log entry:

| Mode | System Log Entry | Infrastructure | Realism |
|------|-----------------|----------------|---------|
| **Quick** (`--mode quick`) | "Admin reported user risk" | None | Low — admin API call |
| **Real** (`--mode real`) | "Session hijacking detected" | Lambda + Playwright | High — genuine detection |
| **SSF** (`--mode ssf`) | "Security events provider reported risk" | Lambda (JWKS) + SSM | Medium-High — signed JWT signal |

All three modes support `--monitor` (watch system log for ITP events), `--auto-reset` (reset risk after demo), and work with the entity risk policy to trigger downstream actions (session revocation, MFA challenges, etc.).

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    trigger_itp_demo.py                    │
│         (Main orchestrator — all three modes)            │
├──────────┬──────────────────┬────────────────────────────┤
│          │                  │                            │
│  Quick   │      Real        │          SSF               │
│  Mode    │      Mode        │          Mode              │
│          │                  │                            │
│ PUT      │ ┌──────────────┐ │ ┌────────────────────────┐ │
│ /users/  │ │ session_     │ │ │ ssf_provider.py        │ │
│ {id}/    │ │ authenticator│ │ │                        │ │
│ risk     │ │ (Playwright) │ │ │ 1. Load config from SSM│ │
│          │ ├──────────────┤ │ │ 2. Build SET JWT       │ │
│          │ │ session_     │ │ │ 3. Sign with RS256     │ │
│          │ │ replayer     │ │ │ 4. POST to /security/  │ │
│          │ │ (Lambda/     │ │ │    api/v1/security-    │ │
│          │ │  direct)     │ │ │    events              │ │
│          │ └──────────────┘ │ └────────────────────────┘ │
├──────────┴──────────────────┴────────────────────────────┤
│                  monitor_itp_events.py                    │
│            (Watches system log for ITP events)            │
└──────────────────────────────────────────────────────────┘
```

### SSF Infrastructure (Terraform-managed)

```
┌─────────────────────────────────────────────────────┐
│  AWS (us-east-2)                                    │
│                                                     │
│  ┌─────────────┐   ┌─────────────────────────────┐  │
│  │ Lambda      │   │ SSM Parameter Store          │  │
│  │ ssf-demo-   │   │                             │  │
│  │ jwks        │   │ /itp-demo/ssf/ │  │
│  │             │   │   ├── private-key (Secure)  │  │
│  │ Returns     │   │   └── provider-config (JSON)│  │
│  │ JWKS JSON   │   │       ├── issuer            │  │
│  └──────┬──────┘   │       ├── jwks_url          │  │
│         │          │       ├── key_id            │  │
│  ┌──────┴──────┐   │       └── provider_id       │  │
│  │ Function    │   └─────────────────────────────┘  │
│  │ URL (public)│                                    │
│  └─────────────┘                                    │
│       ↑                                             │
└───────│─────────────────────────────────────────────┘
        │
   Okta fetches JWKS
   to verify SET signatures
```

---

## File Reference

### Core Scripts

| File | Purpose |
|------|---------|
| `scripts/trigger_itp_demo.py` | Main orchestrator — CLI entry point for all three modes |
| `scripts/itp/ssf_provider.py` | SSF provider: key generation, SET building/signing, signal sending |
| `scripts/itp/session_authenticator.py` | Headless browser auth via Playwright (real mode) |
| `scripts/itp/session_replayer.py` | Cookie replay from different context (real mode) |
| `scripts/monitor_itp_events.py` | System log watcher for ITP events |
| `scripts/setup_ssf_provider.py` | Post-Terraform Okta provider registration |
| `scripts/helpers/pem_to_jwks.py` | PEM-to-JWKS converter (Terraform external data source) |

### Entity Risk Policy Scripts

| File | Purpose |
|------|---------|
| `scripts/import_entity_risk_policy.py` | Import entity risk policy config from Okta |
| `scripts/apply_entity_risk_policy.py` | Apply entity risk policy config to Okta |
| `config/entity_risk_policy.json` | Policy config (rules, actions) |

### Terraform

| File | Purpose |
|------|---------|
| `ssf_jwks_endpoint.tf` | Lambda, Function URL, SSM, IAM, TLS key (SSF mode) |
| `itp_session_replayer.tf` | Lambda in eu-west-1 for cookie replay (Real mode) |
| `itp_demo_videos.tf` | S3 bucket for demo video storage (90-day expiry) |
| `provider.tf` | AWS + TLS providers |

### GitHub Workflows

| File | Purpose |
|------|---------|
| `.github/workflows/itp-demo-trigger.yml` | Run any demo mode (quick/real/ssf) |
| `.github/workflows/itp-ssf-provider-setup.yml` | One-time Okta provider registration |
| `.github/workflows/itp-entity-risk-policy-import.yml` | Import entity risk policy |
| `.github/workflows/itp-entity-risk-policy-apply.yml` | Apply entity risk policy |
| `.github/workflows/itp-monitor-events.yml` | Standalone event monitoring |

### Terraform Module (Real Mode Lambda)

| File | Purpose |
|------|---------|
| `terraform/modules/session-replayer/main.tf` | Lambda for cross-region cookie replay |
| `terraform/modules/session-replayer/lambda/replayer.py` | Lambda handler for session replay |

---

## Setup

### Prerequisites

- Okta org with ITP license (Identity Threat Protection)
- Entity risk policy configured (import/apply via scripts)
- AWS credentials with Lambda + SSM access (GitHub OIDC role)
- Python 3.11+ with `requests`, `pyjwt`, `cryptography`, `boto3`, `pyotp`

### Quick Mode Setup

No infrastructure needed. Works immediately with just Okta API credentials.

### Real Mode Setup

1. **Deploy attacker Lambda** (cross-region cookie replay):
   ```bash
   # Via GitHub Actions (deploys itp_session_replayer.tf)
   gh workflow run tf-apply.yml -f environment=your-environment
   ```
   This creates a Lambda function (`itp-demo-session-replayer`) in eu-west-1 via `itp_session_replayer.tf`.

2. **Create test user** in Okta:
   - Create user `itp-demo-test@yourdomain.com` (use `@yourdomain.com` domain)
   - Enroll TOTP factor with provider **OKTA** (not GOOGLE) — Okta Verify TOTP
   - Save the TOTP seed (base32 secret) for SSM storage

3. **Store victim credentials** in SSM:
   ```bash
   aws --profile yourprofile --region us-east-2 \
     ssm put-parameter --name /itp-demo/password \
     --value "USER_PASSWORD" --type SecureString

   aws --profile yourprofile --region us-east-2 \
     ssm put-parameter --name /itp-demo/totp-secret \
     --value "TOTP_BASE32_SECRET" --type SecureString
   ```

4. **Install Playwright and dependencies** (for headless browser):
   ```bash
   pip install playwright pyotp
   playwright install chromium
   playwright install-deps chromium  # system dependencies (libgbm, etc.)
   ```

### SSF Mode Setup

Two-step process — Terraform for infrastructure, then register with Okta:

**Step 1: Deploy infrastructure (Terraform)**

```bash
# Via GitHub Actions (recommended)
gh workflow run tf-apply.yml -f environment=your-environment

# This creates:
#   - Lambda function (ssf-demo-jwks) serving JWKS
#   - Lambda Function URL (public endpoint)
#   - RSA key pair (tls_private_key)
#   - SSM: /itp-demo/ssf/private-key
#   - SSM: /itp-demo/ssf/provider-config
```

**Step 2: Register provider with Okta**

```bash
# Via GitHub Actions
gh workflow run itp-ssf-provider-setup.yml -f environment=your-environment

# Or locally
export AWS_PROFILE=yourprofile
export OKTA_ORG_NAME=yourorg
export OKTA_API_TOKEN=$(cat ~/Taskvantage-prod-apiKey)
cd scripts && python3 setup_ssf_provider.py --aws-region us-east-2
```

**Verify:** Check Okta Admin > Security > Security Events Providers — you should see "ITP Demo Signal Source".

---

## Usage

### Quick Mode

Directly sets user risk via admin API. Instant, no infrastructure.

```bash
# Set user risk to HIGH and monitor
python3 scripts/trigger_itp_demo.py --mode quick \
  --user user@yourdomain.com \
  --risk-level HIGH --monitor --auto-reset

# Reset risk to LOW
python3 scripts/trigger_itp_demo.py --mode quick \
  --user user@yourdomain.com --risk-level LOW
```

**What happens:**
1. Resolves user by email
2. `PUT /api/v1/users/{id}/risk` with `{"riskLevel": "HIGH"}`
3. System log: "Admin reported user risk"
4. Entity risk policy evaluates
5. (If `--auto-reset`) Resets to LOW

### Real Mode

Two-region session hijacking simulation. Genuine Okta detection.

```bash
# Full simulation with Lambda in eu-west-1
python3 scripts/trigger_itp_demo.py --mode real \
  --user itp-demo-test@yourdomain.com \
  --password-ssm /itp-demo/password \
  --totp-ssm /itp-demo/totp-secret \
  --attacker-lambda itp-demo-session-replayer \
  --attacker-region eu-west-1 \
  \
  --monitor --auto-reset

# With video recording + S3 upload (generates a 7-day presigned URL)
python3 scripts/trigger_itp_demo.py --mode real \
  --user itp-demo-test@yourdomain.com \
  --password-ssm /itp-demo/password \
  --totp-ssm /itp-demo/totp-secret \
  --attacker-lambda itp-demo-session-replayer \
  --record-video /tmp/itp-video \
  --upload-s3 your-environment-itp-demo-videos \
  \
  --monitor --auto-reset
```

**What happens:**
1. **Step 1 — Victim auth:** Playwright headless browser authenticates as user (username -> password -> TOTP), captures IDX cookie (macOS Chrome UA)
2. **Step 2 — Attacker uses stolen cookie (with `--record-video`):** A second browser (Windows/Firefox UA) opens, the stolen cookie is injected via `add_cookies()`, and it navigates straight to the Okta dashboard — no credentials, no MFA. This is what a real attacker does.
3. **Step 3 — Geo-separated replay:** Lambda in eu-west-1 replays cookie (triggers Okta's geo-anomaly detection)
4. **Step 4 — ULO in browser (with `--record-video`):** Both browsers reload every 5s, watching for session termination. When Okta fires ULO, the victim's reload redirects to login — captured in the video.
5. **Full event chain observed in system log:**
   1. `user.risk.detect` — risk detected from attacker IP (e.g., Dublin)
   2. `policy.entity_risk.evaluate` — Entity Risk Policy rule matched
   3. `policy.entity_risk.action` — TERMINATE_ALL_SESSIONS scheduled
   4. `user.session.end` — session terminated
   5. `user.authentication.universal_logout` — universal logout issued
6. (If `--auto-reset`) Risk auto-resets to LOW

### SSF Mode

Sends a Shared Signals Framework security event via signed JWT.

```bash
# Send HIGH risk signal
python3 scripts/trigger_itp_demo.py --mode ssf \
  --user user@yourdomain.com \
  --risk-level HIGH --monitor --auto-reset

# With explicit AWS profile and custom SSM paths
python3 scripts/trigger_itp_demo.py --mode ssf \
  --user user@yourdomain.com \
  --risk-level HIGH \
  \
  --ssf-config-ssm /itp-demo/ssf/provider-config \
  --monitor
```

**What happens:**
1. Resolves user by email (validates they exist)
2. Loads provider config + private key from SSM
3. Builds Security Event Token (SET) with `user-risk-change` event
4. Signs JWT with RS256 (`typ: secevent+jwt`)
5. `POST /security/api/v1/security-events` (self-authenticating via JWT signature)
6. System log: "Security events provider reported risk"
7. Entity risk policy evaluates
8. (If `--auto-reset`) Sends LOW signal to reset

### GitHub Actions

```bash
# Quick mode
gh workflow run itp-demo-trigger.yml \
  -f environment=your-environment \
  -f mode=quick \
  -f user_email=user@yourdomain.com \
  -f risk_level=HIGH

# Real mode
gh workflow run itp-demo-trigger.yml \
  -f environment=your-environment \
  -f mode=real \
  -f user_email=itp-demo-test@yourdomain.com \
  -f attacker_region=eu-west-1

# SSF mode
gh workflow run itp-demo-trigger.yml \
  -f environment=your-environment \
  -f mode=ssf \
  -f user_email=user@yourdomain.com \
  -f ssf_risk_level=HIGH
```

---

## Entity Risk Policy Management

Entity risk policies define what actions Okta takes when a user's risk level changes (from any trigger — admin API, session hijacking, or SSF signal).

### Import

```bash
# Via workflow
gh workflow run itp-entity-risk-policy-import.yml -f environment=your-environment

# Via CLI
python3 scripts/import_entity_risk_policy.py \
  --output config/entity_risk_policy.json
```

### Apply

```bash
# Dry run first
gh workflow run itp-entity-risk-policy-apply.yml \
  -f environment=your-environment -f dry_run=true

# Apply
gh workflow run itp-entity-risk-policy-apply.yml \
  -f environment=your-environment -f dry_run=false
```

### Configuration Format

```json
{
  "policy_id": "rst1yr8u11qDt6moD1d8",
  "policy_name": "Entity Risk Policy",
  "rules": [
    {
      "name": "High Risk Response",
      "conditions": {
        "riskLevel": "HIGH"
      },
      "actions": {
        "terminateSessions": true,
        "challengeWithMFA": true
      }
    }
  ]
}
```

---

## How SSF Works (Technical Details)

### Security Event Token (SET)

A SET is a JWT with `typ: secevent+jwt` containing a security event per RFC 8417. The payload structure:

```json
{
  "iss": "https://xxxx.lambda-url.us-east-2.on.aws/",
  "jti": "unique-uuid",
  "iat": 1709654321,
  "aud": "https://yourorg.okta.com",
  "events": {
    "https://schemas.okta.com/secevent/okta/event-type/user-risk-change": {
      "subject": {
        "user": {
          "format": "email",
          "email": "user@yourdomain.com"
        }
      },
      "event_timestamp": 1709654321,
      "initiating_entity": "admin",
      "reason_admin": {
        "en": "Critical security activity detected"
      },
      "current_level": "high",
      "previous_level": "low"
    }
  }
}
```

### Verification Flow

1. Python builds SET payload and signs with RS256 using private key from SSM
2. `POST /security/api/v1/security-events` with `Content-Type: application/secevent+jwt`
3. Okta reads `iss` claim, finds matching registered provider
4. Okta fetches JWKS from the provider's registered `jwks_url` (our Lambda Function URL)
5. Okta verifies JWT signature using the public key from JWKS
6. If valid, Okta processes the risk event and updates the user's entity risk score

### Key Details

- The security events endpoint is **self-authenticating** — no SSWS token needed for the POST
- SSWS token is only needed for provider registration (`POST /api/v1/security-events-providers`)
- The `issuer` registered with Okta must exactly match the `iss` claim in the SET
- Okta accepts `200` or `202` status codes on success
- The Lambda Function URL serves JWKS with `Cache-Control: public, max-age=3600`

---

## Event Monitoring

The `monitor_itp_events.py` script watches the system log for ITP-related events:

```bash
# Standalone monitoring
python3 scripts/monitor_itp_events.py \
  --duration 120 --user user@yourdomain.com

# Via workflow
gh workflow run itp-monitor-events.yml \
  -f environment=your-environment \
  -f user_email=user@yourdomain.com \
  -f duration=120
```

Events watched (defined in `monitor_itp_events.py`):
- `user.risk.detect` — Risk detected (session hijacking, admin API, SSF signal)
- `policy.entity_risk.evaluate` — Entity risk policy rule evaluated
- `policy.entity_risk.action` — Entity risk policy action taken (e.g., TERMINATE_ALL_SESSIONS)
- `user.session.end` — Session terminated (policy action)
- `user.authentication.universal_logout` — Universal logout issued

---

## Demo Recommendations

### For Sales Engineers

**Best demo flow:**
1. Show the entity risk policy in Okta Admin (what actions are configured)
2. Run SSF mode (`--mode ssf`) — most realistic, shows "Security events provider reported risk"
3. Show system log updating in real-time
4. Show entity risk policy evaluating and taking action
5. Reset with `--auto-reset`

**Why SSF over Quick:**
- "Security events provider reported risk" sounds like CrowdStrike/Zscaler/etc. detected a threat
- "Admin reported user risk" sounds like someone clicked a button manually
- SSF mode takes the same 2 seconds but creates a much better story

### For Deep Demos

Use Real mode (`--mode real`) to show genuine session hijacking detection — this demonstrates Okta's actual threat detection engine, not just policy evaluation from an external signal.

---

## CLI Reference

### Real Mode Options

| Flag | Description |
|------|-------------|
| `--password` | User password (or `ITP_DEMO_PASSWORD` env var) |
| `--password-ssm` | SSM parameter name for password |
| `--totp-secret` | TOTP secret (or `ITP_DEMO_TOTP_SECRET` env var) |
| `--totp-ssm` | SSM parameter name for TOTP secret |
| `--attacker-region` | AWS region for attacker Lambda (default: `eu-west-1`) |
| `--attacker-lambda` | Lambda function name for cookie replay |
| `--record-video DIR` | Record browser session video to directory |
| `--upload-s3 BUCKET` | Upload recorded video to S3 bucket (requires `--record-video`) |
| `--aws-profile` | AWS profile for SSM, Lambda, and S3 access |

### Video Recording & S3 Upload

When `--record-video` and `--upload-s3` are both set, the demo records **two browsers simultaneously** — victim and attacker — capturing the full session hijacking story:

**Victim browser** (Chrome/Mac UA, `{record_video}/victim/`):
1. Login flow — user enters credentials, completes MFA, lands on dashboard
2. Dashboard idle — stays open while attacker activity happens
3. Session terminated — page reload redirects to login (ULO kicks in)

**Attacker browser** (Firefox/Windows UA, `{record_video}/attacker/`):
1. **Terminal animation** — a hacker-workstation-style terminal shows the stolen cookie arriving from a "C2 callback", the cookie value being echoed, and the `document.cookie` injection command executing with a green checkmark. This plays for ~9 seconds before the browser navigates to Okta.
2. **Dashboard access** — navigates to Okta dashboard, lands directly with no credentials or MFA
3. **Cookie inspector overlay** — a DevTools Application-tab-style panel appears at the bottom of the dashboard, showing the stolen `idx` cookie highlighted in red ("STOLEN SESSION") alongside its value, domain, path, and security flags
4. Stays open showing the attacker's view of the hijacked session until ULO terminates it

Both browsers reload every 5s watching for session termination. When Okta's entity risk policy fires `TERMINATE_ALL_SESSIONS` (Universal Logout), the victim's session is revoked and the next reload redirects to the login page.

The Lambda replay from eu-west-1 runs in the background to provide the geo-separated signal that triggers Okta's detection engine. The attacker browser is the visual representation of what a real attacker does with a stolen cookie.

If persistent browser auth fails (e.g., Playwright not installed), the demo automatically falls back to the standard path (API auth, no video).

**S3 upload details:**
- Two `.webm` files uploaded (victim + attacker)
- S3 key format: `{date}/{user}_{timestamp}_{filename}.webm`
- A presigned URL (valid 7 days) is printed for each video
- Upload happens AFTER both browsers close (videos aren't finalized until then)

The S3 bucket `your-environment-itp-demo-videos` is managed by Terraform (`itp_demo_videos.tf`) with:
- 90-day auto-expiration
- AES256 encryption
- Public access blocked
- GitHub Actions OIDC role has write access

In GitHub Actions, the presigned URL is automatically added to the workflow step summary.

---

## Troubleshooting

### SSF Signal Returns 400 "Invalid JWT"
- Verify the JWKS URL is accessible: `curl <function_url>`
- Ensure the `kid` in the JWT header matches the `kid` in JWKS
- Check that the `iss` claim matches the registered provider's issuer

### SSF Signal Returns 400 "Provider not found"
- Run `python3 scripts/setup_ssf_provider.py --list` to verify registration
- Ensure `iss` in JWT matches the registered issuer exactly (including trailing slash)

### SSF Signal Returns 403
- Verify the org has ITP/security events feature enabled
- Check that the API token has sufficient permissions

### Lambda JWKS URL Not Accessible
- Check Lambda Function URL exists: `aws lambda get-function-url-config --function-name ssf-demo-jwks`
- Verify the function returns valid JSON: `curl <function_url>`

### Terraform Plan Shows Drift on provider-config SSM
- Expected — the `lifecycle { ignore_changes = [value] }` on the SSM parameter means Terraform won't overwrite the provider_id added by the setup script

### Real Mode Auth Fails
- Check password/TOTP in SSM are current
- Verify Playwright chromium is installed: `playwright install chromium`
- Install system dependencies: `playwright install-deps chromium`
- Check if user has additional MFA factors beyond TOTP
- **OIE TOTP field**: The password input uses `credentials.passcode`, but the TOTP input uses `credentials.totp` — these are different fields in OIE. The authenticator handles both automatically.
- **TOTP provider**: Must be OKTA (Okta Verify TOTP), not GOOGLE. The OIE authenticator selector looks for `[data-se="okta_verify-totp"]`.
- **TOTP timing**: If TOTP fails with "invalid passcode", the code may have expired during the authentication flow. The script generates the code just before submission, but slow network or page loads can cause timing issues. Retry usually works.
- **Screenshot debugging**: On auth failure, a screenshot is saved to `/tmp/itp-auth-failure.png`
