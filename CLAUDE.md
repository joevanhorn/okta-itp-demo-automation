# CLAUDE.md - Okta ITP Demo Automation

## Repository Purpose

This repo provides **three automated modes** for demonstrating Okta Identity Threat Protection (ITP) to customers:

| Mode | What It Does | Infrastructure Needed |
|------|-------------|----------------------|
| **Quick** | Sets user risk via admin API (instant) | None |
| **Real** | Session hijacking simulation (Playwright + Lambda in eu-west-1) | Lambda + SSM |
| **SSF** | Sends signed JWT security event signal | Lambda (JWKS) + SSM |

All modes support `--monitor` (watch system log), `--auto-reset` (reset risk after demo), and integrate with entity risk policies for downstream actions.

## Common Commands

### Quick Mode (No Infrastructure)
```bash
python3 scripts/trigger_itp_demo.py --mode quick \
  --user user@yourdomain.com --risk-level HIGH --monitor --auto-reset
```

### Real Mode (Session Hijacking)
```bash
python3 scripts/trigger_itp_demo.py --mode real \
  --user itp-demo-test@yourdomain.com \
  --password-ssm /itp-demo/password \
  --totp-ssm /itp-demo/totp-secret \
  --attacker-lambda itp-demo-session-replayer \
  --attacker-region eu-west-1 \
  --monitor --auto-reset
```

### SSF Mode (Signed JWT Signal)
```bash
python3 scripts/trigger_itp_demo.py --mode ssf \
  --user user@yourdomain.com --risk-level HIGH --monitor --auto-reset
```

### Standalone Event Monitor
```bash
python3 scripts/monitor_itp_events.py --duration 120 --user user@yourdomain.com
```

### Entity Risk Policy Management
```bash
# Import current policy from Okta
python3 scripts/import_entity_risk_policy.py --output config/entity_risk_policy.json

# Apply policy changes (dry-run first)
python3 scripts/apply_entity_risk_policy.py --config config/entity_risk_policy.json --dry-run
```

### Terraform
```bash
cd terraform
terraform init
terraform plan -var="okta_org_url=https://yourorg.okta.com"
terraform apply -var="okta_org_url=https://yourorg.okta.com"
```

### GitHub Workflows
```bash
# Trigger any demo mode
gh workflow run itp-demo-trigger.yml \
  -f environment=prod -f mode=quick \
  -f user_email=user@yourdomain.com -f risk_level=HIGH

# One-time SSF provider registration
gh workflow run itp-ssf-provider-setup.yml -f environment=prod

# Import entity risk policy
gh workflow run itp-entity-risk-policy-import.yml -f environment=prod

# Apply entity risk policy
gh workflow run itp-entity-risk-policy-apply.yml -f environment=prod -f dry_run=true
```

## Environment Variables

```bash
export OKTA_ORG_NAME=yourorg      # Okta subdomain
export OKTA_BASE_URL=okta.com     # okta.com or oktapreview.com
export OKTA_API_TOKEN=...         # SSWS admin token
export AWS_PROFILE=yourprofile    # AWS CLI profile (if using SSM/Lambda)
export AWS_DEFAULT_REGION=us-east-2
```

## File Structure

```
scripts/
  trigger_itp_demo.py          Main orchestrator (all 3 modes)
  monitor_itp_events.py        Real-time Okta system log monitor
  setup_ssf_provider.py        One-time SSF provider registration
  apply_entity_risk_policy.py  Apply policy rules to Okta
  import_entity_risk_policy.py Import policy rules from Okta
  itp/
    __init__.py
    ssf_provider.py            JWT/SET building, signing, sending
    session_authenticator.py   Playwright-based headless auth
    session_replayer.py        Cookie replay (Lambda or direct)
  helpers/
    pem_to_jwks.py             PEM to JWKS conversion for Terraform

terraform/
  provider.tf                  AWS provider (parameterized)
  variables.tf                 All configurable inputs
  outputs.tf                   JWKS URL, Lambda name, bucket
  ssf_jwks_endpoint.tf         Lambda + RSA key + SSM + Function URL
  itp_session_replayer.tf      Attacker Lambda (cross-region)
  itp_demo_videos.tf           S3 bucket for recorded demos
  modules/session-replayer/    Reusable Lambda module

config/
  entity_risk_policy.json.example  Example policy config

.github/workflows/
  itp-demo-trigger.yml         Run any demo mode via Actions
  itp-ssf-provider-setup.yml   One-time SSF registration
  itp-entity-risk-policy-*.yml Policy import/apply workflows
  itp-monitor-events.yml       Standalone event monitoring

docs/
  SESSION_REPLAY_EXPLAINER.md  How session hijacking detection works
  DESIGN.md                    Original design document
```

## Key Dependencies

- **Python**: requests, boto3, pyjwt, cryptography, playwright, pyotp
- **Terraform**: AWS provider, tls provider, external provider
- **AWS**: Lambda, SSM Parameter Store, S3 (optional for videos)
- **Okta APIs**: User risk, system logs, security events, entity risk policies
