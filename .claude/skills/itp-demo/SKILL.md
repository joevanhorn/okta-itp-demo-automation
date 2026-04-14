---
name: itp-demo
description: Deploy, run, and manage the Okta Identity Threat Protection (ITP) demo automation. Use when a user wants to fork and set up the ITP demo repo, deploy AWS infrastructure (Lambda, SSM, S3), configure their Okta org for ITP demos, or run any of the three demo modes (quick/real/SSF). Triggers on phrases like "set up ITP demo", "run the session hijacking demo", "trigger ITP", "deploy the ITP infrastructure", "configure SSF provider", or "show me the ITP demo".
---

# Okta ITP Demo Automation Skill

This skill guides a user through the complete lifecycle of the Okta Identity Threat Protection demo: from initial repo fork through infrastructure deployment to running live demos and managing the environment.

## Important: Read Before Acting

Always read this entire SKILL.md and the relevant phase file before taking any action. The phases are sequential — do NOT skip ahead.

## Skill Capabilities

This skill handles four major workflows:

### 1. Initial Setup (first-time only)
Fork the repo, create AWS infrastructure, configure Okta, register the SSF provider. Takes ~30 minutes.

### 2. Run a Demo
Execute any of the three demo modes (quick, real, SSF), monitor events in real time, and auto-reset when done. Takes 2-5 minutes per run.

### 3. Manage the Environment
Update entity risk policies, re-register SSF providers, check infrastructure status, view recent events.

### 4. Teardown
Destroy AWS infrastructure when done. Preserves the repo fork for future use.

## How to Detect Which Workflow the User Wants

Listen for these cues:

| User Says | Workflow | Phase |
|---|---|---|
| "set up the ITP demo" / "I want to deploy ITP" / "help me fork this" | Initial Setup | Start at Phase 1 |
| "run a quick demo" / "trigger ITP" / "show session hijacking" | Run a Demo | Start at Phase 4 |
| "update the risk policy" / "check the SSF provider" / "what's deployed" | Manage | Start at Phase 5 |
| "tear down" / "destroy" / "clean up" | Teardown | Start at Phase 6 |

If the user asks to run a demo but hasn't done the initial setup, detect this by checking for the Terraform state or SSM parameters, and guide them to Phase 1 first.

## Inputs to Collect

Different phases need different inputs. Collect them just-in-time, not all upfront.

**Phase 1 (Fork & Clone):**
- GitHub username (detect via `gh auth status`)
- Whether they want to fork or have already forked

**Phase 2 (AWS Setup):**
- AWS region (default: us-east-2)
- AWS profile name (or confirm default credentials work)
- Attacker Lambda region (default: eu-west-1)

**Phase 3 (Okta Configuration):**
- Okta org name (subdomain, e.g., "acme")
- Okta base URL ("okta.com" or "oktapreview.com")
- Okta API admin token (SSWS)
- Test user email for real mode
- Test user password (stored in SSM, never in files)
- Test user TOTP secret (if MFA is required, stored in SSM)

**Phase 4 (Run Demo):**
- Which mode: quick, real, or ssf
- Target user email
- Risk level (HIGH, LOW, NONE)
- Whether to monitor events
- Whether to auto-reset

## Phases

### Phase 1: Fork & Clone
**File:** `phase1-fork.md`
Fork the repo, clone locally, verify the structure.

### Phase 2: AWS Infrastructure
**File:** `phase2-aws.md`
Create the GitHub Actions OIDC IAM role, deploy Terraform (JWKS Lambda, session replayer Lambda, video S3 bucket), store secrets in SSM.

### Phase 3: Okta Configuration
**File:** `phase3-okta.md`
Register SSF provider, import/configure entity risk policy, store test user credentials in SSM.

### Phase 4: Run Demo
**File:** `phase4-run.md`
Execute any demo mode, monitor events, auto-reset. This is the phase users return to most often.

### Phase 5: Manage
**File:** `phase5-manage.md`
Day-2 operations: update policies, check status, view events, re-register providers.

### Phase 6: Teardown
**File:** `phase6-teardown.md`
Destroy AWS infrastructure, clean up SSM parameters. Preserve the repo fork.

## Key Principles

1. **Never write secrets to files.** Passwords, API tokens, TOTP secrets go to SSM Parameter Store or environment variables. Never to disk, never to git.

2. **Show the user what's happening.** When running commands, show the output. When calling APIs, show the request/response. The user should understand what was done.

3. **Verify before proceeding.** After each step, verify the result. Don't assume success — check.

4. **Be specific about Okta system log events.** Each mode produces different events. Tell the user exactly what to look for:
   - Quick: `user.risk.change` ("Admin reported user risk")
   - Real: `security.session.detect` ("Session hijacking detected")
   - SSF: `security.events.provider.receive` ("Security events provider reported risk")

5. **Handle the "no infrastructure" case gracefully.** Quick mode needs zero AWS infrastructure. If a user just wants to do a quick demo, don't make them deploy Terraform first.

6. **Remember the user's context between runs.** If they've already set up the environment, don't ask them to do it again. Check for existing SSM parameters, Terraform state, and SSF providers before suggesting setup steps.

## Reference: File Structure

```
scripts/
  trigger_itp_demo.py          Main orchestrator (all 3 modes)
  monitor_itp_events.py        Real-time Okta system log monitor
  setup_ssf_provider.py        One-time SSF provider registration
  apply_entity_risk_policy.py  Apply policy rules to Okta
  import_entity_risk_policy.py Import policy rules from Okta
  itp/
    ssf_provider.py            JWT/SET building, signing, sending
    session_authenticator.py   Playwright-based headless auth
    session_replayer.py        Cookie replay (Lambda or direct)
  helpers/
    pem_to_jwks.py             PEM to JWKS conversion

terraform/                     JWKS Lambda, session replayer, video bucket
config/                        Entity risk policy (example)
.github/workflows/             GitHub Actions for all operations
docs/                          Architecture docs
```

## Environment Variables

The scripts use these environment variables (set them or pass as CLI flags):

```bash
export OKTA_ORG_NAME=yourorg
export OKTA_BASE_URL=okta.com        # or oktapreview.com
export OKTA_API_TOKEN=00abc...       # SSWS admin token
export AWS_PROFILE=default           # or your named profile
export AWS_DEFAULT_REGION=us-east-2
```
