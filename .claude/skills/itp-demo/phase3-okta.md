# Phase 3: Okta Configuration

Configure the Okta org for ITP demos: register the SSF provider, set up the entity risk policy, and store test user credentials.

## Prerequisites

- Okta API admin token (SSWS)
- JWKS endpoint URL from Phase 2 (only for SSF mode)
- A test user in the Okta org with password + optional TOTP enrolled

## Steps

### 3.1 Set environment variables

```bash
export OKTA_ORG_NAME=yourorg
export OKTA_BASE_URL=okta.com       # or oktapreview.com
export OKTA_API_TOKEN=00abc...      # SSWS admin token
```

Verify the token works:

```bash
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "https://$OKTA_ORG_NAME.$OKTA_BASE_URL/api/v1/users/me" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f'Authenticated as: {d.get(\"profile\",{}).get(\"login\",\"FAILED\")}')"
```

### 3.2 Register SSF provider (SSF mode only)

Skip this step if the user only wants quick mode or real mode.

The SSF provider registration tells Okta to trust signed security event tokens from our JWKS endpoint.

```bash
python3 scripts/setup_ssf_provider.py \
  --org-name $OKTA_ORG_NAME \
  --base-url $OKTA_BASE_URL \
  --api-token $OKTA_API_TOKEN \
  --action register \
  --ssm-prefix /itp-demo/ssf \
  --region us-east-2
```

This script:
1. Reads the JWKS URL and private key from SSM (put there by Terraform in Phase 2)
2. Registers the provider with Okta's `/api/v1/security-events-providers` endpoint
3. Writes the `provider_id` back to SSM for later use

**Verify** the provider was registered:

```bash
python3 scripts/setup_ssf_provider.py \
  --org-name $OKTA_ORG_NAME \
  --base-url $OKTA_BASE_URL \
  --api-token $OKTA_API_TOKEN \
  --action list
```

Should show at least one provider with the JWKS URL matching the Terraform output.

### 3.3 Import entity risk policy

Import the current entity risk policy from Okta to see what rules exist:

```bash
python3 scripts/import_entity_risk_policy.py \
  --org-name $OKTA_ORG_NAME \
  --base-url $OKTA_BASE_URL \
  --api-token $OKTA_API_TOKEN \
  --output config/entity_risk_policy.json
```

Review the output:

```bash
python3 -c "
import json
with open('config/entity_risk_policy.json') as f:
    d = json.load(f)
print(f'Policy: {d[\"policy\"][\"name\"]}')
print(f'Rules: {len(d[\"rules\"])}')
for r in d['rules']:
    print(f'  - {r[\"name\"]}: {r.get(\"conditions\",{}).get(\"riskScore\",{}).get(\"level\",\"?\")} -> {r.get(\"actions\",{}).get(\"entityRisk\",{}).get(\"action\",\"?\")}')
"
```

### 3.4 Configure entity risk policy for the demo

For a compelling demo, you want at least these rules:

| Rule | Condition | Action | Purpose |
|---|---|---|---|
| High Risk - Terminate Sessions | Risk = HIGH | UNIVERSAL_LOGOUT | Shows automatic session revocation |
| Medium Risk - Force Re-Auth | Risk = MEDIUM | CHALLENGE | Shows step-up authentication |
| Low Risk - Log Only | Risk = LOW | NONE | Shows detection without disruption |

If these rules don't exist, create them by editing `config/entity_risk_policy.json` and applying:

```bash
python3 scripts/apply_entity_risk_policy.py \
  --org-name $OKTA_ORG_NAME \
  --base-url $OKTA_BASE_URL \
  --api-token $OKTA_API_TOKEN \
  --config config/entity_risk_policy.json \
  --dry-run
```

Review the dry-run output. If it looks correct, apply for real:

```bash
python3 scripts/apply_entity_risk_policy.py \
  --org-name $OKTA_ORG_NAME \
  --base-url $OKTA_BASE_URL \
  --api-token $OKTA_API_TOKEN \
  --config config/entity_risk_policy.json
```

### 3.5 Store test user credentials in SSM (real mode only)

Skip this step if the user only wants quick mode or SSF mode.

Real mode needs a test user's password (and optionally TOTP secret) to authenticate via Playwright. Store them in SSM:

```bash
# Password
aws ssm put-parameter \
  --name "/itp-demo/password" \
  --value "THE_TEST_USER_PASSWORD" \
  --type "SecureString" \
  --overwrite \
  --region us-east-2

# TOTP secret (only if MFA is required for this user)
aws ssm put-parameter \
  --name "/itp-demo/totp-secret" \
  --value "BASE32_TOTP_SECRET" \
  --type "SecureString" \
  --overwrite \
  --region us-east-2
```

**IMPORTANT:** Ask the user to type or paste these values themselves. NEVER have the skill echo passwords to the terminal or write them to a file.

**Where to get the TOTP secret:**
- If the test user has Okta Verify TOTP enrolled, the base32 secret was shown during enrollment (it's the text below the QR code)
- If they don't have it, they'll need to re-enroll with a TOTP authenticator (Google Authenticator, etc.) and capture the secret during enrollment
- If MFA isn't required for the test user, skip the TOTP parameter entirely

### 3.6 Verify the full configuration

Run a quick mode test to confirm the Okta connection works:

```bash
python3 scripts/trigger_itp_demo.py --mode quick \
  --user <test-user-email> --risk-level HIGH --monitor --auto-reset
```

Expected output:
1. "Setting risk to HIGH for <user>..."
2. "Monitoring for ITP events..."
3. Event: `user.risk.change` ("Admin reported user risk")
4. Event: `policy.entity_risk.evaluate`
5. Event: `policy.entity_risk.action` (UNIVERSAL_LOGOUT if HIGH rule exists)
6. "Auto-resetting risk to LOW..."

If this works, the Okta configuration is complete.

## Outputs

- SSF provider registered (if SSF mode needed)
- Entity risk policy configured with demo-appropriate rules
- Test user credentials stored in SSM (if real mode needed)
- Quick mode verified working
- Ready for Phase 4 (Run Demo)
