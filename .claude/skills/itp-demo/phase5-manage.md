# Phase 5: Manage

Day-2 operations for the ITP demo environment.

## Check What's Deployed

### Terraform state
```bash
cd terraform
terraform show -no-color | head -50
```

### SSM parameters
```bash
aws ssm get-parameters-by-path --path /itp-demo/ --recursive \
  --query "Parameters[].{Name:Name,Type:Type,LastModified:LastModifiedDate}" \
  --output table --region us-east-2
```

### SSF providers registered with Okta
```bash
python3 scripts/setup_ssf_provider.py \
  --org-name $OKTA_ORG_NAME \
  --base-url $OKTA_BASE_URL \
  --api-token $OKTA_API_TOKEN \
  --action list
```

### Entity risk policy rules
```bash
python3 scripts/import_entity_risk_policy.py \
  --org-name $OKTA_ORG_NAME \
  --base-url $OKTA_BASE_URL \
  --api-token $OKTA_API_TOKEN \
  --output /tmp/current_policy.json

python3 -c "
import json
with open('/tmp/current_policy.json') as f:
    d = json.load(f)
for r in d['rules']:
    level = r.get('conditions',{}).get('riskScore',{}).get('level','any')
    action = r.get('actions',{}).get('entityRisk',{}).get('action','?')
    print(f'  {r[\"name\"]:40s} risk={level:8s} action={action}')
"
```

## Update Entity Risk Policy

1. Edit `config/entity_risk_policy.json` with the desired rules
2. Preview changes:
   ```bash
   python3 scripts/apply_entity_risk_policy.py \
     --config config/entity_risk_policy.json --dry-run
   ```
3. Apply:
   ```bash
   python3 scripts/apply_entity_risk_policy.py \
     --config config/entity_risk_policy.json
   ```

## Re-register SSF Provider

If the JWKS endpoint URL changed (e.g., after a Terraform destroy + re-apply):

```bash
# Delete the old provider
python3 scripts/setup_ssf_provider.py --action list  # get the provider ID
python3 scripts/setup_ssf_provider.py --action delete --provider-id <id>

# Register the new one
python3 scripts/setup_ssf_provider.py --action register \
  --ssm-prefix /itp-demo/ssf --region us-east-2
```

## Update Test User Credentials

If the test user's password changed:
```bash
aws ssm put-parameter --name "/itp-demo/password" \
  --value "NEW_PASSWORD" --type SecureString --overwrite --region us-east-2
```

If the TOTP secret changed (re-enrolled MFA):
```bash
aws ssm put-parameter --name "/itp-demo/totp-secret" \
  --value "NEW_BASE32_SECRET" --type SecureString --overwrite --region us-east-2
```

## View Recent ITP Events

Quick check of what happened recently:
```bash
python3 scripts/monitor_itp_events.py --duration 10 --user <email>
```

Or check the Okta system log directly:
```bash
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "https://$OKTA_ORG_NAME.$OKTA_BASE_URL/api/v1/logs?filter=eventType+sw+%22user.risk%22+or+eventType+sw+%22security.session%22+or+eventType+sw+%22policy.entity_risk%22&limit=10&sortOrder=DESCENDING" | python3 -c "
import sys,json
for e in json.load(sys.stdin):
    t = e.get('target',[{}])[0].get('alternateId','?') if e.get('target') else '?'
    print(f'{e[\"published\"][:19]}  {e[\"eventType\"]:45s}  target={t}')
"
```

## Rotate SSF Keys

If you need to rotate the RSA key pair (e.g., security policy, key compromise):

1. Re-run `terraform apply` — this regenerates the `tls_private_key` and updates the JWKS Lambda
2. Re-register the SSF provider (see "Re-register SSF Provider" above)
3. The old provider should be deleted so Okta doesn't try to verify with stale keys

## Check Lambda Health

```bash
# JWKS Lambda
JWKS_URL=$(cd terraform && terraform output -raw jwks_endpoint_url)
curl -s "$JWKS_URL" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Keys: {len(d.get(\"keys\",[]))}  kid: {d[\"keys\"][0].get(\"kid\",\"?\")}')"

# Session replayer Lambda
REPLAYER=$(cd terraform && terraform output -raw session_replayer_lambda)
REGION=$(cd terraform && terraform output -raw attacker_region)
aws lambda get-function --function-name "$REPLAYER" --region "$REGION" \
  --query "Configuration.[FunctionName,Runtime,LastModified]" --output text
```
