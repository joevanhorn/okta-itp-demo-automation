# Phase 6: Teardown

Destroy AWS infrastructure when done. Preserves the repo fork for future use.

## What Gets Destroyed

- Lambda functions (JWKS + session replayer)
- Lambda IAM roles and policies
- Lambda function URL
- S3 video bucket (and all videos in it)
- TLS private key resource
- SSM parameters created by Terraform

## What's Preserved

- The forked GitHub repo (and all code)
- SSM parameters created manually (test user creds at `/itp-demo/password`, `/itp-demo/totp-secret`)
- The SSF provider registration in Okta (can be cleaned up separately)
- The entity risk policy rules in Okta (unaffected by Terraform destroy)
- The GitHub Actions OIDC IAM role (created outside Terraform)

## Steps

### 6.1 Destroy Terraform infrastructure

```bash
cd terraform
terraform destroy
```

Review the plan — confirm it's only destroying the expected resources (Lambdas, S3, IAM roles, SSM params). Type `yes` to confirm.

### 6.2 (Optional) Clean up SSM parameters

If the user wants a clean slate:

```bash
# Remove test user credentials
aws ssm delete-parameter --name "/itp-demo/password" --region us-east-2 2>/dev/null
aws ssm delete-parameter --name "/itp-demo/totp-secret" --region us-east-2 2>/dev/null

# Remove SSF config (if not already removed by Terraform)
aws ssm delete-parameter --name "/itp-demo/ssf/private-key" --region us-east-2 2>/dev/null
aws ssm delete-parameter --name "/itp-demo/ssf/provider-config" --region us-east-2 2>/dev/null
```

### 6.3 (Optional) Delete SSF provider from Okta

```bash
python3 scripts/setup_ssf_provider.py \
  --org-name $OKTA_ORG_NAME \
  --base-url $OKTA_BASE_URL \
  --api-token $OKTA_API_TOKEN \
  --action list
```

Note the provider ID, then delete:

```bash
python3 scripts/setup_ssf_provider.py \
  --org-name $OKTA_ORG_NAME \
  --base-url $OKTA_BASE_URL \
  --api-token $OKTA_API_TOKEN \
  --action delete \
  --provider-id <id>
```

### 6.4 (Optional) Delete entity risk policy rules

If you want to remove the demo rules from Okta:

```bash
python3 scripts/apply_entity_risk_policy.py \
  --org-name $OKTA_ORG_NAME \
  --base-url $OKTA_BASE_URL \
  --api-token $OKTA_API_TOKEN \
  --config config/entity_risk_policy.json \
  --delete-removed --dry-run
```

### 6.5 (Optional) Delete the GitHub OIDC role

If the user doesn't plan to re-deploy:

```bash
aws iam delete-role-policy --role-name GitHubActions-ITPDemo --policy-name <each-attached-policy>
aws iam delete-role --role-name GitHubActions-ITPDemo
```

### 6.6 Re-deploying later

The repo fork is preserved. To re-deploy at any time:

```bash
cd okta-itp-demo-automation/terraform
terraform init
terraform apply -var="okta_org_url=https://yourorg.okta.com"
python3 scripts/setup_ssf_provider.py --action register --ssm-prefix /itp-demo/ssf
```

The full environment comes back in ~2 minutes.

## Cost Note

While deployed, approximate monthly costs:
- Lambda (JWKS + replayer): ~$0 (free tier covers demo usage)
- S3 (video bucket): ~$0.03/GB stored
- SSM parameters: free (standard tier)
- Total: effectively **$0/month** for demo usage patterns

There's no urgency to tear down for cost reasons. The main reason to teardown is security hygiene (removing unused IAM roles and Lambda functions from the account).
