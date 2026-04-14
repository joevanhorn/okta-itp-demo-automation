# Phase 2: AWS Infrastructure

Deploy the AWS resources needed for real mode and SSF mode. Quick mode doesn't need any of this.

## What Gets Created

| Resource | Purpose | Required For |
|---|---|---|
| Lambda: `ssf-demo-jwks` | Public JWKS endpoint for SET signature verification | SSF mode |
| Lambda: `itp-demo-session-replayer` | Cross-region cookie replay (attacker) | Real mode |
| S3: `itp-demo-videos-<env>` | Recorded demo videos (optional) | Real mode with `--record-video` |
| SSM parameters | Private keys, provider config, test user creds | SSF mode + Real mode |
| IAM roles | Lambda execution roles | Both |

## Steps

### 2.1 Verify AWS credentials

```bash
aws sts get-caller-identity
```

Confirm the response shows the expected account. Note the account ID — we'll need it for the OIDC role.

### 2.2 (Optional) Create GitHub Actions OIDC IAM Role

This is only needed if the user wants to run demos via GitHub Actions workflows. If they'll only run locally, skip this step.

**Tell the user:**

If you want to use the GitHub Actions workflows (recommended for repeatability), you need an IAM role that GitHub can assume via OIDC. Here's how to create one:

1. Go to the **AWS IAM Console > Identity providers**
2. Check if `token.actions.githubusercontent.com` already exists as an OIDC provider
3. If not, click **Add provider**:
   - Provider type: OpenID Connect
   - Provider URL: `https://token.actions.githubusercontent.com`
   - Audience: `sts.amazonaws.com`
   - Click **Add provider**

4. Go to **IAM > Roles > Create role**:
   - Trusted entity: **Web identity**
   - Identity provider: `token.actions.githubusercontent.com`
   - Audience: `sts.amazonaws.com`
   - Click **Next**
   - Attach these managed policies:
     - `AWSLambda_FullAccess` (or a scoped-down custom policy)
     - `AmazonSSMFullAccess` (or scoped to `/itp-demo/*`)
     - `AmazonS3FullAccess` (or scoped to `itp-demo-*`)
     - `IAMFullAccess` (only needed for initial Terraform apply — can be removed after)
   - Click **Next**
   - Role name: `GitHubActions-ITPDemo`
   - Click **Create role**

5. Edit the role's trust policy to restrict to your repo:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {
         "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
       },
       "Action": "sts:AssumeRoleWithWebIdentity",
       "Condition": {
         "StringEquals": {
           "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
         },
         "StringLike": {
           "token.actions.githubusercontent.com:sub": "repo:<USERNAME>/okta-itp-demo-automation:*"
         }
       }
     }]
   }
   ```

6. Copy the **Role ARN** (e.g., `arn:aws:iam::123456789012:role/GitHubActions-ITPDemo`)

7. Add it as a GitHub repo secret:
   ```bash
   gh secret set AWS_ROLE_ARN -b "arn:aws:iam::<ACCOUNT_ID>:role/GitHubActions-ITPDemo"
   ```

### 2.3 Configure Terraform backend

The repo's `terraform/provider.tf` has a commented-out S3 backend block. For first-time users, local backend is simplest:

```bash
cd terraform
terraform init
```

If they want shared state (team use), uncomment the S3 backend block and provide their own bucket/table.

### 2.4 Set Terraform variables

Create a `terraform.tfvars` (gitignored):

```bash
cat > terraform/terraform.tfvars <<EOF
aws_region      = "us-east-2"
attacker_region = "eu-west-1"
environment     = "demo"
okta_org_url    = "https://<their-org>.okta.com"
EOF
```

### 2.5 Deploy Terraform

```bash
cd terraform
terraform plan
```

Review the plan — expect ~8-10 resources:
- 2 Lambda functions (JWKS + replayer)
- 2 IAM roles + 2 policy attachments
- 1 Lambda function URL (public, for JWKS)
- 1 S3 bucket (videos)
- 1 TLS private key
- SSM parameters for the generated keys

If the plan looks good:

```bash
terraform apply
```

### 2.6 Capture outputs

```bash
terraform output
```

Key outputs to note:
- `jwks_endpoint_url` — needed for SSF provider registration in Phase 3
- `session_replayer_lambda` — function name for real mode
- `attacker_region` — confirms the Lambda region
- `video_bucket` — for `--upload-s3` flag
- `ssm_prefix` — where secrets are stored

### 2.7 Verify Lambda functions

```bash
# Test JWKS endpoint
JWKS_URL=$(terraform output -raw jwks_endpoint_url)
curl -s "$JWKS_URL" | python3 -m json.tool

# Test session replayer Lambda
REPLAYER=$(terraform output -raw session_replayer_lambda)
aws lambda invoke --function-name "$REPLAYER" \
  --region $(terraform output -raw attacker_region) \
  --payload '{"cookie":"test","okta_domain":"test.okta.com"}' \
  /tmp/replayer-test.json
cat /tmp/replayer-test.json
```

The JWKS endpoint should return a JSON object with a `keys` array. The replayer test should return an error (expected — we sent a fake cookie) but confirms the Lambda is invokable.

## Outputs

- Terraform deployed: JWKS Lambda, session replayer Lambda, video bucket
- JWKS endpoint URL captured (for Phase 3)
- IAM role ARN configured for GitHub Actions (optional)
- Ready for Phase 3 (Okta configuration)
