# ==============================================================================
# SSF (Shared Signals Framework) JWKS Endpoint
# ==============================================================================
# Hosts a public JWKS endpoint via Lambda Function URL for SSF demo.
# Okta fetches this JWKS to verify Security Event Token (SET) signatures.
#
# Resources created:
#   - RSA key pair (tls_private_key)
#   - Lambda function serving JWKS JSON
#   - Lambda Function URL (public, no auth)
#   - SSM parameters for private key and provider config
#   - IAM role for Lambda execution
#
# After terraform apply:
#   1. Run setup_ssf_provider.py to register the provider with Okta
#   2. Use trigger_itp_demo.py --mode ssf to send signals
# ==============================================================================

# --- Key Generation ---

resource "random_id" "ssf_key_id" {
  byte_length = 4
  prefix      = "ssf-demo-"
}

resource "tls_private_key" "ssf_demo" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Convert public key PEM to JWKS format
data "external" "ssf_jwks" {
  program = ["python3", "${path.module}/../scripts/helpers/pem_to_jwks.py"]

  query = {
    public_key_pem = tls_private_key.ssf_demo.public_key_pem
    key_id         = random_id.ssf_key_id.hex
  }
}

# --- Lambda Function ---

data "archive_file" "ssf_jwks_lambda" {
  type        = "zip"
  output_path = "${path.module}/ssf_jwks_lambda.zip"

  source {
    content  = <<-PYTHON
import json
import os

def handler(event, context):
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=3600",
        },
        "body": os.environ["JWKS_JSON"],
    }
    PYTHON
    filename = "index.py"
  }
}

resource "aws_iam_role" "ssf_jwks_lambda" {
  name = "ssf-demo-jwks-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssf_jwks_lambda_basic" {
  role       = aws_iam_role.ssf_jwks_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "ssf_jwks" {
  function_name    = "ssf-demo-jwks"
  role             = aws_iam_role.ssf_jwks_lambda.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.ssf_jwks_lambda.output_path
  source_code_hash = data.archive_file.ssf_jwks_lambda.output_base64sha256
  timeout          = 5
  memory_size      = 128

  environment {
    variables = {
      JWKS_JSON = data.external.ssf_jwks.result.jwks_json
    }
  }
}

resource "aws_lambda_function_url" "ssf_jwks" {
  function_name      = aws_lambda_function.ssf_jwks.function_name
  authorization_type = "NONE"
}

# --- SSM Parameters ---

resource "aws_ssm_parameter" "ssf_private_key" {
  name        = "${var.ssm_prefix}/ssf/private-key"
  description = "SSF Demo - RSA private key for SET signing"
  type        = "SecureString"
  value       = tls_private_key.ssf_demo.private_key_pem
}

resource "aws_ssm_parameter" "ssf_provider_config" {
  name        = "${var.ssm_prefix}/ssf/provider-config"
  description = "SSF Demo - Provider configuration (update provider_id after Okta registration)"
  type        = "String"
  value = jsonencode({
    issuer        = aws_lambda_function_url.ssf_jwks.function_url
    jwks_url      = aws_lambda_function_url.ssf_jwks.function_url
    key_id        = random_id.ssf_key_id.hex
    provider_name = "ITP Demo Signal Source"
    provider_id   = "pending-registration"
  })

  lifecycle {
    ignore_changes = [value]
  }
}

# --- Outputs ---

output "ssf_jwks_url" {
  description = "Public JWKS URL for SSF provider registration"
  value       = aws_lambda_function_url.ssf_jwks.function_url
}

output "ssf_key_id" {
  description = "Key ID used in JWKS and SET headers"
  value       = random_id.ssf_key_id.hex
}

output "ssf_issuer" {
  description = "Issuer URL for SSF provider (same as JWKS URL)"
  value       = aws_lambda_function_url.ssf_jwks.function_url
}
