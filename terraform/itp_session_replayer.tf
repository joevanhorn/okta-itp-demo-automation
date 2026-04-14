# ==============================================================================
# ITP Session Replayer Lambda (eu-west-1)
# ==============================================================================
# Deploys a Lambda function to eu-west-1 that replays an Okta session cookie
# from a different geographic region, triggering Okta's session hijacking
# detection for the ITP (Identity Threat Protection) demo.
#
# This is the "attacker" side of the real-mode ITP demo. The cookie is captured
# locally via headless browser (Playwright), then replayed by this Lambda from
# a different IP and region.
#
# Usage:
#   python3 scripts/trigger_itp_demo.py --mode real \
#     --user itp-demo-test@taskvantage.ai \
#     --attacker-lambda itp-demo-session-replayer \
#     --attacker-region eu-west-1 \
#     --monitor
# ==============================================================================

# --- Provider Alias for eu-west-1 ---

provider "aws" {
  alias  = "eu_west_1"
  region = "eu-west-1"
}

# --- IAM Role (Global — uses default provider) ---

resource "aws_iam_role" "itp_session_replayer" {
  name = "itp-demo-session-replayer-role"

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

resource "aws_iam_role_policy_attachment" "itp_session_replayer_basic" {
  role       = aws_iam_role.itp_session_replayer.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# --- Lambda Package ---

data "archive_file" "itp_session_replayer" {
  type        = "zip"
  source_file = "${path.module}/modules/session-replayer/lambda/replayer.py"
  output_path = "${path.module}/itp_session_replayer.zip"
}

# --- Lambda Function (eu-west-1) ---

resource "aws_lambda_function" "itp_session_replayer" {
  provider = aws.eu_west_1

  function_name = "itp-demo-session-replayer"
  description   = "ITP Demo - Replays Okta session cookies from eu-west-1 to trigger session hijacking detection"

  filename         = data.archive_file.itp_session_replayer.output_path
  source_code_hash = data.archive_file.itp_session_replayer.output_base64sha256

  handler = "replayer.handler"
  runtime = "python3.11"
  timeout = 30

  role = aws_iam_role.itp_session_replayer.arn
}
