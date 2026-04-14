terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  alias  = "attacker"
  region = var.attacker_region
}

# --- IAM Role for Lambda ---

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "replayer" {
  name               = "${var.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "replayer_basic" {
  role       = aws_iam_role.replayer.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# --- Lambda Function ---

data "archive_file" "replayer" {
  type        = "zip"
  source_file = "${path.module}/lambda/replayer.py"
  output_path = "${path.module}/lambda/replayer.zip"
}

resource "aws_lambda_function" "replayer" {
  provider = aws.attacker

  function_name = var.function_name
  description   = "ITP Demo - Replays Okta session cookies from a different region to trigger session hijacking detection"

  filename         = data.archive_file.replayer.output_path
  source_code_hash = data.archive_file.replayer.output_base64sha256

  handler = "replayer.handler"
  runtime = "python3.11"
  timeout = 30

  role = aws_iam_role.replayer.arn

  tags = var.tags
}
