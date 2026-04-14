output "jwks_endpoint_url" {
  description = "Public JWKS endpoint URL for Okta SSF provider registration"
  value       = try(aws_lambda_function_url.ssf_jwks.function_url, "")
}

output "session_replayer_lambda" {
  description = "Name of the attacker Lambda function for session replay"
  value       = try(module.session_replayer.lambda_function_name, "")
}

output "attacker_region" {
  description = "AWS region where the attacker Lambda runs"
  value       = var.attacker_region
}

output "video_bucket" {
  description = "S3 bucket for demo recording videos"
  value       = try(aws_s3_bucket.itp_demo_videos.id, "")
}

output "ssm_prefix" {
  description = "SSM Parameter Store prefix for ITP secrets"
  value       = var.ssm_prefix
}
