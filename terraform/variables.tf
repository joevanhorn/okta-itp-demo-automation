variable "aws_region" {
  description = "Primary AWS region for SSF JWKS endpoint and video storage"
  type        = string
  default     = "us-east-2"
}

variable "attacker_region" {
  description = "AWS region for the attacker Lambda (should differ from primary to trigger geo-based detection)"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Environment name used for SSM parameter paths and resource naming"
  type        = string
  default     = "prod"
}

variable "okta_org_url" {
  description = "Okta org URL (e.g., https://acme.okta.com)"
  type        = string
}

variable "ssm_prefix" {
  description = "SSM Parameter Store prefix for ITP secrets"
  type        = string
  default     = "/itp-demo"
}

variable "video_expiry_days" {
  description = "Number of days to retain demo recording videos in S3"
  type        = number
  default     = 90
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
