variable "attacker_region" {
  description = "AWS region for the attacker Lambda function (should differ from victim)"
  type        = string
  default     = "eu-west-1"
}

variable "function_name" {
  description = "Name for the Lambda function"
  type        = string
  default     = "itp-demo-session-replayer"
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default = {
    Purpose   = "ITP Demo"
    ManagedBy = "Terraform"
  }
}
