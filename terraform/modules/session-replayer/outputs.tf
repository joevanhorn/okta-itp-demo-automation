output "lambda_function_name" {
  description = "Name of the attacker Lambda function"
  value       = aws_lambda_function.replayer.function_name
}

output "lambda_function_arn" {
  description = "ARN of the attacker Lambda function"
  value       = aws_lambda_function.replayer.arn
}

output "lambda_region" {
  description = "Region where the attacker Lambda is deployed"
  value       = var.attacker_region
}
