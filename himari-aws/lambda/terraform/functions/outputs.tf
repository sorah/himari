output "dynamodb_table_name" {
  value = var.dynamodb_table_name
}

output "dynamodb_table_arn" {
  value = var.create_dynamodb_table ? aws_dynamodb_table.table[0].arn : null
}

output "function_url" {
  value = (var.deploy_rack && var.enable_function_url) ? aws_lambda_function_url.rack[0].function_url : null
}

output "rack_function_arn" {
  value = var.deploy_rack ? aws_lambda_function.rack[0].arn : null
}

output "secrets_rotation_function_arn" {
  value = var.deploy_secrets_rotation ? aws_lambda_function.secrets_rotation[0].arn : null
}
