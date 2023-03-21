variable "role_name" {
  type        = string
  description = "IAM Role name to create"
}

variable "role_description" {
  type        = string
  description = "IAM Role description to specify"
  default     = "sorah/himari lambda function role"
}

variable "role_permissions_boundary" {
  type        = string
  description = "IAM Role permissions boundary to specify"
  default     = null
}

variable "dynamodb_table_arn" {
  type        = string
  description = "DynamoDB Table ARN"
  default     = null
}

variable "dynamodb_table_name" {
  type        = string
  description = "DynamoDB Table name"
  default     = null
}

variable "secret_arns" {
  type        = set(string)
  description = "Secrets Manager secret ARNs"
  default     = null
}

variable "secrets_rotation_function_arn" {
  type        = string
  description = "ARN of rotation function. If set, it will be used to harden the write action policy"
  default     = null
}

locals {
  dynamodb_table_arn = coalesce(var.dynamodb_table_arn, var.dynamodb_table_name != null ? "arn:aws:dynamodb:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/${var.dynamodb_table_name}" : null)
}
