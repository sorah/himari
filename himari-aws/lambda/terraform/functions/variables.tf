variable "iam_role_arn" {
  type        = string
  description = "IAM role arn for functions"
}

variable "image_url" {
  type        = string
  description = "Image url for deploy"
}

variable "dynamodb_table_name" {
  type        = string
  description = "dynamodb table name to use"
}

variable "create_dynamodb_table" {
  type        = bool
  description = "Create dynamodb table"
  default     = true
}

variable "function_name_prefix" {
  type        = string
  description = "function name prefix"
}

variable "deploy_rack" {
  type        = bool
  description = "Deploy rack function"
  default     = true
}

variable "rack_memory_size" {
  type    = number
  default = 256
}

variable "deploy_secrets_rotation" {
  type        = bool
  description = "Deploy secrets rotation function"
  default     = true
}

variable "enable_function_url" {
  type        = bool
  description = "Enable function URL"
  default     = true
}

variable "config_ru" {
  type        = string
  description = "File content of config.ru"
  default     = "raise 'empty config_ru'\n"
}

variable "environment" {
  type        = map(any)
  description = "Additional environment variables"
  default     = {}
}

variable "architectures" {
  type    = list(string)
  default = ["x86_64"]
}
