variable "secret_name" {
  type        = string
  description = "Secret name to create"
}

variable "rotation_function_arn" {
  type        = string
  description = "Lambda function ARN to handle secret rotation"
}

variable "rotate_automatically_after_days" {
  type        = number
  description = "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_rotation#automatically_after_days"
  default     = 16
}

variable "keygen_params" {
  type        = object({ kty = string, len = string })
  description = "keygen params"
  default = {
    "kty" = "rsa"
    "len" = 2048
  }
}
