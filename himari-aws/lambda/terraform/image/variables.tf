variable "repository_name" {
  type        = string
  description = "Repository name to create on your AWS account"
}

variable "source_image_tag" {
  type        = string
  description = "Image tag for public.ecr.aws/sorah/himari-lambda. You can use Git commit hash on https://github.com/sorah/himari"
}

variable "architecture" {
  type        = string
  default     = "x86_64"
  description = "Lambda CPU architecture to copy from the multi-arch source image (x86_64 or arm64)"

  validation {
    condition     = contains(["x86_64", "arm64"], var.architecture)
    error_message = "architecture must be one of: x86_64, arm64."
  }
}
