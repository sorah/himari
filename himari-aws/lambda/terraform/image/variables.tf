variable "repository_name" {
  type        = string
  description = "Repository name to create on your AWS account"
}

variable "source_image_tag" {
  type        = string
  description = "Image tag for public.ecr.aws/sorah/himari-lambda. You can use Git commit hash on https://github.com/sorah/himari"
}
