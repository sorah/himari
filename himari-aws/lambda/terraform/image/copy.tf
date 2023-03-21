resource "null_resource" "copy-image" {
  triggers = {
    region           = data.aws_region.current.name
    repository_url   = aws_ecr_repository.repo.repository_url
    source_image_tag = var.source_image_tag
  }
  provisioner "local-exec" {
    command = "cd ${path.module} && ./copy.sh"
    environment = {
      AWS_REGION         = data.aws_region.current.name
      AWS_DEFAULT_REGION = data.aws_region.current.name

      REPOSITORY_URL   = aws_ecr_repository.repo.repository_url
      SOURCE_IMAGE_TAG = var.source_image_tag
    }
  }
}
