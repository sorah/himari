output "image" {
  value = {
    url = "${aws_ecr_repository.repo.repository_url}:${var.source_image_tag}"

    repository_url = aws_ecr_repository.repo.repository_url
    repository_arn = aws_ecr_repository.repo.arn
  }
  depends_on = [null_resource.copy-image]
}
