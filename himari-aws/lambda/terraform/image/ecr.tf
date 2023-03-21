resource "aws_ecr_repository" "repo" {
  name = var.repository_name
}

resource "aws_ecr_repository_policy" "repo-lambda" {
  repository = aws_ecr_repository.repo.name
  policy     = data.aws_iam_policy_document.repo-lambda.json
}

data "aws_iam_policy_document" "repo-lambda" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = [
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer"
    ]
  }
}

resource "aws_ecr_lifecycle_policy" "repo" {
  repository = aws_ecr_repository.repo.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 10
        description  = "expire old images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
