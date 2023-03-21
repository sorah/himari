resource "aws_iam_role" "role" {
  name                 = var.role_name
  description          = var.role_description
  assume_role_policy   = data.aws_iam_policy_document.role-trust.json
  permissions_boundary = var.role_permissions_boundary
}

data "aws_iam_policy_document" "role-trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "lambda.amazonaws.com"
      ]
    }
  }
}

resource "aws_iam_role_policy_attachment" "role-AWSLambdaBasicExecutionRole" {
  role       = aws_iam_role.role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "role-dynamodb" {
  count  = local.dynamodb_table_arn != null ? 1 : 0
  role   = aws_iam_role.role.name
  policy = data.aws_iam_policy_document.role-dynamodb.json
}

data "aws_iam_policy_document" "role-dynamodb" {
  statement {
    effect = "Allow"
    actions = [
      "dynamodb:DeleteItem",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
    ]
    resources = [local.dynamodb_table_arn]
  }
}

resource "aws_iam_role_policy" "role-secretsmanager" {
  count  = length(var.secret_arns) > 0 ? 1 : 0
  role   = aws_iam_role.role.name
  policy = data.aws_iam_policy_document.role-secretsmanager.json
}

data "aws_iam_policy_document" "role-secretsmanager" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",

    ]
    resources = toset(var.secret_arns)
  }
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage",
    ]
    dynamic "condition" {
      for_each = var.secrets_rotation_function_arn != null ? { hardening = true } : {}
      content {
        test     = "StringEquals"
        variable = "lambda:SourceFunctionArn"
        values   = [var.secrets_rotation_function_arn]
      }
    }
    resources = toset(var.secret_arns)
  }

}
