resource "aws_lambda_function" "secrets_rotation" {
  count = var.deploy_secrets_rotation ? 1 : 0

  function_name = "${var.function_name_prefix}-secrets-rotation"

  package_type  = "Image"
  image_uri     = var.image_url
  architectures = var.architectures

  image_config {
    command = ["himari_lambda_entrypoint.Himari::Aws::LambdaHandler.secrets_rotation_handler"]
  }

  role = var.iam_role_arn

  memory_size = 128
  timeout     = 20

  environment {
    variables = merge({
    }, var.environment)
  }
}

resource "aws_lambda_permission" "secrets_rotation_secretsmanager" {
  count = var.deploy_secrets_rotation ? 1 : 0

  statement_id   = "secretsmanager"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.secrets_rotation[0].function_name
  principal      = "secretsmanager.amazonaws.com"
  source_account = data.aws_caller_identity.current.account_id
}
