resource "aws_secretsmanager_secret" "signing_key" {
  name = var.secret_name

  tags = {
    HimariKey = base64encode(jsonencode(var.keygen_params))
  }
}

resource "aws_secretsmanager_secret_rotation" "signing_key" {
  secret_id           = aws_secretsmanager_secret.signing_key.id
  rotation_lambda_arn = var.rotation_function_arn

  # XXX: https://github.com/hashicorp/terraform-provider-aws/issues/22969
  rotation_rules {
    automatically_after_days = 16
  }

}
