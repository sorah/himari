resource "aws_lambda_function" "rack" {
  count = var.deploy_rack ? 1 : 0

  function_name = "${var.function_name_prefix}-rack"

  package_type  = "Image"
  image_uri     = var.image_url
  architectures = var.architectures

  image_config {
    command = ["himari_lambda_entrypoint.Himari::Aws::LambdaHandler.rack_handler"]
  }

  role = var.iam_role_arn

  memory_size = var.rack_memory_size
  timeout     = 20

  environment {
    variables = merge({
      HIMARI_RACK_DYNAMODB_TABLE = var.dynamodb_table_name
      HIMARI_DYNAMODB_TABLE      = var.dynamodb_table_name

      # dependency trick. see below
      HIMARI_RACK_DIGEST = nonsensitive(jsondecode(aws_dynamodb_table_item.config_ru[local.config_ru_dgst].item)["dgst"]["S"])

      RACK_ENV = "production"
    }, var.environment)
  }

  depends_on = [aws_dynamodb_table_item.config_ru]
}

resource "aws_lambda_function_url" "rack" {
  count              = (var.deploy_rack && var.enable_function_url) ? 1 : 0
  function_name      = aws_lambda_function.rack[0].function_name
  authorization_type = "NONE"
}

resource "aws_dynamodb_table_item" "config_ru" {
  # Employing dependency trick to make sure a previous config_ru item removed after the function environment value update.
  # By using for_each every updates will be a new resource and is referred by aws_lambda_function as a dependency, old item will be removed after updating the function completes.
  for_each = { "${local.config_ru_dgst}" = var.config_ru }

  table_name = var.dynamodb_table_name
  hash_key   = "pk"
  range_key  = "sk"

  # using sensitive to supress unwanted diff, and diff is useful as we use for_each here
  item = sensitive(jsonencode({
    "pk"   = { "S" = "rack" },
    "sk"   = { "S" = "rack:${each.key}" },
    "dgst" = { "S" = each.key },
    "file" = { "S" = each.value },
  }))

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_dynamodb_table.table]
}

locals {
  config_ru_dgst = base64sha256(var.config_ru)
}
