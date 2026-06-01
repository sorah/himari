# Himari Terraform modules for AWS Lambda

himari-aws/lambda/terraform provides the following modules:

- **iam:** to establish IAM role
- **image:** to copy prebuilt container image for Lambda from ECR Public
- **functions:** to deploy Lambda function
- **signing_key:** to create a secret with auto rotation enabled on Secrets Manager

## iam

Provisions IAM role for Lambda functions.

```terraform
module "himari_iam" {
  source = "github.com/sorah/himari//himari-aws/lambda/terraform/iam"

  role_name = "HimariRole"

  # for policy hardening
  secrets_rotation_function_arn = module.himari_functions.secrets_rotation_function_arn

  # Add grants
  dynamodb_table_arn  = module.himari_functions.dynamodb_table_arn
  secret_arns         = toset([module.himari_signing_key.secret_arn])
}
```

## image

Create ECR private repository then mirror specified image tag from https://gallery.ecr.aws/sorah/himari-lambda

```terraform
module "himari_image" {
  source = "github.com/sorah/himari//himari-aws/lambda/terraform/image"

  repository_name  = "himari-lambda"
  source_image_tag = "" # Replace with image tag
  architecture     = "x86_64" # or arm64; must match the Lambda architecture
}
```

- Uses null_resource with `skopeo` command to copy the image to ECR private locally (requires `skopeo` on the machine running Terraform)
- `architecture` selects which platform to copy out of the multi-arch source image (defaults to `x86_64`); set it to match the `architecture` you pass to the functions module
- Requires Terraform >= 1.10 and AWS provider >= 5.83 (ephemeral resource for ECR credentials)
- Prebuilt image tag is based on git commit SHA: https://github.com/sorah/himari/commits/main

## functions

Deploy lambda functions and DynamoDB table

```terraform
module "himari_functions" {
  source = "github.com/sorah/himari//himari-aws/lambda/terraform/functions"

  iam_role_arn = module.himari_iam.role_arn
  image_url    = module.himari_image.image.url

  dynamodb_table_name  = "himari"
  function_name_prefix = "himari"

  config_ru = file("${path.module}/config.ru")

  environment = {
    HIMARI_SIGNING_KEY_ARN   = module.himari_signing_key.secret_arn
    HIMARI_SECRET_PARAMS_ARN = aws_secretsmanager_secret.params.arn
  }
}
```

## signing_key

```terraform
module "himari_signing_key" {
  source = "github.com/sorah/himari//himari-aws/lambda/terraform/signing_key"

  secret_name = "himari-prd-signing-key"

  rotation_function_arn           = module.himari_functions.secrets_rotation_function_arn
  rotate_automatically_after_days = 20
}
```

## misc (not modules)

Use secrets manager to store additional secrets like upstream client secrets and SECRET_KEY_BASE...

```terraform
resource "aws_secretsmanager_secret" "params" {
  name = "himari-secret-params"
}
```
