# Himari Lambda Container Image

## Deploy

- See [./terraform/](./terraform/) for quick deployment using Terraform modules.

## Image

### Prebuilt image

- https://gallery.ecr.aws/sorah/himari-lambda
- `public.ecr.aws/sorah/himari-lambda`

Images are tagged with commit SHA.

### Build an image

Run the following at the repository root:

```
docker build -f himari-aws/lambda/Dockerfile .
```

### Usage

The same container image supports multiple handlers:

#### Rack app for API Gateway v2, Function URL, ALB target

- Handler: `himari_lambda_entrypoint.Himari::Aws::LambdaHandler.rack_handler`

Served through [apigatewayv2_rack](https://github.com/sorah/apigatewayv2_rack).

This handler reads `config.ru` from:

- `${LAMBDA_TASK_ROOT}/config.ru` in a container image
- DynamoDB Table item (pk=`rack`, sk=`rack:${HIMARI_RACK_DIGEST}`, file=config.ru content) on table `$HIMARI_RACK_DYNAMODB_TABLE`
  - where HIMARI_RACK_DIGEST must be [base64'd sha256 hash](https://developer.hashicorp.com/terraform/language/functions/base64sha256) of `file` attribute

#### Secrets Manager automatic rotation handler

- Handler: `himari_lambda_entrypoint.Himari::Aws::LambdaHandler.secrets_rotation_handler`
