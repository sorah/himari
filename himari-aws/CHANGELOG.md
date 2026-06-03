## [Unreleased]

### Enhancements

- Lambda image: copy the prebuilt image with skopeo instead of docker (gains an `architecture` input), with Terraform AWS provider v6 compatibility and a `role_name` output [#18](https://github.com/sorah/himari/pull/18)
- DynamoDB storage: compare-and-swap writes backing refresh-token rotation [#14](https://github.com/sorah/himari/pull/14)
- Lambda image: bundle `omniauth-entra-id` and `omniauth-okta`, depend explicitly on `aws-sdk-ssm` and `aws-sdk-secretsmanager`, and make `rack-cors` available.

### Changes

- Lambda image: Ruby 4.0, build on dnf, and rolled dependencies (including `apigatewayv2_rack` 0.5.0).

## [0.2.0] - 2023-03-22

- Initial release: `Himari::Aws::DynamodbStorage`, Secrets Manager signing key provider and rotation handler, prebuilt Lambda container image, and Terraform modules.
