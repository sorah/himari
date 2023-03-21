output "secret_arn" {
  value = aws_secretsmanager_secret.signing_key.arn
}
