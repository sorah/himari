ephemeral "aws_ecr_authorization_token" "repo" {
  registry_id = aws_ecr_repository.repo.registry_id
}

locals {
  # Map Lambda's architecture notation to the source image's OS/arch so skopeo
  # picks the matching image out of the multi-arch index deterministically,
  # regardless of the host running Terraform.
  skopeo_platform = {
    x86_64 = { os = "linux", arch = "amd64" }
    arm64  = { os = "linux", arch = "arm64" }
  }[var.architecture]
}

resource "null_resource" "copy-image" {
  triggers = {
    region           = data.aws_region.current.name
    repository_url   = aws_ecr_repository.repo.repository_url
    source_image_tag = var.source_image_tag
    architecture     = var.architecture
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    # public.ecr.aws is pulled anonymously; only the destination ECR needs credentials.
    # The password is fed over stdin into a temporary authfile rather than passed as a
    # command-line argument, so it never appears in the process argument list.
    command = <<-EOT
      set -euo pipefail
      authfile="$(mktemp)"
      trap 'rm -f "$authfile"' EXIT
      printf '%s' "$DEST_PASSWORD" | skopeo login --username AWS --password-stdin --authfile "$authfile" "$${REPOSITORY_URL%%/*}"
      skopeo copy --authfile "$authfile" --override-os "$OVERRIDE_OS" --override-arch "$OVERRIDE_ARCH" "docker://public.ecr.aws/sorah/himari-lambda:$SOURCE_IMAGE_TAG" "docker://$REPOSITORY_URL:$SOURCE_IMAGE_TAG"
    EOT

    environment = {
      DEST_PASSWORD    = ephemeral.aws_ecr_authorization_token.repo.password
      REPOSITORY_URL   = aws_ecr_repository.repo.repository_url
      SOURCE_IMAGE_TAG = var.source_image_tag
      OVERRIDE_OS      = local.skopeo_platform.os
      OVERRIDE_ARCH    = local.skopeo_platform.arch
    }
  }
}
