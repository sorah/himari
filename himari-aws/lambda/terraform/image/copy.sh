#!/bin/bash -xe
aws ecr get-login-password | docker login --username AWS --password-stdin "${REPOSITORY_URL}"
docker pull "public.ecr.aws/sorah/himari-lambda:${SOURCE_IMAGE_TAG}"
docker tag "public.ecr.aws/sorah/himari-lambda:${SOURCE_IMAGE_TAG}" "${REPOSITORY_URL}:${SOURCE_IMAGE_TAG}"
docker push "${REPOSITORY_URL}:${SOURCE_IMAGE_TAG}"
