# context must be repository root
FROM public.ecr.aws/lambda/ruby:3.4 as builder
RUN --mount=type=cache,target=/var/cache/dnf dnf update -y && dnf install -y gcc gcc-c++ make

COPY ./himari/himari.gemspec ${LAMBDA_TASK_ROOT}/app/himari/himari.gemspec
COPY ./himari/lib/himari/version.rb ${LAMBDA_TASK_ROOT}/app/himari/lib/himari/version.rb

COPY ./himari-aws/himari-aws.gemspec ${LAMBDA_TASK_ROOT}/app/himari-aws/himari-aws.gemspec
COPY ./himari-aws/lib/himari/aws/version.rb ${LAMBDA_TASK_ROOT}/app/himari-aws/lib/himari/aws/version.rb

COPY ./omniauth-himari/omniauth-himari.gemspec ${LAMBDA_TASK_ROOT}/app/omniauth-himari/omniauth-himari.gemspec
COPY ./omniauth-himari/lib/omniauth-himari/version.rb ${LAMBDA_TASK_ROOT}/app/omniauth-himari/lib/omniauth-himari/version.rb

COPY ./himari-aws/lambda/Gemfile* ${LAMBDA_TASK_ROOT}/app/himari-aws/lambda/
WORKDIR ${LAMBDA_TASK_ROOT}/app

ENV LANG=C.UTF-8
ENV BUNDLE_GEMFILE ${LAMBDA_TASK_ROOT}/app/himari-aws/lambda/Gemfile
ENV BUNDLE_PATH ${LAMBDA_TASK_ROOT}/vendor/bundle
ENV BUNDLE_DEPLOYMENT 1
ENV BUNDLE_JOBS 16
ENV HIMARI_LAMBDA_IMAGE 1
RUN bundle install

COPY . ${LAMBDA_TASK_ROOT}/app

FROM public.ecr.aws/lambda/ruby:3.4

COPY --from=builder ${LAMBDA_TASK_ROOT}/vendor ${LAMBDA_TASK_ROOT}/vendor
COPY . ${LAMBDA_TASK_ROOT}/app

COPY ./himari-aws/lambda/entrypoint.rb ${LAMBDA_TASK_ROOT}/himari_lambda_entrypoint.rb

WORKDIR ${LAMBDA_TASK_ROOT}/app
ENV LANG=C.UTF-8
ENV BUNDLE_GEMFILE ${LAMBDA_TASK_ROOT}/app/himari-aws/lambda/Gemfile
ENV BUNDLE_PATH ${LAMBDA_TASK_ROOT}/vendor/bundle
ENV BUNDLE_DEPLOYMENT 1
ENV HIMARI_LAMBDA_IMAGE 1
CMD [ "himari_lambda_entrypoint.Himari::Aws::LambdaHandler.rack_handler" ]
