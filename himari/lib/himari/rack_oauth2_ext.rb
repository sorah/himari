# frozen_string_literal: true

require 'rack/oauth2'

module Himari
  # RFC 9207 Authorization Server Issuer Identification, implemented as extensions to rack-oauth2.
  #
  # rack-oauth2 builds the grant redirect from the response object handed to the authorization
  # endpoint block, but constructs and finishes error redirects internally (Authorize#_call rescues
  # and calls e.finish), so those error objects are out of reach. Instead we teach rack-oauth2 to
  # carry an `iss` through both: the issuer is set on the request/response, and the response classes
  # merge it into their protocol_params (the parameters rack-oauth2 places on the redirect). Errors
  # copy it from the request the same way they copy state/redirect_uri.
  module RackOAuth2Ext
    # Carried by the grant response; always emitted because the grant is always a redirect.
    # Prepended onto the base response so every response type (Code::Response calls super) gains the
    # `iss` accessor, including the response objects the loaded extensions hand to the endpoint block.
    module IssuerParam
      attr_accessor :iss

      def protocol_params
        super.merge(iss:)
      end
    end

    # Carried by error responses, but only emitted when the error is actually delivered to the
    # client via redirect. RFC 9207 covers authorization responses, not the JSON error bodies
    # rack-oauth2 returns directly to the user agent when there is no trusted redirect_uri.
    module ErrorIssuerParam
      attr_accessor :iss

      def protocol_params
        redirect? ? super.merge(iss:) : super
      end
    end

    # rack-oauth2 stamps state and redirect_uri from the request onto every error it raises; thread
    # the issuer along the same path so ErrorIssuerParam has a value to emit.
    module RequestIssuer
      attr_accessor :iss

      private def error!(klass, error, description, options)
        super
      rescue Rack::OAuth2::Server::Abstract::Error => e
        e.iss = iss if e.respond_to?(:iss=)
        raise e
      end
    end

    Rack::OAuth2::Server::Authorize::Response.prepend(IssuerParam)
    Rack::OAuth2::Server::Authorize::Request.prepend(RequestIssuer)
    [
      Rack::OAuth2::Server::Authorize::BadRequest,
      Rack::OAuth2::Server::Authorize::ServerError,
      Rack::OAuth2::Server::Authorize::TemporarilyUnavailable,
    ].each { |klass| klass.prepend(ErrorIssuerParam) }
  end
end
