# frozen_string_literal: true

require 'rack/oauth2'
require 'digest/sha2'
require 'openid_connect'
require 'himari/access_token'
require 'himari/refresh_token'
require 'himari/id_token'
require 'himari/storages/base'
require 'himari/services/downstream_authorization'
require 'himari/services/upstream_authentication'

module Himari
  module Services
    class OidcTokenEndpoint
      class SigningKeyMissing < StandardError; end

      Issued = Struct.new(:access, :id_token_jwt, :signing_key, keyword_init: true)

      # @param client_provider [Himari::ProviderChain<Himari::ClientRegistration>]
      # @param signing_key_provider [Himari::ProviderChain<Himari::SigningKey>]
      # @param storage [Himari::Storages::Base]
      # @param issuer [String]
      # @param logger [Logger]
      def initialize(client_provider:, signing_key_provider:, storage:, issuer:, logger: nil)
        @client_provider = client_provider
        @signing_key_provider = signing_key_provider
        @storage = storage
        @issuer = issuer
        @logger = logger
      end

      def call(env)
        app(env).call(env)
      rescue Rack::OAuth2::Server::Abstract::Error => e
        @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: returning error', req: env['himari.request_as_log'], err: e.class.inspect, err_content: e.protocol_params))
        e.finish
      end

      def app(env)
        Rack::OAuth2::Server::Token.new do |req, res|
          client = @client_provider.find(id: req.client_id)
          unless client
            @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_client, no client registration', req: env['himari.request_as_log'], client_id: req.client_id))
            next req.invalid_client!
          end
          # Public clients (token_endpoint_auth_method=none) present no secret; they are bound
          # to the authorization code by PKCE and the client_id check in handle_authorization_code.
          if client.confidential? && !client.match_secret?(req.client_secret)
            @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_client, client secret mismatch', req: env['himari.request_as_log'], client: client.as_log))
            next req.invalid_client!
          end

          case req.grant_type
          when :authorization_code
            handle_authorization_code(env, req, res, client)
          when :refresh_token
            handle_refresh_token(env, req, res, client)
          else
            req.unsupported_response_type!
          end
        end
      end

      private def handle_authorization_code(env, req, res, client)
        authz = @storage.find_authorization(req.code)
        unless authz
          @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_grant, no grant code found', req: env['himari.request_as_log'], client: client.as_log))
          return req.invalid_grant!
        end
        unless authz.client_id == client.id
          @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_grant, grant client_id mismatch', req: env['himari.request_as_log'], client: client.as_log, grant: authz.as_log))
          return req.invalid_grant!
        end
        unless authz.valid_redirect_uri?(req.redirect_uri)
          @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_grant, redirect_uri mismatch', req: env['himari.request_as_log'], client: client.as_log, grant: authz.as_log))
          return req.invalid_grant!
        end
        if authz.expiry <= Time.now.to_i
          @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_grant, expired grant', req: env['himari.request_as_log'], client: client.as_log, grant: authz.as_log))
          return req.invalid_grant!
        end

        if authz.pkce?
          if req.verify_code_verifier!(authz.code_challenge, authz.code_challenge_method)
            # do nothing
          else
            # :nocov:
            @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_grant, invalid pkce', req: env['himari.request_as_log'], client: client.as_log, grant: authz.as_log))
            return req.invalid_grant!
            # :nocov:
          end
        elsif client.require_pkce
          @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_grant, pkce is mandatory', req: env['himari.request_as_log'], client: client.as_log, grant: authz.as_log))
          return req.invalid_grant!
        end

        issued = issue_access_and_id(
          client: client,
          claims: authz.claims,
          lifetime: authz.lifetime,
          openid: authz.openid,
          session_handle: authz.session_handle,
          nonce: authz.nonce,
        )

        refresh = nil
        if authz.offline_access && authz.session_handle && authz.lifetime&.refresh_token
          refresh = RefreshToken.make(client_id: client.id, claims: authz.claims, session_handle: authz.session_handle, openid: authz.openid, scopes: authz.scopes, lifetime: authz.lifetime.refresh_token)
          @storage.put_refresh_token(refresh)
        end

        bearer = issued.access.to_bearer
        bearer.refresh_token = refresh.format.to_s if refresh
        res.access_token = bearer
        res.id_token = issued.id_token_jwt if issued.id_token_jwt

        @storage.delete_authorization(authz)
        @logger&.info(Himari::LogLine.new('OidcTokenEndpoint: issued', req: env['himari.request_as_log'], client: client.as_log, grant: authz.as_log, token: issued.access.as_log, refresh_token: refresh&.as_log, signing_key_kid: issued.signing_key&.id))
      end

      private def handle_refresh_token(env, req, res, client)
        given_token_str = req.refresh_token
        unless given_token_str
          return reject_refresh!(env, req, client, 'no refresh_token given')
        end

        begin
          parsed = Himari::RefreshToken.parse(given_token_str)
        rescue Himari::TokenString::InvalidFormat => e
          return reject_refresh!(env, req, client, 'invalid refresh_token format', err: e.class.inspect)
        end

        refresh = @storage.find_refresh_token(parsed.handle)
        unless refresh
          return reject_refresh!(env, req, client, 'unknown refresh_token')
        end

        begin
          refresh.verify!(secret: parsed.secret)
        rescue Himari::TokenString::Error => e
          return reject_refresh!(env, req, client, 'refresh_token verify failed', refresh: refresh, err: e.class.inspect)
        end

        unless refresh.client_id == client.id
          return reject_refresh!(env, req, client, 'refresh_token client_id mismatch', refresh: refresh)
        end

        session = refresh.session_handle && @storage.find_session(refresh.session_handle)
        unless session
          return reject_refresh!(env, req, client, 'refresh_token has no session', refresh: refresh)
        end

        unless session.refreshable?
          return reject_refresh!(env, req, client, 'session is not refreshable (no refresh_info)', refresh: refresh, session: session.as_log)
        end

        unless session.active?
          return reject_refresh!(env, req, client, 'session expired', refresh: refresh, session: session.as_log)
        end

        rack_request = Rack::Request.new(env)

        begin
          authn = Himari::Services::UpstreamAuthentication.revalidate_from_request(session: session, request: rack_request).perform
        rescue Himari::Services::UpstreamAuthentication::UnauthorizedError => e
          return reject_refresh!(env, req, client, 'refresh upstream authn denied', refresh: refresh, session: session.as_log, result: e.as_log)
        end

        updated_session = authn.session_data

        begin
          downstream = Himari::Services::DownstreamAuthorization.from_request(session: updated_session, client: client, request: rack_request, grant_type: :refresh_token, requested_scopes: refresh.scopes).perform
        rescue Himari::Services::DownstreamAuthorization::ForbiddenError => e
          return reject_refresh!(env, req, client, 'refresh downstream authz denied', refresh: refresh, session: updated_session.as_log, result: e.as_log)
        end

        # Refresh lifetime is recomputed by the authz rules on every refresh; if it is no
        # longer configured the session is no longer refreshable. Fail closed.
        unless downstream.lifetime&.refresh_token
          return reject_refresh!(env, req, client, 'refresh_token lifetime no longer configured', refresh: refresh, session: updated_session.as_log)
        end

        # Rotate the token in place; verify! above recorded which secret the client presented,
        # which rotate keeps valid as the previous one. The token's original expiry is
        # preserved (absolute cap); the lifetime guard above only gates whether refresh is
        # still permitted by the rules, not how long the rotated token lives.
        rotated = refresh.rotate(claims: downstream.claims, openid: refresh.openid)

        # Compare-and-swap on the version we read. A concurrent refresh that already rotated
        # this token bumps the version, so the loser's write conflicts. Reject the loser
        # without revoking — the winner's rotation (same handle) must survive.
        begin
          @storage.put_refresh_token(rotated, if_version: refresh.version)
        rescue Himari::Storages::Base::Conflict
          return reject_refresh!(env, req, client, 'refresh_token version conflict (concurrent use)', refresh: refresh, revoke: false)
        end

        @storage.put_session(updated_session, overwrite: true)

        # OIDC core §12.2: refreshed ID Token MAY be returned, with no nonce on refresh.
        issued = issue_access_and_id(
          client: client,
          claims: downstream.claims,
          lifetime: downstream.lifetime,
          openid: refresh.openid,
          session_handle: updated_session.handle,
          nonce: nil,
        )

        bearer = issued.access.to_bearer
        bearer.refresh_token = rotated.format.to_s
        res.access_token = bearer
        res.id_token = issued.id_token_jwt if issued.id_token_jwt

        @logger&.info(Himari::LogLine.new('OidcTokenEndpoint: refreshed', req: env['himari.request_as_log'], client: client.as_log, session: updated_session.as_log, token: issued.access.as_log, refresh_token: rotated.as_log, prev_version: refresh.version, secret_slot: refresh.verification&.via, signing_key_kid: issued.signing_key&.id))
      end

      # Reject a refresh request with invalid_grant. By default this revokes the presented
      # refresh token when one was looked up, keeping refresh failures fail-closed against
      # replay. revoke: false is used only for the concurrent-conflict path, where the
      # winning request has already rotated this same handle and must not be revoked.
      private def reject_refresh!(env, req, client, reason, refresh: nil, revoke: true, **fields)
        log = {req: env['himari.request_as_log'], client: client.as_log}
        log[:refresh] = refresh.as_log if refresh
        @logger&.warn(Himari::LogLine.new("OidcTokenEndpoint: invalid_grant, #{reason}", **log, **fields))
        @storage.delete_refresh_token(refresh) if refresh && revoke
        req.invalid_grant!
      end

      # Mint an access token (and, for OIDC, an id_token JWT). Refresh tokens are handled
      # separately by each grant path: the authorization_code path mints a fresh one, while
      # the refresh path rotates the presented token in place.
      private def issue_access_and_id(client:, claims:, lifetime:, openid:, session_handle:, nonce:)
        access = AccessToken.make(client_id: client.id, claims: claims, session_handle: session_handle, lifetime: lifetime.access_token)
        @storage.put_token(access)

        signing_key = nil
        id_token_jwt = nil
        if openid
          signing_key = @signing_key_provider.find(group: client.preferred_key_group, active: true)
          raise SigningKeyMissing unless signing_key

          id_token_jwt = IdToken.new(
            claims: claims,
            client_id: client.id,
            nonce: nonce,
            signing_key: signing_key,
            issuer: @issuer,
            access_token: access.format.to_s,
            lifetime: lifetime.id_token,
          ).to_jwt
        end

        Issued.new(access: access, id_token_jwt: id_token_jwt, signing_key: signing_key)
      end
    end
  end
end
