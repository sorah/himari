# frozen_string_literal: true

require 'himari/authorization_code'
require 'himari/access_token'
require 'himari/refresh_token'
require 'himari/session_data'
require 'himari/dynamic_client_registration'

module Himari
  module Storages
    module Base
      class Conflict < StandardError; end

      def find_authorization(code)
        content = read('authz', code)
        content && AuthorizationCode.new(**content)
      end

      def put_authorization(authz, overwrite: false)
        write('authz', authz.code, authz.as_json, overwrite: overwrite)
      end

      def delete_authorization(authz)
        delete_authorization_by_code(authz.code)
      end

      def delete_authorization_by_code(code)
        delete('authz', code)
      end

      def find_token(handle)
        content = read('token', handle)
        content[:handle] = content.delete(:handle) if content.key?(:handler) # compat
        content && AccessToken.new(**content)
      end

      def put_token(token, overwrite: false)
        write('token', token.handle, token.as_json, overwrite: overwrite)
      end

      def delete_token(token)
        delete_authorization_by_token(token.handle)
      end

      def delete_token_by_handle(handle)
        delete('token', handle)
      end

      def find_refresh_token(handle)
        content = read('refresh', handle)
        content && RefreshToken.new(**content)
      end

      # @param if_version [Integer, nil] when given, only write if the stored record's
      #   version equals this value (compare-and-swap); raises Conflict otherwise.
      def put_refresh_token(token, overwrite: false, if_version: nil)
        write('refresh', token.handle, token.as_json, overwrite: overwrite, if_version: if_version)
      end

      def delete_refresh_token(token)
        delete_refresh_token_by_handle(token.handle)
      end

      def delete_refresh_token_by_handle(handle)
        delete('refresh', handle)
      end

      def find_dynamic_client(id)
        # ids are server-generated url-safe base64; reject anything else before it reaches a
        # storage key (defense-in-depth against path traversal on filesystem-backed storage).
        return unless id.is_a?(String) && id.match?(/\A[A-Za-z0-9_-]+\z/)

        content = read('dynamic_client', id)
        content && DynamicClientRegistration.from_json(content)
      end

      def put_dynamic_client(client, overwrite: false)
        write('dynamic_client', client.id, client.as_json, overwrite: overwrite)
      end

      def delete_dynamic_client(client)
        delete_dynamic_client_by_id(client.id)
      end

      def delete_dynamic_client_by_id(id)
        delete('dynamic_client', id)
      end

      def find_session(handle)
        content = read('session', handle)
        content && SessionData.new(**content)
      end

      def put_session(session, overwrite: false)
        write('session', session.handle, session.as_json, overwrite: overwrite)
      end

      def delete_session(session)
        delete_session_by_handle(session.handle)
      end

      def delete_session_by_handle(handle)
        delete('session', handle)
      end

      private def write(kind, key, content, overwrite: false, if_version: nil)
        raise NotImplementedError
      end

      private def read(kind, key)
        raise NotImplementedError
      end

      private def delete(kind, key)
        raise NotImplementedError
      end
    end
  end
end
