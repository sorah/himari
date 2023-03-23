require 'himari/authorization_code'
require 'himari/access_token'
require 'himari/session_data'

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

      private def write(kind, key, content, overwrite: false)
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
