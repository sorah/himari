require 'himari/authorization_code'
require 'himari/access_token'

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

      def find_token(handler)
        content = read('token', handler)
        content && AccessToken.new(**content)
      end

      def put_token(token, overwrite: false)
        write('token', token.handler, token.as_json, overwrite: overwrite)
      end

      def delete_token(token)
        delete_authorization_by_token(token.handler)
      end

      def delete_token_by_handler(handler)
        delete('token', handler)
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
