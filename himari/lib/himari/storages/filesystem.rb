require 'himari/authorization_code'
require 'himari/access_token'
require 'himari/storages/base'

module Himari
  module Storages
    class Filesystem
      include Himari::Storages::Base

      def initialize(path)
        @path = path
      end

      attr_reader :path

      def find_authorization(code)
        content = read_file('authz', code)
        content && AuthorizationCode.new(**content)
      end

      def put_authorization(authz, overwrite: false)
        write_file('authz', authz.code, authz.as_json, overwrite: overwrite)
      end

      def delete_authorization(authz)
        delete_authorization_by_code(authz.code)
      end

      def delete_authorization_by_code(code)
        delete_file('authz', code)
      end

      def find_token(handler)
        content = read_file('token', handler)
        content && AccessToken.new(**content)
      end

      def put_token(token, overwrite: false)
        write_file('token', token.handler, token.as_json, overwrite: overwrite)
      end

      def delete_token(token)
        delete_authorization_by_token(token.handler)
      end

      def delete_token_by_handler(handler)
        delete_file('token', handler)
      end

      private def write_file(kind, key, content, overwrite: false)
        dir = File.join(@path, kind)
        path = File.join(dir, key)
        Dir.mkdir(dir) unless Dir.exist?(dir)
        raise Himari::Storages::Base::Conflict if File.exist?(path)
        File.write(path, "#{JSON.pretty_generate(content)}\n")
        nil
      end

      private def read_file(kind, key)
        path = File.join(@path, kind, key)
        JSON.parse(File.read(path), symbolize_names: true)
      rescue Errno::ENOENT
        return nil
      end

      private def delete_file(kind, key)
        path = File.join(@path, kind, key)
        File.unlink(path) if File.exist?(path)
      end
    end
  end
end
