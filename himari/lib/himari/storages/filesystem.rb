# frozen_string_literal: true

require 'himari/storages/base'

module Himari
  module Storages
    class Filesystem
      include Himari::Storages::Base

      def initialize(path, hex_path: false)
        @path = path
        @hex_path = hex_path
      end

      attr_reader :path

      # hex_path: false keeps plain keys for backward compatibility with existing files,
      # but keys containing a path separator are always hex-encoded to prevent path traversal.
      private def encode_key(key)
        return key.unpack1('H*') if @hex_path

        if key.include?(File::SEPARATOR) || (File::ALT_SEPARATOR && key.include?(File::ALT_SEPARATOR))
          key.unpack1('H*')
        else
          key
        end
      end

      # The version compare-and-swap below is a read-compare-write, which is not atomic
      # across processes. Adequate for filesystem storage's dev/single-node use; the
      # production atomic path is DynamoDB's conditional update.
      private def write(kind, key, content, overwrite: false, if_version: nil)
        dir = File.join(@path, kind)
        path = File.join(dir, encode_key(key))
        Dir.mkdir(dir) unless Dir.exist?(dir)
        if if_version
          existing = read(kind, key)
          raise Himari::Storages::Base::Conflict unless existing && existing[:version] == if_version
        elsif File.exist?(path) && !overwrite
          raise Himari::Storages::Base::Conflict
        end

        File.write(path, "#{JSON.pretty_generate(content)}\n")
        nil
      end

      private def read(kind, key)
        path = File.join(@path, kind, encode_key(key))
        JSON.parse(File.read(path), symbolize_names: true)
      rescue Errno::ENOENT
        nil
      end

      private def delete(kind, key)
        path = File.join(@path, kind, encode_key(key))
        File.unlink(path) if File.exist?(path)
      end
    end
  end
end
