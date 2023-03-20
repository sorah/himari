require 'himari/storages/base'

module Himari
  module Storages
    class Filesystem
      include Himari::Storages::Base

      def initialize(path)
        @path = path
      end

      attr_reader :path

      private def write(kind, key, content, overwrite: false)
        dir = File.join(@path, kind)
        path = File.join(dir, key)
        Dir.mkdir(dir) unless Dir.exist?(dir)
        raise Himari::Storages::Base::Conflict if File.exist?(path)
        File.write(path, "#{JSON.pretty_generate(content)}\n")
        nil
      end

      private def read(kind, key)
        path = File.join(@path, kind, key)
        JSON.parse(File.read(path), symbolize_names: true)
      rescue Errno::ENOENT
        return nil
      end

      private def delete(kind, key)
        path = File.join(@path, kind, key)
        File.unlink(path) if File.exist?(path)
      end
    end
  end
end
