require 'himari/storages/base'

module Himari
  module Storages
    class Memory
      include Himari::Storages::Base

      def initialize
        @memory = {}
      end

      private def write(kind, key, content, overwrite: false)
        path = File.join(kind, key)
        raise Himari::Storages::Base::Conflict if @memory.key?(path)
        @memory[path] = JSON.pretty_generate(content)
        nil
      end

      private def read(kind, key)
        path = File.join(kind, key)
        @memory[path]&.then { |v| JSON.parse(v, symbolize_names: true) } || nil
      end

      private def delete(kind, key)
        path = File.join(kind, key)
        @memory.delete(path)
        nil
      end
    end
  end
end
