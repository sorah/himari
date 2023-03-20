require 'json'

module Himari
  LogLine = Struct.new(:message, :data) do
    def to_s
      "#{message} -- #{JSON.generate(data || {})}"
    end
  end
end
