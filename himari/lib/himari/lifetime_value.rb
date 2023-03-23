module Himari
  LifetimeValue = Struct.new(:access_token, :id_token, :code, keyword_init: true) do
    def self.from_integer(i)
      new(access_token: i, id_token: i, code: nil)
    end

    def as_log
      as_json&.compact
    end

    def as_json
      {access_token: access_token, id_token: id_token, code: code}
    end
  end
end
