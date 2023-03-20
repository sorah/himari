module Himari
  SessionData = Struct.new(:claims, :user_data, keyword_init: true) do
    def as_log
      {claims: claims}
    end
  end
end
