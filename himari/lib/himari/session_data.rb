module Himari
  SessionData = Struct.new(:claims, :user_data, keyword_init: true)
end
