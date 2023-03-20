# frozen_string_literal: true
require 'simplecov'
SimpleCov.start

require 'rack/test'

require "himari"

module Himari
  module Testing
    # https://www.rfc-editor.org/rfc/rfc7517#appendix-A.2
    TEST_EC_KEY_PEM = <<~EOF
      -----BEGIN EC PRIVATE KEY-----
      MHcCAQEEIPO9DAeoH7kyeB7VJ1L2DMiaa+XlGTT+AZON21XY93gBoAoGCCqGSM49
      AwEHoUQDQgAEMKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D7gS2XpJFbZ
      iItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==
      -----END EC PRIVATE KEY-----
    EOF

    TEST_EC_KEY_JWK = {
      kty: "EC",
      crv: "P-256",
      x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      use: "sig",
      kid: "example-ec",
      alg: "ES256",
    }

    TEST_RSA_KEY_PEM = <<~EOF
      -----BEGIN RSA PRIVATE KEY-----
      MIIEowIBAAKCAQEA0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78L
      hWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc/BJECPebWKRXjBZCiFV4n3oknj
      hMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt7/RN5w6Cf0h4QyQ5v+65YGjQR0/F
      DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbO
      pbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ+G/xBni
      Iqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDKgwIDAQABAoIBAF+HE7XiWP4J+BWD
      7FwfK3V4seb8LINRSzeRNxGhukSaFR/hyyyg/TO3ceaKOxlEZJ3IZ60cHlJAu4U+
      XySzNFmxQCjS1mNr7+wejal0s1L8U9P2En6oo8Kd0U85QWgsVqeHaBZOTdqPBsv5
      xzSq6AAyJCeOqUVKIbF8sG0XgHWGjMBbPbb/Hf3D1WN4tO2t7fDDekzcJtHUmsJv
      b+O1Igpd0pOWYhu8aIzy7uLG4NVNo8eCAUzQc52yUsxRyuuo0/G4JLqrJNBo7JAy
      ZNfWeKsI8G7J5+I9lgYot0S/lLNpRlZGPH5Bc5ntc9B2yJH89GOpqpzmLanNF+I3
      3CqAAvECgYEA83i+7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxt
      PVnwD20R+60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQy
      qVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfsCgYEA3dfO
      R9cuYq+0S+mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgT
      nCdpYzBcOfW5r370AFXjiWft/NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ+1k
      Yd/s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxkCgYAbiw9eRzphr3Lyglb38guP
      jG6mm7SXOL8ftVORLzGPlJ1fdygTSiKZjDEiLZ6ZMC57RQ5rl2mAUbIEnhzy1DZU
      XjTZdG6AoNM/xqRiEWjm0ADvtB782a25hlzcLebcjbgbYa9HmxIPFTIA3bOrwt+f
      0RSazqtjc5vxh6IqROIGPQKBgQCz2UAf1+CAGygVHw5pzZH8TaDDbzatPaQY4CG8
      iWURMTV5+sDqG5RS8x8FwymfyWp5bq/POdhjlJJAXukx0L9qAjecbwhunUFRvQlS
      KtpE2pR8uFxBv930YXgOHt7vhZtGyhtGie6NNg3XEJo/pM7rWO9atf4vXy3FfDj3
      hD9yCQKBgBsjP6eia18kos9baBYCm1lfiXSN40OMqbva2zFsd60CQX5rdBaGM4FC
      GRFRRHDqsHpkTfNc6AwGmvgZNCljRg4yR2Q3Q5hYVtwDe5SPqbsZP5h2Ridda8ck
      fDueVy0nt0j5kXysGSOslNuGcb0ChWCLXZXVChszuiGus0yoQFUV
      -----END RSA PRIVATE KEY-----
    EOF

    TEST_RSA_KEY_JWK = {
      kty: "RSA",
      n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      e: "AQAB",
      alg: "RS256",
      kid: "example-rsa",
      use: 'sig',
    }
  end
end

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
