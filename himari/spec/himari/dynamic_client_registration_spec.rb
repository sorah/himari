# frozen_string_literal: true

require 'spec_helper'
require 'himari/dynamic_client_registration'

RSpec.describe Himari::DynamicClientRegistration do
  let(:redirect_uris) { %w(https://rp.test.invalid/callback) }

  describe ".register" do
    context "with token_endpoint_auth_method=none (public client)" do
      subject(:client) do
        described_class.register(metadata: {redirect_uris: redirect_uris, token_endpoint_auth_method: 'none'})
      end

      it "is a public client requiring PKCE without a secret" do
        expect(client.confidential?).to eq(false)
        expect(client.require_pkce).to eq(true)
        expect(client.secret).to be_nil
        expect(client.secret_hash).to be_nil
      end

      it "defaults grant_types and response_types" do
        expect(client.grant_types).to eq(%w(authorization_code))
        expect(client.response_types).to eq(%w(code))
      end

      it "skips consent on the converted ClientRegistration" do
        expect(client.to_client_registration.skip_consent).to eq(true)
      end

      it "omits client_secret from the registration response" do
        expect(client.registration_response).not_to have_key(:client_secret)
      end
    end

    context "with confidential auth method" do
      subject(:client) do
        described_class.register(metadata: {redirect_uris: redirect_uris, token_endpoint_auth_method: 'client_secret_basic'})
      end

      it "generates a secret verifiable via the converted ClientRegistration" do
        expect(client.confidential?).to eq(true)
        expect(client.require_pkce).to eq(false)
        expect(client.secret).to be_a(String)
        registration = client.to_client_registration
        expect(registration.match_secret?(client.secret)).to eq(true)
        expect(registration.match_secret?('wrong')).to eq(false)
      end

      it "returns the plaintext secret once in the registration response" do
        response = client.registration_response
        expect(response[:client_secret]).to eq(client.secret)
        expect(response[:client_secret_expires_at]).to eq(client.expiry)
      end

      it "defaults token_endpoint_auth_method to client_secret_basic" do
        c = described_class.register(metadata: {redirect_uris: redirect_uris})
        expect(c.token_endpoint_auth_method).to eq('client_secret_basic')
      end
    end

    context "with refresh_token grant" do
      it "is accepted" do
        client = described_class.register(metadata: {redirect_uris: redirect_uris, grant_types: %w(authorization_code refresh_token)})
        expect(client.grant_types).to eq(%w(authorization_code refresh_token))
      end
    end

    it "captures registration source" do
      client = described_class.register(metadata: {redirect_uris: redirect_uris}, registration_ip: '203.0.113.1', registration_remote_addr: '198.51.100.1', registration_x_forwarded_for: '203.0.113.1, 198.51.100.1')
      expect(client.registration_ip).to eq('203.0.113.1')
      expect(client.registration_remote_addr).to eq('198.51.100.1')
      expect(client.registration_x_forwarded_for).to eq('203.0.113.1, 198.51.100.1')
    end

    it "expires 180 days after issuance by default" do
      now = Time.at(1_700_000_000)
      client = described_class.register(metadata: {redirect_uris: redirect_uris}, now: now)
      expect(client.client_id_issued_at).to eq(now.to_i)
      expect(client.expiry).to eq(now.to_i + (180 * 86400))
    end

    it "honors a custom lifetime" do
      now = Time.at(1_700_000_000)
      client = described_class.register(metadata: {redirect_uris: redirect_uris}, lifetime: 3600, now: now)
      expect(client.expiry).to eq(now.to_i + 3600)
    end

    describe "validation" do
      it "rejects missing redirect_uris" do
        expect { described_class.register(metadata: {}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_redirect_uri) }
      end

      it "rejects empty redirect_uris" do
        expect { described_class.register(metadata: {redirect_uris: []}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_redirect_uri) }
      end

      it "rejects a redirect_uri without a scheme" do
        expect { described_class.register(metadata: {redirect_uris: %w(/relative)}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_redirect_uri) }
      end

      it "rejects a redirect_uri with a fragment" do
        expect { described_class.register(metadata: {redirect_uris: %w(https://rp.test.invalid/cb#frag)}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_redirect_uri) }
      end

      it "rejects a redirect_uri with a dangerous scheme" do
        expect { described_class.register(metadata: {redirect_uris: ['javascript:alert(1)//']}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_redirect_uri) }
      end

      it "rejects too many redirect_uris" do
        uris = Array.new(described_class::MAX_REDIRECT_URIS + 1) { |i| "https://rp.test.invalid/cb#{i}" }
        expect { described_class.register(metadata: {redirect_uris: uris}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_redirect_uri) }
      end

      it "rejects an overlong redirect_uri" do
        long = "https://rp.test.invalid/#{"a" * described_class::MAX_URI_LENGTH}"
        expect { described_class.register(metadata: {redirect_uris: [long]}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_redirect_uri) }
      end

      it "rejects an overlong client_name" do
        expect { described_class.register(metadata: {redirect_uris: redirect_uris, client_name: 'x' * (described_class::MAX_CLIENT_NAME_LENGTH + 1)}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_client_metadata) }
      end

      it "accepts a client_name at the limit" do
        client = described_class.register(metadata: {redirect_uris: redirect_uris, client_name: 'x' * described_class::MAX_CLIENT_NAME_LENGTH})
        expect(client.client_name.length).to eq(described_class::MAX_CLIENT_NAME_LENGTH)
      end

      it "accepts and echoes a valid client_uri" do
        client = described_class.register(metadata: {redirect_uris: redirect_uris, client_uri: 'https://app.test.invalid/'})
        expect(client.client_uri).to eq('https://app.test.invalid/')
        expect(client.registration_response[:client_uri]).to eq('https://app.test.invalid/')
      end

      it "rejects an overlong client_uri" do
        long = "https://app.test.invalid/#{"a" * described_class::MAX_URI_LENGTH}"
        expect { described_class.register(metadata: {redirect_uris: redirect_uris, client_uri: long}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_client_metadata) }
      end

      it "rejects a client_uri that is not a valid URL" do
        expect { described_class.register(metadata: {redirect_uris: redirect_uris, client_uri: 'not a url'}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_client_metadata) }
      end

      it "rejects an unsupported token_endpoint_auth_method" do
        expect { described_class.register(metadata: {redirect_uris: redirect_uris, token_endpoint_auth_method: 'private_key_jwt'}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_client_metadata) }
      end

      it "rejects an unsupported grant_type" do
        expect { described_class.register(metadata: {redirect_uris: redirect_uris, grant_types: %w(client_credentials)}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_client_metadata) }
      end

      it "rejects an unsupported response_type" do
        expect { described_class.register(metadata: {redirect_uris: redirect_uris, response_types: %w(token)}) }
          .to raise_error(described_class::ValidationError) { |e| expect(e.error_code).to eq(:invalid_client_metadata) }
      end
    end
  end

  describe "#active?" do
    let(:now) { Time.at(1_700_000_000) }
    subject(:client) { described_class.register(metadata: {redirect_uris: redirect_uris}, now: now) }

    it "is active before expiry and inactive after" do
      expect(client.active?(now)).to eq(true)
      expect(client.active?(Time.at(client.expiry + 1))).to eq(false)
    end
  end

  describe "#as_log" do
    subject(:client) do
      described_class.register(metadata: {redirect_uris: redirect_uris, token_endpoint_auth_method: 'client_secret_basic', client_name: 'cli', client_uri: 'https://app.test.invalid/', scope: 'openid'})
    end

    it "exposes client metadata attributes without secrets" do
      log = client.as_log
      expect(log).to include(
        id: client.id,
        token_endpoint_auth_method: 'client_secret_basic',
        redirect_uris: redirect_uris,
        grant_types: client.grant_types,
        response_types: client.response_types,
        client_name: 'cli',
        client_uri: 'https://app.test.invalid/',
        scope: 'openid',
        client_id_issued_at: client.client_id_issued_at,
        expiry: client.expiry,
        dynamic: true,
      )
      expect(log).not_to include(:secret, :secret_hash)
    end
  end

  describe "ignore_localhost_redirect_uri_port" do
    it "defaults to true" do
      client = described_class.register(metadata: {redirect_uris: redirect_uris, token_endpoint_auth_method: 'none'})
      expect(client.ignore_localhost_redirect_uri_port).to eq(true)
    end

    it "honours an override from the registration policy" do
      client = described_class.register(metadata: {redirect_uris: redirect_uris, token_endpoint_auth_method: 'none'}, ignore_localhost_redirect_uri_port: false)
      expect(client.ignore_localhost_redirect_uri_port).to eq(false)
    end

    it "is not taken from client-supplied metadata" do
      client = described_class.register(metadata: {redirect_uris: redirect_uris, token_endpoint_auth_method: 'none', ignore_localhost_redirect_uri_port: false})
      expect(client.ignore_localhost_redirect_uri_port).to eq(true)
    end

    it "round-trips through as_json/from_json and to_client_registration" do
      client = described_class.register(metadata: {redirect_uris: redirect_uris, token_endpoint_auth_method: 'none'}, ignore_localhost_redirect_uri_port: false)
      restored = described_class.from_json(client.as_json)
      expect(restored.ignore_localhost_redirect_uri_port).to eq(false)
      expect(restored.to_client_registration.ignore_localhost_redirect_uri_port).to eq(false)
    end
  end

  describe "JSON round-trip" do
    subject(:client) do
      described_class.register(metadata: {redirect_uris: redirect_uris, token_endpoint_auth_method: 'client_secret_basic', client_name: 'cli', scope: 'openid'})
    end

    it "includes ttl mirroring expiry in as_json" do
      expect(client.as_json[:ttl]).to eq(client.expiry)
    end

    it "reconstructs an equivalent client (secret_hash persisted, plaintext not)" do
      restored = described_class.from_json(client.as_json)
      expect(restored.id).to eq(client.id)
      expect(restored.secret).to be_nil
      expect(restored.to_client_registration.match_secret?(client.secret)).to eq(true)
      expect(restored.redirect_uris).to eq(client.redirect_uris)
      expect(restored.client_name).to eq('cli')
      expect(restored.expiry).to eq(client.expiry)
    end
  end

  describe "#to_client_registration" do
    it "produces a public ClientRegistration for token_endpoint_auth_method=none" do
      client = described_class.register(metadata: {redirect_uris: redirect_uris, token_endpoint_auth_method: 'none'})
      registration = client.to_client_registration

      expect(registration).to be_a(Himari::ClientRegistration)
      expect(registration.id).to eq(client.id)
      expect(registration.name).to be_nil
      expect(registration.confidential?).to eq(false)
      expect(registration.require_pkce).to eq(true)
      expect(registration.match_secret?('anything')).to eq(false)
      expect(registration.match_hint?(id: client.id)).to eq(true)
    end

    it "produces a confidential ClientRegistration carrying the secret hash" do
      client = described_class.register(metadata: {redirect_uris: redirect_uris, token_endpoint_auth_method: 'client_secret_basic'})
      registration = client.to_client_registration

      expect(registration.confidential?).to eq(true)
      expect(registration.require_pkce).to eq(false)
      expect(registration.match_secret?(client.secret)).to eq(true)
    end
  end
end
