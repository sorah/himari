# frozen_string_literal: true

require 'spec_helper'
require 'himari/client_registration'

RSpec.describe Himari::ClientRegistration do
  describe "#match_secret?" do
    context "with cleartext secret" do
      let(:client) { described_class.new(name: 'a', id: 'a', secret: 'secret', redirect_uris: []) }

      specify do
        expect(client.match_secret?('secret')).to eq(true)
        expect(client.match_secret?('incorrect')).to eq(false)
      end
    end

    context "with hash secret" do
      let(:client) { described_class.new(name: 'a', id: 'a', secret_hash: Digest::SHA384.hexdigest('secret'), redirect_uris: []) }

      specify do
        expect(client.match_secret?('secret')).to eq(true)
        expect(client.match_secret?('incorrect')).to eq(false)
      end
    end

    context "with a public client (confidential: false)" do
      let(:client) { described_class.new(id: 'a', redirect_uris: [], confidential: false, require_pkce: true) }

      it "needs no secret and never matches one" do
        expect(client.confidential?).to eq(false)
        expect(client.require_pkce).to eq(true)
        expect(client.match_secret?('anything')).to eq(false)
        expect(client.match_secret?(nil)).to eq(false)
      end
    end
  end

  describe "confidential validation" do
    it "requires a secret for confidential clients" do
      expect { described_class.new(id: 'a', redirect_uris: []) }.to raise_error(ArgumentError)
    end

    it "allows a public client without a secret" do
      expect { described_class.new(id: 'a', redirect_uris: [], confidential: false) }.not_to raise_error
    end
  end

  describe "#match_hint?" do
    let(:client) { described_class.new(name: 'a', id: 'a', secret: 'secret', redirect_uris: []) }

    specify do
      expect(client.match_hint?).to eq(true)
      expect(client.match_hint?(id: 'a')).to eq(true)
      expect(client.match_hint?(id: 'b')).to eq(false)
    end
  end
end
