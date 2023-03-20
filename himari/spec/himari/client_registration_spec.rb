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
  end

  describe "#match_hint?" do
    let(:client) { described_class.new(name: 'a', id: 'a', secret: 'secret', redirect_uris: []) }

    specify do
      expect(client.match_hint?()).to eq(true)
      expect(client.match_hint?(id: 'a')).to eq(true)
      expect(client.match_hint?(id: 'b')).to eq(false)
    end
  end
end
