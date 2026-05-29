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

  describe "#redirect_uri_covers?" do
    let(:client) { described_class.new(id: 'a', redirect_uris:, confidential: false) }

    context "with a regular redirect_uri" do
      let(:redirect_uris) { ['https://rp.invalid/cb'] }

      it "matches only on exact string comparison" do
        expect(client.redirect_uri_covers?('https://rp.invalid/cb')).to eq(true)
        expect(client.redirect_uri_covers?('https://rp.invalid/cb?x=1')).to eq(false)
        expect(client.redirect_uri_covers?('https://rp.invalid/other')).to eq(false)
        expect(client.redirect_uri_covers?('https://attacker.invalid/cb')).to eq(false)
        expect(client.redirect_uri_covers?(nil)).to eq(false)
        expect(client.redirect_uri_covers?('')).to eq(false)
      end
    end

    context "with ignore_localhost_redirect_uri_port enabled (default)" do
      let(:redirect_uris) { ['http://127.0.0.1/cb'] }

      it "defaults to true" do
        expect(client.ignore_localhost_redirect_uri_port).to eq(true)
      end

      %w(127.0.0.1 [::1] localhost).each do |host|
        context "with loopback host #{host} over http" do
          let(:redirect_uris) { ["http://#{host}/cb"] }

          it "ignores the port" do
            expect(client.redirect_uri_covers?("http://#{host}/cb")).to eq(true)
            expect(client.redirect_uri_covers?("http://#{host}:54321/cb")).to eq(true)
            expect(client.redirect_uri_covers?("http://#{host}:0/cb")).to eq(true)
          end

          it "still requires scheme, host, path and query to match" do
            expect(client.redirect_uri_covers?("https://#{host}:54321/cb")).to eq(false)
            expect(client.redirect_uri_covers?("http://#{host}:54321/other")).to eq(false)
            expect(client.redirect_uri_covers?("http://#{host}:54321/cb?x=1")).to eq(false)
          end
        end
      end

      context "with a loopback host over https" do
        let(:redirect_uris) { ['https://localhost/cb'] }

        it "also ignores the port" do
          expect(client.redirect_uri_covers?('https://localhost:8443/cb')).to eq(true)
        end
      end

      context "with a non-loopback host" do
        let(:redirect_uris) { ['https://rp.invalid:443/cb'] }

        it "does not ignore the port" do
          expect(client.redirect_uri_covers?('https://rp.invalid:8443/cb')).to eq(false)
        end
      end
    end

    context "with a Regexp registered redirect_uri" do
      let(:redirect_uris) { [%r{\Ahttps://rp\.invalid/cb/[0-9]+\z}] }

      it "matches via the pattern" do
        expect(client.redirect_uri_covers?('https://rp.invalid/cb/123')).to eq(true)
        expect(client.redirect_uri_covers?('https://rp.invalid/cb/abc')).to eq(false)
        expect(client.redirect_uri_covers?('https://attacker.invalid/cb/123')).to eq(false)
      end
    end

    context "with a mix of String and Regexp entries" do
      let(:redirect_uris) { ['https://rp.invalid/cb', %r{\Ahttps://rp\.invalid/alt/}] }

      it "matches against either" do
        expect(client.redirect_uri_covers?('https://rp.invalid/cb')).to eq(true)
        expect(client.redirect_uri_covers?('https://rp.invalid/alt/x')).to eq(true)
        expect(client.redirect_uri_covers?('https://rp.invalid/other')).to eq(false)
      end
    end

    context "with ignore_localhost_redirect_uri_port disabled" do
      let(:client) { described_class.new(id: 'a', redirect_uris:, confidential: false, ignore_localhost_redirect_uri_port: false) }
      let(:redirect_uris) { ['http://127.0.0.1:3000/cb'] }

      it "requires exact loopback port match" do
        expect(client.redirect_uri_covers?('http://127.0.0.1:3000/cb')).to eq(true)
        expect(client.redirect_uri_covers?('http://127.0.0.1:54321/cb')).to eq(false)
      end
    end
  end
end
