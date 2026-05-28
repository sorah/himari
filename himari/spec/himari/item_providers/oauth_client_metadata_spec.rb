# frozen_string_literal: true

require 'spec_helper'
require 'himari/item_providers/oauth_client_metadata'

RSpec.describe Himari::ItemProviders::OauthClientMetadata do
  # Minimal stand-in for an HTTPX response. raise_for_status is a no-op on success.
  FakeResponse = Struct.new(:status, :headers, :body) do
    def raise_for_status
      self
    end
  end

  def ok_response(doc, headers: {}, status: 200)
    body = doc.is_a?(String) ? doc : JSON.generate(doc)
    FakeResponse.new(status, {'content-type' => 'application/json'}.merge(headers), body)
  end

  let(:url) { 'https://client.example.com/oauth/metadata' }
  let(:document) do
    {
      client_id: url,
      redirect_uris: %w(https://client.example.com/callback),
      token_endpoint_auth_method: 'none',
    }
  end

  let(:session) { instance_double('HTTPX::Session') }
  let(:options) { {} }
  let(:provider) { described_class.new(session: session, **options) }

  describe '#collect' do
    context 'with a compliant client_id whose document is valid' do
      before { allow(session).to receive(:get).with(url).and_return(ok_response(document)) }

      it 'returns a public ClientRegistration that requires PKCE' do
        result = provider.collect(id: url)
        expect(result.size).to eq(1)
        client = result.first
        expect(client).to be_a(Himari::ClientRegistration)
        expect(client.id).to eq(url)
        expect(client.redirect_uris).to eq(%w(https://client.example.com/callback))
        expect(client.confidential?).to eq(false)
        expect(client.require_pkce).to eq(true)
      end

      it 'matches the fetched client by hint' do
        client = provider.collect(id: url).first
        expect(client.match_hint?(id: url)).to eq(true)
      end
    end

    context 'when no id hint is given' do
      it 'returns [] without fetching' do
        expect(session).not_to receive(:get)
        expect(provider.collect).to eq([])
      end
    end

    context 'when the id is not a compliant client_id URL' do
      it 'rejects non-URL ids without fetching' do
        expect(session).not_to receive(:get)
        expect(provider.collect(id: 'myclient1')).to eq([])
      end

      it 'rejects non-https URLs' do
        expect(session).not_to receive(:get)
        expect(provider.collect(id: 'http://client.example.com/meta')).to eq([])
      end

      it 'rejects URLs without a path' do
        expect(session).not_to receive(:get)
        expect(provider.collect(id: 'https://client.example.com')).to eq([])
      end

      it 'rejects URLs with a fragment' do
        expect(session).not_to receive(:get)
        expect(provider.collect(id: 'https://client.example.com/meta#x')).to eq([])
      end

      it 'rejects URLs with userinfo' do
        expect(session).not_to receive(:get)
        expect(provider.collect(id: 'https://user@client.example.com/meta')).to eq([])
      end

      it 'rejects URLs with dot path segments' do
        expect(session).not_to receive(:get)
        expect(provider.collect(id: 'https://client.example.com/../meta')).to eq([])
      end
    end

    context 'with allowed_client_ids restrictions' do
      let(:options) { {allowed_client_ids: ['https://allowed.example.com/meta', %r{\Ahttps://re\.example\.com/}]} }

      it 'fetches an id matching a String entry' do
        allowed = 'https://allowed.example.com/meta'
        allow(session).to receive(:get).with(allowed).and_return(ok_response(document.merge(client_id: allowed)))
        expect(provider.collect(id: allowed).size).to eq(1)
      end

      it 'fetches an id matching a Regexp entry' do
        allowed = 'https://re.example.com/anything'
        allow(session).to receive(:get).with(allowed).and_return(ok_response(document.merge(client_id: allowed)))
        expect(provider.collect(id: allowed).size).to eq(1)
      end

      it 'rejects an id matching no entry without fetching' do
        expect(session).not_to receive(:get)
        expect(provider.collect(id: url)).to eq([])
      end
    end

    context 'when the document is invalid' do
      it 'rejects when client_id does not match the URL' do
        allow(session).to receive(:get).with(url).and_return(ok_response(document.merge(client_id: 'https://evil.example.com/x')))
        expect(provider.collect(id: url)).to eq([])
      end

      it 'rejects a shared-secret token_endpoint_auth_method' do
        allow(session).to receive(:get).with(url).and_return(ok_response(document.merge(token_endpoint_auth_method: 'client_secret_basic')))
        expect(provider.collect(id: url)).to eq([])
      end

      it 'rejects when client_secret is present' do
        allow(session).to receive(:get).with(url).and_return(ok_response(document.merge(client_secret: 'nope')))
        expect(provider.collect(id: url)).to eq([])
      end

      it 'rejects dangerous redirect_uri schemes' do
        allow(session).to receive(:get).with(url).and_return(ok_response(document.merge(redirect_uris: %w(javascript:alert(1)))))
        expect(provider.collect(id: url)).to eq([])
      end

      it 'rejects malformed JSON' do
        allow(session).to receive(:get).with(url).and_return(ok_response('{not json', headers: {'content-type' => 'application/json'}))
        expect(provider.collect(id: url)).to eq([])
      end

      it 'rejects a non-JSON content-type' do
        allow(session).to receive(:get).with(url).and_return(ok_response(document, headers: {'content-type' => 'text/html'}))
        expect(provider.collect(id: url)).to eq([])
      end
    end

    context 'with HTTP-level problems' do
      it 'rejects a non-200 status' do
        allow(session).to receive(:get).with(url).and_return(ok_response(document, status: 302))
        expect(provider.collect(id: url)).to eq([])
      end

      it 'rejects when the transport raises (e.g. SSRF block)' do
        resp = instance_double('HTTPX::ErrorResponse')
        allow(resp).to receive(:raise_for_status).and_raise(HTTPX::Error.new('blocked'))
        allow(session).to receive(:get).with(url).and_return(resp)
        expect(provider.collect(id: url)).to eq([])
      end
    end

    context 'with response size limits' do
      let(:options) { {max_response_size: 50} }

      it 'rejects when Content-Length exceeds the limit' do
        allow(session).to receive(:get).with(url).and_return(ok_response(document, headers: {'content-length' => '999'}))
        expect(provider.collect(id: url)).to eq([])
      end

      it 'rejects when the body exceeds the limit' do
        # the document JSON is well over 50 bytes and carries no Content-Length header here
        allow(session).to receive(:get).with(url).and_return(ok_response(document))
        expect(provider.collect(id: url)).to eq([])
      end
    end

    context 'caching' do
      it 'serves a second lookup from cache without re-fetching' do
        expect(session).to receive(:get).with(url).once.and_return(ok_response(document, headers: {'cache-control' => 'max-age=300'}))
        first = provider.collect(id: url).first
        second = provider.collect(id: url).first
        expect(second).to equal(first)
      end

      it 'does not cache error responses' do
        allow(session).to receive(:get).with(url).and_return(ok_response(document, status: 500))
        expect(provider.collect(id: url)).to eq([])
        # a subsequent success is served (proving the failure was not cached)
        allow(session).to receive(:get).with(url).and_return(ok_response(document))
        expect(provider.collect(id: url).size).to eq(1)
      end

      it 'does not cache when Cache-Control is no-store' do
        expect(session).to receive(:get).with(url).twice.and_return(ok_response(document, headers: {'cache-control' => 'no-store'}))
        provider.collect(id: url)
        provider.collect(id: url)
      end
    end
  end
end
