# frozen_string_literal: true

require 'spec_helper'

require 'himari/services/upstream_authentication'
require 'himari/rule'
require 'himari/session_data'

RSpec.describe Himari::Services::UpstreamAuthentication do
  let(:rack_request) { double('rack request') }
  let(:auth_hash) { {provider: 'test', id: 'abcdef', name: 'himari'} }

  let(:claims_rules) do
    [
      # Himari::Rule.new(name: 'continue', block: proc { |c,d| d.continue! }),
    ]
  end

  let(:authn_rules) do
    [
      # Himari::Rule.new(name: 'continue', block: proc { |c,d| d.continue! }),
    ]
  end

  subject(:service) { described_class.new(auth: auth_hash, request: rack_request, claims_rules: claims_rules, authn_rules: authn_rules) }
  subject(:result) { service.perform }

  describe "nominal case" do
    let(:claims_rules) do
      [
        Himari::Rule.new(name: 'claims', block: proc { |c, d|
          d.initialize_claims!(sub: c.auth[:id], preferred_username: c.auth[:name])
          d.user_data[:foo] = :bar
          d.continue!
        }),
      ]
    end

    let(:authn_rules) do
      [
        Himari::Rule.new(name: 'allow', block: proc { |c, d|
          next d.allow! if c.claims[:sub] == 'abcdef'

          d.skip!
        }),
      ]
    end

    it "returns a session" do
      expect(result.claims_result.decision).not_to be_nil
      expect(result.authn_result.allowed).to eq(true)
      expect(result.session_data.claims).to eq(sub: 'abcdef', preferred_username: 'himari')
      expect(result.session_data.user_data).to eq(foo: :bar)
    end
  end

  describe "authn denial case" do
    let(:claims_rules) do
      [
        Himari::Rule.new(name: 'claims', block: proc { |c, d|
          d.initialize_claims!(sub: c.auth[:id])
          d.continue!
        }),
      ]
    end

    let(:authn_rules) do
      [
        Himari::Rule.new(name: 'deny', block: proc { |_c, d| d.deny! }),
      ]
    end

    it "raises UnauthorizedError" do
      expect { result }.to raise_error(Himari::Services::UpstreamAuthentication::UnauthorizedError)
    end
  end

  describe "no claims case" do
    let(:claims_rules) do
      []
    end

    let(:authn_rules) do
      [
        Himari::Rule.new(name: 'allow', block: proc { |_c, d| d.allow! }),
      ]
    end

    it "raises UnauthorizedError" do
      expect { result }.to raise_error(Himari::Services::UpstreamAuthentication::UnauthorizedError)
    end
  end

  describe "revalidation (grant_type: :refresh_token)" do
    let(:existing_session) do
      Himari::SessionData.make(claims: {sub: 'abcdef'}, user_data: {provider: 'test'}, refresh_info: {sub: 'abcdef'})
    end

    subject(:service) { described_class.new(session: existing_session, grant_type: :refresh_token, request: rack_request, claims_rules: claims_rules, authn_rules: authn_rules) }

    context "happy path" do
      let(:claims_rules) do
        [
          Himari::Rule.new(name: 'claims', block: proc { |c, d|
            d.initialize_claims!(sub: c.refresh_info[:sub], name: 'refreshed')
            d.user_data[:provider] = 'test'
            d.continue!
          }),
        ]
      end

      let(:authn_rules) do
        [
          Himari::Rule.new(name: 'authn', block: proc { |c, d|
            d.refresh_info = c.refresh_info
            d.allow!
          }),
        ]
      end

      it "preserves session handle and refreshes claims/user_data" do
        r = service.perform
        expect(r.session_data.handle).to eq(existing_session.handle)
        expect(r.session_data.claims).to eq(sub: 'abcdef', name: 'refreshed')
        expect(r.session_data.user_data).to eq(provider: 'test')
        expect(r.session_data.refresh_info).to eq(sub: 'abcdef')
        expect(r.session_data.refreshable?).to eq(true)
      end
    end

    context "when claims rule skips (does not initialize_claims!)" do
      let(:claims_rules) { [] }
      let(:authn_rules) { [Himari::Rule.new(name: 'authn', block: proc { |_c, d| d.allow! })] }

      it "raises UnauthorizedError" do
        expect { service.perform }.to raise_error(Himari::Services::UpstreamAuthentication::UnauthorizedError)
      end
    end

    context "when authn rule writes a new refresh_info" do
      let(:claims_rules) do
        [Himari::Rule.new(name: 'claims', block: proc { |c, d|
          d.initialize_claims!(sub: c.refresh_info[:sub])
          d.continue!
        })]
      end
      let(:authn_rules) do
        [Himari::Rule.new(name: 'authn', block: proc { |_c, d|
          d.refresh_info = {sub: 'abcdef', rotated_at: 123}
          d.allow!
        })]
      end

      it "carries the new refresh_info onto the returned session" do
        r = service.perform
        expect(r.session_data.refresh_info).to eq(sub: 'abcdef', rotated_at: 123)
      end
    end

    context "when neither rule sets refresh_info" do
      let(:claims_rules) do
        [Himari::Rule.new(name: 'claims', block: proc { |c, d|
          d.initialize_claims!(sub: c.refresh_info[:sub])
          d.continue!
        })]
      end
      let(:authn_rules) do
        [Himari::Rule.new(name: 'authn', block: proc { |_c, d| d.allow! })]
      end

      it "carries nil — session becomes non-refreshable (no implicit preserve)" do
        r = service.perform
        expect(r.session_data.refresh_info).to be_nil
        expect(r.session_data.refreshable?).to eq(false)
      end
    end

    context "when only the claims rule writes refresh_info" do
      let(:claims_rules) do
        [Himari::Rule.new(name: 'claims', block: proc { |c, d|
          d.initialize_claims!(sub: c.refresh_info[:sub])
          d.user_data[:provider] = 'test'
          d.refresh_info = c.refresh_info.merge(rotated: 'yes')
          d.continue!
        })]
      end
      let(:authn_rules) do
        [Himari::Rule.new(name: 'authn', block: proc { |_c, d| d.allow! })]
      end

      it "flows the claims-decision value to the session" do
        r = service.perform
        expect(r.session_data.refresh_info).to eq(sub: 'abcdef', rotated: 'yes')
      end
    end

    context "when both claims and authn write refresh_info" do
      let(:claims_rules) do
        [Himari::Rule.new(name: 'claims', block: proc { |c, d|
          d.initialize_claims!(sub: c.refresh_info[:sub])
          d.refresh_info = {source: :claims}
          d.continue!
        })]
      end
      let(:authn_rules) do
        [Himari::Rule.new(name: 'authn', block: proc { |_c, d|
          d.refresh_info = {source: :authn}
          d.allow!
        })]
      end

      it "authn-decision wins over claims-decision" do
        r = service.perform
        expect(r.session_data.refresh_info).to eq(source: :authn)
      end
    end

    context "Context#provider on refresh" do
      let(:claims_rules) do
        [Himari::Rule.new(name: 'claims', block: proc { |c, d|
          # provider should be populated from session.user_data[:provider]
          d.initialize_claims!(sub: c.refresh_info[:sub], provider_observed: c.provider)
          d.user_data[:provider] = c.provider
          d.continue!
        })]
      end
      let(:authn_rules) do
        [Himari::Rule.new(name: 'authn', block: proc { |c, d|
          # context provider also populated for authn rule
          expect(c.provider).to eq('test')
          d.allow!
        })]
      end

      it "exposes provider on the claims context via session.user_data fallback" do
        r = service.perform
        expect(r.session_data.claims[:provider_observed]).to eq('test')
      end
    end
  end

  describe "claims rule explicit deny" do
    let(:claims_rules) do
      [Himari::Rule.new(name: 'claims-deny', block: proc { |_c, d| d.deny!("nope") })]
    end
    let(:authn_rules) { [] }

    it "raises UnauthorizedError" do
      expect { result }.to raise_error(Himari::Services::UpstreamAuthentication::UnauthorizedError)
    end

    it "surfaces explicit_deny on the claims result" do
      err = nil
      begin
        result
      rescue Himari::Services::UpstreamAuthentication::UnauthorizedError => e
        err = e
      end
      expect(err.result.claims_result.explicit_deny).to eq(true)
    end
  end
end
