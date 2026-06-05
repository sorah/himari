# frozen_string_literal: true

RSpec.describe OmniAuth::Strategies::Himari do
  it "has a version number" do
    expect(Omniauth::Himari::VERSION).not_to be nil
  end

  describe "#callback_phase (RFC 9207 issuer validation)" do
    subject(:strategy) { described_class.new(app, 'https://idp.invalid', client_id: 'cid', client_secret: 'secret', **options) }

    let(:app) { ->(_env) { [200, {}, ['ok']] } }
    let(:options) { {} }

    before do
      allow(strategy).to receive(:request).and_return(double('request', params: params))
      # An empty session makes the upstream OAuth2 state check fail (omniauth.state is absent),
      # so a request that passes the issuer gate stops at :csrf_detected without any token exchange.
      allow(strategy).to receive(:session).and_return({})
      allow(strategy).to receive(:fail!)
    end

    context "when iss matches the configured site" do
      let(:params) { {'iss' => 'https://idp.invalid', 'code' => 'c', 'state' => 's'} }

      it "passes the issuer gate and proceeds to the standard callback" do
        strategy.callback_phase
        expect(strategy).not_to have_received(:fail!).with(:issuer_mismatch, anything)
        expect(strategy).to have_received(:fail!).with(:csrf_detected, anything)
      end
    end

    context "when iss is absent" do
      let(:params) { {'code' => 'c', 'state' => 's'} }

      it "passes the issuer gate (backward compatible with servers not emitting iss)" do
        strategy.callback_phase
        expect(strategy).not_to have_received(:fail!).with(:issuer_mismatch, anything)
        expect(strategy).to have_received(:fail!).with(:csrf_detected, anything)
      end
    end

    context "when iss does not match the configured site" do
      let(:params) { {'iss' => 'https://evil.invalid', 'code' => 'c', 'state' => 's'} }

      it "rejects the response before exchanging the code" do
        strategy.callback_phase
        expect(strategy).to have_received(:fail!).with(:issuer_mismatch, an_instance_of(described_class::VerificationError))
        expect(strategy).not_to have_received(:fail!).with(:csrf_detected, anything)
      end
    end

    context "when verify_iss is disabled" do
      let(:options) { {verify_iss: false} }
      let(:params) { {'iss' => 'https://evil.invalid', 'code' => 'c', 'state' => 's'} }

      it "skips issuer validation" do
        strategy.callback_phase
        expect(strategy).not_to have_received(:fail!).with(:issuer_mismatch, anything)
        expect(strategy).to have_received(:fail!).with(:csrf_detected, anything)
      end
    end
  end
end
