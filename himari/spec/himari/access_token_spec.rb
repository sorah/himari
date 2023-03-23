require 'spec_helper'
require 'himari/access_token'
require 'base64'
require 'digest/sha2'


RSpec.describe Himari::AccessToken do
  describe "make roundtrip" do
    let(:now) { Time.now }
    let(:authz) { double('authz', client_id: 'client', claims: {sub: 'chihiro'}, lifetime: double('lifetime', access_token: 123)) }
    subject { described_class.from_authz(authz) }

    before do
      expect(Time).to receive(:now).and_return(now)
    end

    specify do
      expect(subject.client_id).to eq('client')
      expect(subject.claims).to eq({sub: 'chihiro'})
      expect(subject.expiry).to eq(now.to_i+123)
      expect(subject.secret).to be_a(String)
    end

    specify do
      parse = Himari::AccessToken.parse(subject.format.to_s)
      expect(parse.handle).to eq(subject.handle)
      expect(parse.secret).to eq(subject.secret)
    end
  end
end
