require 'spec_helper'
require 'himari/access_token'
require 'base64'
require 'digest/sha2'


RSpec.describe Himari::AccessToken do
  describe "make roundtrip" do
    let(:authz) { double('authz', client_id: 'client', claims: {sub: 'chihiro'}) }
    subject { described_class.from_authz(authz) }

    specify do
      expect(subject.client_id).to eq('client')
      expect(subject.claims).to eq({sub: 'chihiro'})
      expect(subject.expiry).to be_a(Integer)
      expect(subject.secret).to be_a(String)
    end

    specify do
      parse = Himari::AccessToken.parse(subject.format.to_s)
      expect(parse.handle).to eq(subject.handle)
      expect(parse.secret).to eq(subject.secret)
    end
  end
end
