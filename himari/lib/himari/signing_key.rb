require 'digest/sha2'
require 'base64'
module Himari
  class SigningKey
    class AlgUnknown < StandardError; end
    class OperationInvalid < StandardError; end

    def initialize(id:, pkey:, alg: nil, inactive: false, group: nil)
      @id = id
      @pkey = pkey
      @alg = alg
      @inactive = inactive
      @group = group
    end

    attr_reader :id, :pkey, :group


    def active?
      !@inactive
    end

    def match_hint?(id: nil, active: nil, group: nil)
      result = true

      result &&= if id
        id == self.id
      else
        true
      end

      result &&= if !active.nil?
        active == self.active?
      else
        true
      end

      result &&= if group
        group == self.group
      else
        true
      end

      result
    end

    def alg
      @alg ||= inferred_alg
    end

    def inferred_alg
      # https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
      case pkey
      when OpenSSL::PKey::RSA
        'RS256'
      when OpenSSL::PKey::EC
        case ec_crv
        when 'P-256'; 'ES256'
        when 'P-384'; 'ES384'
        when 'P-521'; 'ES512'
        else
          raise AlgUnknown
        end
      else
        raise AlgUnknown
      end
    end

    def hash_function
      case alg
      when 'ES256', 'RS256'; Digest::SHA256
      when 'ES384'; Digest::SHA384
      when 'ES512'; Digest::SHA512
      else
        raise AlgUnknown
      end
    end

    def ec_crv
      raise OperationInvalid, "this key is not EC" unless pkey.is_a?(OpenSSL::PKey::EC)
      # https://www.rfc-editor.org/rfc/rfc8422.html#appendix-A
      case pkey.group.curve_name
      when 'prime256v1', 'secp256r1'
        'P-256'
      when 'secp384r1'
        'P-384'
      when 'secp521r1'
        'P-521'
      else
        raise AlgUnknown
      end
    end

    def as_jwk
      # https://www.rfc-editor.org/rfc/rfc7517#section-4
      case pkey
      when OpenSSL::PKey::EC # https://www.rfc-editor.org/rfc/rfc7518#section-6.2
        # https://www.secg.org/sec1-v2.pdf - 2.3.3. Elliptic-Curve-Point-to-Octet-String Conversion
        xy = pkey.public_key.to_octet_string(:uncompressed) # 0x04 || X || Y
        len = pkey.group.degree/8
        raise unless xy[0] == "\x04".b && xy.size == ((len*2)+1)
        x = xy[1,len]
        y = xy[1+len,len]

        {
          kid: id,
          kty: 'EC',
          crv: ec_crv,
          use: "sig",
          alg: alg,
          x: Base64.urlsafe_encode64(OpenSSL::BN.new(x, 2).to_s(2)).gsub(/\n|=/, ''),
          y: Base64.urlsafe_encode64(OpenSSL::BN.new(y, 2).to_s(2)).gsub(/\n|=/, ''),
        }
      when OpenSSL::PKey::RSA # https://www.rfc-editor.org/rfc/rfc7518#section-6.3
        {
          kid: id,
          kty: 'RSA',
          use: "sig",
          alg: alg,
          n: Base64.urlsafe_encode64(pkey.n.to_s(2)).gsub(/=+/,''),
          e: Base64.urlsafe_encode64(pkey.e.to_s(2)).gsub(/=+/,''),
        }
      else
        raise AlgUnknown
      end
    end
  end
end
