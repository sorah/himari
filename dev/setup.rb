require 'openssl'
require 'fileutils'

Dir.chdir(__dir__)
FileUtils.mkdir_p './tmp/storage'

File.umask(0077)
File.write "tmp/rsa.pem", OpenSSL::PKey::RSA.generate(2048).to_pem
File.write "tmp/ec.pem", OpenSSL::PKey::EC.generate('prime256v1').to_pem
