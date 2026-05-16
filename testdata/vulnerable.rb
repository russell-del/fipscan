require 'digest/md5'
require 'openssl'

def bad_md5(data)
  Digest::MD5.hexdigest(data)
end

def bad_sha1(data)
  Digest::SHA1.hexdigest(data)
end

def bad_des(key, iv)
  OpenSSL::Cipher.new('DES-CBC').encrypt
end

def bad_3des(key, iv)
  OpenSSL::Cipher.new('DES-EDE3-CBC').encrypt
end

def bad_rc4(key)
  OpenSSL::Cipher.new('RC4').encrypt
end

def weak_rsa
  OpenSSL::PKey::RSA.new(1024)
end

def disallowed_dsa
  OpenSSL::PKey::DSA.new(2048)
end

def non_nist_curve
  OpenSSL::PKey::EC.new('secp256k1')
end
