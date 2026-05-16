import hashlib
from Crypto.Cipher import DES, DES3, ARC4


def insecure_md5(data):
    return hashlib.md5(data).hexdigest()


def insecure_sha1(data):
    return hashlib.sha1(data).hexdigest()


def insecure_des(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)


def insecure_3des(data, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(data)


def insecure_rc4(data, key):
    cipher = ARC4.new(key)
    return cipher.encrypt(data)
