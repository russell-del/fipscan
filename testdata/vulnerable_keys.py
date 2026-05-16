from Crypto.PublicKey import RSA, DSA
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def weak_rsa_old_api():
    return RSA.generate(1024)


def weak_rsa_new_api():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def disallowed_dsa():
    return DSA.generate(2048)


def non_nist_curve():
    return ec.generate_private_key(ec.SECP256K1())
