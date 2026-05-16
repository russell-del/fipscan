import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def safe_hash(data):
    return hashlib.sha256(data).hexdigest()


def safe_encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()
