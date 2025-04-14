import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa import NIST256p,numbertheory
import hashlib

class Cryptico:

    def chameleon_hash(s_k:ec.EllipticCurvePrivateKey, m:int, r:int, p:int=NIST256p.order, g:int=NIST256p.generator):
        term = (m + r * s_k) % p
        result = g * term
        hash_result = hashlib.sha256(
            result.x().to_bytes(32, 'big')).hexdigest()
        return hash_result
    
    def group_addition(m:int, r:int, p:int=NIST256p.order):
        return (m + r) % p
    
    def find_collision(s_k:ec.EllipticCurvePrivateKey, m1:int, r1:int, m2:int, p:int=NIST256p.order):
        delta_m = (m1 - m2) % p
        sk_inv = numbertheory.inverse_mod(s_k, p)
        r2 = (r1 + delta_m * sk_inv) % p
        return r2

    def derive_aes_key(private_key, public_key):
        peer_pubkey = serialization.load_pem_public_key(public_key)
        shared_key = private_key.exchange(ec.ECDH(), peer_pubkey)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b''
        ).derive(shared_key)
        return derived_key
    
    def aes_encrypt(self, key, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_plaintext = plaintext + b' ' * (16 - len(plaintext) % 16)
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv + ciphertext
    
    def aes_decrypt(self, key, ciphertext):
        iv, actual_ciphertext = ciphertext[:16], ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        return plaintext.rstrip(b' ')