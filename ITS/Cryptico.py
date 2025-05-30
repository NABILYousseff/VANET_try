import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa import NIST256p, numbertheory
import hashlib


class Cryptico:
    """
    Cryptico class provides cryptographic primitives for chameleon hashing,
    group operations, collision finding, and symmetric encryption/decryption.
    """
    
    @staticmethod
    def group_addition(op1: int, op2: int, order: int = NIST256p.order):
        """
        Performs group addition modulo the curve order.

        param
        -----
            op1 : int
                First operand.
            op2 : int
                Second operand.
            order : int
                Modulus (default: NIST256p.order).

        return
        ------
            int
                Result of (op1 + op1) mod order.
        """
        return (op1 + op2) % order
    
    @staticmethod
    def chameleon_hash(Secret_Key: int, message: int, random: int, order: int = NIST256p.order, generator: int = NIST256p.generator):
        """
        Computes a chameleon hash using elliptic curve operations.

        param
        -----
            Secret_Key : Secret key.
            message : Message to hash.
            random : Random value (nonce).
            order : Curve order (default: NIST256p.order).
            generator : int
                Curve generator (default: NIST256p.generator).

        return
        ------
            str
                SHA-256 hash (hex) of the x-coordinate of the resulting EC point.
        """
        term = Cryptico.group_addition(message, random * Secret_Key, order)
        result = generator * term
        hash_result = hashlib.sha256(
            result.x().to_bytes(32, 'big')).hexdigest()
        return hash_result

    @staticmethod
    def find_collision(Secret_Key: int, message1: int, random1: int, message2: int, order: int = NIST256p.order):
        """
        Finds a collision for the chameleon hash function.

        param
        -----
            Secret_Key : Secret key.
            message1 : First message.
            random1 : Random value for message1.
            message2 : Message to find it's collision.
            order : Curve order (default: NIST256p.order).

        return
        ------
            int : Random value random2 such that chameleon_hash(Secret_Key, message1, random1) == chameleon_hash(Secret_Key, message2, random2).
        """
        delta_m = (message1 - message2) % order
        sk_inv = numbertheory.inverse_mod(Secret_Key, order)
        random2 = Cryptico.group_addition(random1, delta_m * sk_inv, order)
        return random2

    @staticmethod
    def derive_aes_key(private_key : ec.EllipticCurvePrivateKey, public_key : bytes):
        """
        Derives a 256-bit AES key from an ECDH shared secret using HKDF.

        param
        -----
            private_key : Local private key.
            public_key : Peer public key in PEM format.

        return
        ------
            bytes : Derived 32-byte AES key.
        """
        peer_pubkey = serialization.load_pem_public_key(public_key)
        shared_key = private_key.exchange(ec.ECDH(), peer_pubkey)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b''
        ).derive(shared_key)
        return derived_key

    @staticmethod
    def aes_encrypt(key : bytes, plaintext : bytes):
        """
        Encrypts plaintext using AES-CBC with PKCS7-like padding.

        param
        -----
            key : AES key (32 bytes).
            plaintext : Data to encrypt.

        return
        ------
            bytes : IV concatenated with ciphertext.
        """
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_plaintext = plaintext + b' ' * (16 - len(plaintext) % 16)
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv + ciphertext

    @staticmethod
    def aes_decrypt(key : bytes, ciphertext : bytes):
        """
        Decrypts ciphertext using AES-CBC and removes padding.

        param
        -----
            key : AES key (32 bytes).
            ciphertext : IV concatenated with ciphertext.

        return
        ------
            bytes : Decrypted plaintext with padding removed.
        """
        iv, actual_ciphertext = ciphertext[:16], ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        return plaintext.rstrip(b' ')
