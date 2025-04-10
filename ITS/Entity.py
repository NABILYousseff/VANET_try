from .mini_packet import *
from abc import abstractmethod
from cryptography.hazmat.primitives.asymmetric import ec
import socket
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa import NIST256p, numbertheory
import hashlib
import random

class Entity:

    def __init__(self, sending_address: Address, listening_address: Address):
        self.__Private_Key = ec.generate_private_key(ec.SECP256R1())
        self.__Public_Key = self.__Private_Key.public_key()
        self.sending_address = sending_address
        self.listening_address = listening_address
        self.connected_Entities: dict[str, Entity] = {}
        self.buffer: list[mini_packet] = []
        self.curve = NIST256p.curve
        self.p = NIST256p.order
        self.g = NIST256p.generator
        self.id=random.randint(0,5e12)

    def send(self, destination: "Entity", binary_msg: bin):
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.sending_address.ip_address,
                        self.sending_address.Port))
                s.connect((destination.listening_address.ip_address,
                            destination.listening_address.Port))
                s.sendall(binary_msg)
                # print("data is sent from {} to {}".format(self.sending_address.Port,destination.listening_address.Port))       #Logs
                s.close()
                break
            except:
                continue
    
    def send_to_address(self, destination: Address, binary_msg: bin):
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.sending_address.ip_address,
                        self.sending_address.Port))
                s.connect((destination.ip_address,
                            destination.Port))
                s.sendall(binary_msg)
                # print("data is sent from {} to {}".format(self.sending_address.Port,destination.listening_address.Port))       #Logs
                s.close()
                break
            except:
                continue

    # this fnct maybe will not be in use
    def listen(self, address: Address):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address.ip_address, address.Port))
            s.listen(100)
            conn, addr = s.accept()
            with conn:
                data = conn.recv(4096)
                return addr, data

    def listen_and_fill_buffer(self, address: Address):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address.ip_address, address.Port))
            while True:
                s.listen(100)
                conn, addr = s.accept()
                source_address = Address(None, None)
                source_address.ip_address, source_address.Port = addr
                with conn:
                    data = conn.recv(4096)
                    packet = mini_packet(None, None)
                    packet.address, packet.data = source_address, data
                    self.buffer.append(packet)

    def get_Public_Key(self):
        return self.__Public_Key

    def get_Exchanged_Key(self, entity: "Entity"):
        return self.__Private_Key.exchange(ec.ECDH(), entity.get_Public_Key())

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

    def derive_aes_key(self, peer):
        shared_key = self.get_Exchanged_Key(peer)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b''
        ).derive(shared_key)
        return derived_key

    def get_Private_value(self):
        return self.__Private_Key.private_numbers().private_value

    def derive_aes_key_from_data(self, public_key):
        peer_pubkey = serialization.load_pem_public_key(public_key)
        shared_key = self.__Private_Key.exchange(ec.ECDH(), peer_pubkey)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b''
        ).derive(shared_key)
        return derived_key

    def get_msg_Entity_source(self, address: Address):
        # On traite notre cas ou juste les port sont differents
        for name, entity in self.connected_Entities.items():
            if address.Port == entity.sending_address.Port:
                return name
        return None

    @abstractmethod
    def packet_forwarding(self):
        pass

    @abstractmethod
    def forward_and_empty_buffer(self):
        pass

    @abstractmethod
    def start(self):
        pass

    def chameleon_hash_and_PLV(self, m, r, p, g):
        s_k = self.get_Private_value()

        term = (m + r * s_k) % p
        PLV = (m + r) % p
        result = g * term

        hash_result = hashlib.sha256(
            result.x().to_bytes(32, 'big')).hexdigest()
        return hash_result, PLV

    def find_collision(self, m1, r1, m2, p):
        s_k = self.get_Private_value()

        delta_m = (m1 - m2) % p

        sk_inv = numbertheory.inverse_mod(s_k, p)
        r2 = (r1 + delta_m * sk_inv) % p
        return r2