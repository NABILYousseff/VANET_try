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
from .mini_packet import *
from .Cryptico import *

class Entity:

    def __init__(self, sending_address: Address, listening_address: Address):
        self.__Private_Key = ec.generate_private_key(ec.SECP256R1())
        self.__Public_Key = self.__Private_Key.public_key()
        self.sending_address = sending_address
        self.listening_address = listening_address
        self.connected_Entities: dict[str, Entity] = {}
        self.buffer: list[mini_packet] = []
        self.id=random.randint(0,int(5e12))
        self.p=NIST256p.order
        self.g=NIST256p.generator

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

    def get_Exchanged_Key(self, entity: "Entity"):  #will not be used
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
    
    def get_Private_value(self):
        return self.__Private_Key.private_numbers().private_value

    def derive_aes_key_from_data(self, public_key):
        return Cryptico.derive_aes_key( self.__Private_Key, public_key)

    def get_msg_Entity_source(self, address: Address):
        # On traite notre cas ou juste les port sont differents
        for name, entity in self.connected_Entities.items():
            if address.Port == entity.sending_address.Port:
                return name
        return None

    @abstractmethod
    
    def packet_processing(self, packet: mini_packet):
        """
        The function will process the given packet and decide what to do whit it.

        Parameters
        ----------
        packet : mini_packet
            The packet to process.

        Return
        ------
            Void
        """
        pass

    @abstractmethod
    def forward_and_empty_buffer(self):
        pass

    @abstractmethod
    def start(self):
        pass

    def chameleon_hash_and_PLV(self, m, r):
        hash_result = Cryptico.chameleon_hash(self.get_Private_value(), m, r)
        PLV = Cryptico.group_addition(m, r)
        return hash_result, PLV

    def find_collision(self, m1, r1, m2):
        s_k = self.get_Private_value()
        return Cryptico.find_collision(s_k, m1, r1, m2)