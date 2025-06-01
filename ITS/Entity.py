from abc import abstractmethod
from typing import override
from cryptography.hazmat.primitives.asymmetric import ec
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
from ecdsa import NIST256p
import random
from .mini_packet import *
from .Cryptico import *

class Entity:

    def __init__(self, sending_address: Address, listening_address: Address):
        """
        Initializes the Entity with key pairs, addresses, and buffers.

        param
        -----
            sending_address : Address used for sending messages.
            listening_address : Address used for listening to incoming messages.
        """
        self.__Private_Key = ec.generate_private_key(ec.SECP256R1())
        self.__Public_Key = self.__Private_Key.public_key()
        self.sending_address = sending_address
        self.listening_address = listening_address
        self.connected_Entities: dict[str, Entity] = {}
        self.buffer: list[mini_packet] = []
        self.id = random.randint(0, int(5e12))
        self.p = NIST256p.order
        self.g = NIST256p.generator

    def send(self, destination: "Entity", binary_msg: bytes):
        """
        Sends a binary message to the specified destination entity.

        param
        -----
            destination : Entity
                The entity to which the message will be sent.
            binary_msg : bin
                The binary message to be sent.
        """
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.sending_address.ip_address,
                        self.sending_address.Port))
                s.connect((destination.listening_address.ip_address,
                           destination.listening_address.Port))
                s.sendall(binary_msg)
                s.close()
                break
            except:
                continue

    def send_to_address(self, destination: Address, binary_msg: bytes):
        """
        Sends a binary message to the specified destination address.

        param
        -----
            destination : The address to which the message will be sent.
            binary_msg : The binary message to be sent.
        """
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.sending_address.ip_address,
                        self.sending_address.Port))
                s.connect((destination.ip_address,
                           destination.Port))
                s.sendall(binary_msg)
                s.close()
                break
            except:
                continue

    def listen_and_fill_buffer(self, address: Address):
        """
        Listens for incoming connections and fills the buffer with received packets.

        param
        -----
            address : The address to which the entity is bound for listening.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address.ip_address, address.Port))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
                conn.close()

    def get_Public_Key(self):
        """
        Returns the public key of the entity.
        
        return
        ------
            EllipticCurvePublicKey : The public key object.
        """
        return self.__Public_Key

    def get_Private_value(self):
        """
        Returns the private value of the entity.

        return
        ------
            int : The private value.
        """
        return self.__Private_Key.private_numbers().private_value

    def derive_aes_key_from_data(self, public_key : ec.EllipticCurvePublicKey):
        """
        Derives an AES key from the given public key using the private key.

        param
        -----
            public_key : The public key to derive the AES key from.

        return
        ------
            bytes : The derived AES key.
        """
        return Cryptico.derive_aes_key(self.__Private_Key, public_key)

    def get_msg_Entity_source(self, address: Address):
        """
        Gets the source entity name for a message based on the address.

        param
        -----
            address : The address to check against connected entities.

        return
        ------
            str | None : The name of the source entity or None if not found.
        """
        # We process our case where we use only the localhost while changing ports for the sum of entities
        for name, entity in self.connected_Entities.items():
            if address.Port == entity.sending_address.Port:
                return name
        return None

    def verify_cert_signature(self, cert_pem: str, issuer_pubkey_pem: bytes):
        """
        Verifies the signature of a certificate using the issuer's public key.

        param
        -----
            cert_pem : The PEM-encoded certificate to verify.
            issuer_pubkey_pem : The PEM-encoded public key of the issuer.

        return
        ------
            bool : True if the signature is valid, False otherwise.
        """
        try:
            cert = load_pem_x509_certificate(cert_pem.encode())
            issuer_pub = serialization.load_pem_public_key(issuer_pubkey_pem)
            issuer_pub.verify(
                cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"[Cert Verify Error] {e}")
            return False

    @abstractmethod
    def packet_forwarding(self, packet: mini_packet):
        """
        Process the given packet and decide what to do with it.

        param
        -----
            packet : The packet to process.

        return
        ------
            void
        """
        pass

    @abstractmethod
    def forward_and_empty_buffer(self):
        """
        Forward the contents of the buffer to the appropriate destination and empty the buffer.

        return
        ------
            void
        """
        pass

    @abstractmethod
    def start(self):
        """
        Start the entity's operations.

        return
        ------
            void
        """
        pass
