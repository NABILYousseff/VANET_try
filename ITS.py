from abc import abstractmethod
from base64 import b64encode, encode
import threading
from typing import override
from cryptography.hazmat.primitives.asymmetric import ec
import socket
import time

import json
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa import NIST256p, numbertheory
from ecdsa.ellipticcurve import Point
import hashlib
import random
from pathlib import Path


class Address:
    def __init__(self, ip_address, Port):
        self.ip_address: str = ip_address
        self.Port: int = Port


class mini_packet:
    def __init__(self, address: Address, data):
        self.address: Address = address
        self.data = data


class Entity:

    def __init__(self, sending_address: Address, listening_address: Address):
        self.__Private_Key = ec.generate_private_key(ec.SECP256R1())
        self.__Public_Key = self.__Private_Key.public_key()
        self.sending_address = sending_address
        self.listening_address = listening_address
        self.connected_Entities: dict[str, Entity] = {}
        self.buffer: list[mini_packet] = []

    def send(self, destination: "Entity", binary_msg: bin):
        while (True):
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
                pass

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

      # To see later

    def encrypt_message():
        pass

    # To see later
    def decrypt_received_msg(data, addr):
        pass

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
    # A ne pas décommenter pour le moment
    """
    def send_request(address:Address, binary_msg):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((address.ip_address, address.Port))
            s.sendall(binary_msg)
            return 1

    def listen_for_response(address:Address):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address.ip_address, address.Port))
            s.listen() #nb de conx
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024)
            s.close()
            return data

    def send_and_listen(self,address:Address, binary_msg):
        self.send_request(address, binary_msg)
        time.sleep(1)
        return  self.listen_for_response(address)
    """


class Registration_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule = 0
        self.linkage_cert = []  # it will be used to verify that both LC1 and LC2 are created
        self.RA_buffer = []
        self.pubkeys_house = {}

    def add_LA1(self, LA):
        self.connected_Entities["LA1"] = LA

    def add_LA2(self, LA):
        self.connected_Entities["LA2"] = LA

    def add_PCA(self, PCA):
        self.connected_Entities["PCA"] = PCA

    def add_LTCA(self, LTCA):
        self.connected_Entities["LTCA"] = LTCA

    def add_vehicule(self, VEH):
        self.connected_vehicule += 1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)] = VEH

    def packet_forwarding(self, packet: mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('RA received a message from ', source_entity)
        time.sleep(3)
        if source_entity == None:
            pass  # The source of the packet is not known
        elif source_entity == "LA1":
            pass  # implement a fonction waiting LA2 then sending both lc to PCA
        elif source_entity == "LA2":
            pass  # implement a fonction waiting LA1 then sending both lc to PCA
        elif source_entity == "LTCA":
            print('Sending Linkage certif to LA1 and LA2..')
            # verfying if response is true or false
            data = packet.data.decode()
            json_data = json.loads(data)
            print(json_data)
            found = False
            if json_data["validity"] == "valid":
                ID = json_data["id"]
                for quadruple in self.RA_buffer:
                    if quadruple[0] == base64.b64decode(ID):
                        found = True
                        print(quadruple)
                        LA1_cipher = quadruple[2]
                        LA2_cipher = quadruple[3]
                        vehicule_pubkey = quadruple[1]
                        message1 = {
                            "id": ID,
                            "Vehicule_pubkey": vehicule_pubkey,
                            "LA_cipher": LA1_cipher
                        }
                        message2 = {
                            "id": ID,
                            "Vehicule_pubkey": vehicule_pubkey,
                            "LA_cipher": LA2_cipher
                        }
                        message2_json = json.dumps(message2)
                        print("Message to LA2 : ", message2_json, "\n")
                        message1_json = json.dumps(message1)
                        print("Message to LA1 : ", message1_json, "\n")
                        self.send(
                            self.connected_Entities['LA1'], message1_json.encode())
                        self.send(
                            self.connected_Entities['LA2'], message2_json.encode())
                if found is False:
                    print("id not found")
            else:
                print("LTC is invalid")
        elif source_entity == "PCA":
            print('Sending PC to VEH')
            self.send(VEH, packet.data)
        else:  # the entity is a vehicule implement then a function to send LTC in data to LTCA
            # processing...
            ID = os.urandom(4)
            ID_to_send = base64.b64encode(ID).decode()
            data = packet.data.decode()
            json_data = json.loads(data)
            Cipher = base64.b64decode(json_data["CipherLTC"])
            LA1_cipher = base64.b64decode(json_data["CipherLA1"])
            LA2_cipher = base64.b64decode(json_data["CipherLA2"])
            v_pub = json_data["PubKey"]
            vehicule_pubkey = base64.b64decode(json_data["PubKey"])
            aes_vehicule = self.derive_aes_key(VEH)
            Nested_LTC_Cipher = self.aes_decrypt(aes_vehicule, Cipher)

            Nested_LA1_Cipher = base64.b64encode(
                self.aes_decrypt(aes_vehicule, LA1_cipher))
            Nested_LA2_Cipher = base64.b64encode(
                self.aes_decrypt(aes_vehicule, LA2_cipher))
            message = {
                "id": ID_to_send,
                "Vehicule_pubkey": v_pub,
                "CipherLTC": base64.b64encode(Nested_LTC_Cipher).decode()
            }

            message_json = json.dumps(message)
            print('Sending LTC to LTCA')
            print(message_json)
            self.send(self.connected_Entities['LTCA'], message_json.encode())

            self.RA_buffer.append(
                [ID, v_pub, Nested_LA1_Cipher.decode(), Nested_LA2_Cipher.decode()])
            self.pubkeys_house[ID] = vehicule_pubkey
            print(self.pubkeys_house)

    def forward_and_empty_buffer(self, buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet = buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)

    def start(self):
        ra_listening_thread = threading.Thread(
            target=self.listen_and_fill_buffer, args=(self.listening_address,))
        ra_listening_thread.start()
        ra_forwarding_thread = threading.Thread(
            target=self.forward_and_empty_buffer, args=(self.buffer,))
        ra_forwarding_thread.start()


class Link_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule = 0

    def add_RA(self, RA):
        self.connected_Entities["RA"] = RA

    def add_PCA(self, PCA):
        self.connected_Entities["PCA"] = PCA

    def add_vehicule(self, VEH):
        self.connected_vehicule += 1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)] = VEH

    def chameleon_hash_and_PLV(self, m, r, p, g):
        s_k = self.get_Private_value()

        term = (m + r * s_k) % p
        PLV = (m + r) % p
        result = g * term

        hash_result = hashlib.sha256(
            result.x().to_bytes(32, 'big')).hexdigest()
        return hash_result, PLV

    def save_hash_to_json(self, m, r, filename, PLV):
        identifier = f"{m}_{r}"
        data = {
            "msg_random": identifier,
            "message": m,
            "random": r,
            # "hash": hash_value,
            "Prelinkage Value": PLV
        }
        try:
            with open(filename, "r") as f:
                all_data = json.load(f)
        except FileNotFoundError:
            all_data = {}

        all_data[identifier] = data
        with open(filename, 'w') as f:
            json.dump(all_data, f, indent=4)

    def find_collision(self, m1, r1, m2, p, g):
        s_k = self.get_Private_value()

        delta_m = (m1 - m2) % p

        sk_inv = numbertheory.inverse_mod(s_k, p)
        r2 = (r1 + delta_m * sk_inv) % p
        return r2

    def packet_forwarding(self, packet: mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('LA had received message from ', source_entity)
        if source_entity == "RA":
            data = packet.data.decode()
            json_data = json.loads(data)
            veh_pub = base64.b64decode(json_data["Vehicule_pubkey"])
            veh_id = int.from_bytes(base64.b64decode(json_data["id"]), 'big')
            aes_key = self.derive_aes_key_from_data(
                veh_pub)
            LA_cipher = base64.b64decode(json_data["LA_cipher"])
            LA_cert = self.aes_decrypt(aes_key, LA_cipher)

            filename = str(veh_id) + LA_cert.decode() + ".json"
            file_path = Path(filename)
            if LA_cert == b"LA_CERT_1" or LA_cert == b"LA_CERT_2":
                curve = NIST256p.curve
                p = NIST256p.order
                g = NIST256p.generator
                aes_PC_LA_key = self.derive_aes_key(
                    self.connected_Entities["PCA"])
                aes_RA_LA_key = self.derive_aes_key(
                    self.connected_Entities["RA"])

                m1, r1 = int.from_bytes(os.urandom(32), 'big') % p, int.from_bytes(
                    os.urandom(32), 'big') % p
                H, PLV = self.chameleon_hash_and_PLV(m1, r1, p, g)
                encrypted_PLV_for_PCA = self.aes_encrypt(
                    aes_PC_LA_key, PLV.to_bytes(PLV.bit_length(), 'big'))
                encrypt_for_RA = self.aes_encrypt(
                    aes_RA_LA_key, encrypted_PLV_for_PCA)
                hash_to_file = {"Hc": H}
                if file_path.exists() == False:
                    with open(filename, "w") as f:
                        json.dump(hash_to_file, f)
                else:
                    m2 = int.from_bytes(os.urandom(32), 'big') % p
                    r2 = self.find_collision(m1, m2, r1, p, g)
                    with open(filename, "r") as f:
                        veh_data = json.load(f)
                        assert veh_data["Hc"] == self.chameleon_hash_and_PLV(
                            m2, r2, p, g)[0]
                        r1 = r2
                self.save_hash_to_json(m1, r1, filename, PLV)
                message = {
                    "id": veh_id,
                    "PLV": base64.b64encode(encrypt_for_RA).decode()
                }
                message_json = json.dumps(message)

                print(message_json)
                self.send(self.connected_Entities['RA'], message_json)
            else:
                print("Invalid LA cert")
        else:  # The source of the packet is not known
            pass

    def forward_and_empty_buffer(self, buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet = buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)

    def start(self):
        listening_thread = threading.Thread(
            target=self.listen_and_fill_buffer, args=(self.listening_address,))
        listening_thread.start()
        forwarding_thread = threading.Thread(
            target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()


class Pseudonym_Certificate_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule = 0

    def add_LA1(self, LA):
        self.connected_Entities["LA1"] = LA

    def add_LA2(self, LA):
        self.connected_Entities["LA2"] = LA

    def add_RA(self, RA):
        self.connected_Entities["RA"] = RA

    def add_vehicule(self, VEH):
        self.connected_vehicule += 1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)] = VEH

    def packet_forwarding(self, packet: mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('PCA had received a message from ', source_entity)
        if source_entity == "RA":
            self.send(self.connected_Entities['RA'], packet.data)
        else:  # the unknown
            pass

    def forward_and_empty_buffer(self, buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet = buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)

    def start(self):
        listening_thread = threading.Thread(
            target=self.listen_and_fill_buffer, args=(self.listening_address,))
        listening_thread.start()
        forwarding_thread = threading.Thread(
            target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()


class Long_Term_Certificate_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule = 0
        self.LTC_validity = {}

    def add_RA(self, RA):
        self.connected_Entities["RA"] = RA

    def add_vehicule(self, VEH):
        self.connected_vehicule += 1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)] = VEH

    def packet_forwarding(self, packet: mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('LTCA received a message from ', source_entity)
        if source_entity == "RA":
            data = packet.data.decode()
            json_data = json.loads(data)
            ID = json_data["id"]
            vehicule_pubkey = base64.b64decode(
                json_data["Vehicule_pubkey"])
            LTC = base64.b64decode(json_data["CipherLTC"])
            aes_key = self.derive_aes_key_from_data(vehicule_pubkey)
            LTC_decrypted = self.aes_decrypt(aes_key, LTC)
            if LTC_decrypted == b"LT_CERT":
                self.LTC_validity[ID] = "valid"
            message = {
                "id": ID,
                "validity": self.LTC_validity[ID]
            }
            message_json = json.dumps(message)
            print(message_json)
            self.send(self.connected_Entities['RA'], message_json.encode())
        else:  # the source is unknown
            pass

    def forward_and_empty_buffer(self, buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet = buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)

    def start(self):
        listening_thread = threading.Thread(
            target=self.listen_and_fill_buffer, args=(self.listening_address,))
        listening_thread.start()
        forwarding_thread = threading.Thread(
            target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()


class Vehicule (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)

    def add_LA1(self, LA):
        self.connected_Entities["LA1"] = LA

    def add_LA2(self, LA):
        self.connected_Entities["LA2"] = LA

    def add_PCA(self, PCA):
        self.connected_Entities["PCA"] = PCA

    def add_LTCA(self, LTCA):
        self.connected_Entities["LTCA"] = LTCA

    def add_RA(self, RA):
        self.connected_Entities["RA"] = RA

    def packet_forwarding(self, packet: mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        if source_entity == "RA":
            pass
        else:
            pass  # The source of the packet is not unknown

    def forward_and_empty_buffer(self, buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet = buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)

    def start(self):
        veh_listening_thread = threading.Thread(
            target=self.listen_and_fill_buffer, args=(self.listening_address,))
        veh_listening_thread.start()

        # forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        # forwarding_thread.start()


if __name__ == '__main__':

    # Address INIT
    ra_sending_address = Address('localhost', 5000)
    ra_listening_address = Address('localhost', 5006)
    la1_sending_address = Address('localhost', 5001)
    la1_listening_address = Address('localhost', 5007)
    la2_sending_address = Address('localhost', 5002)
    la2_listening_address = Address('localhost', 5008)
    LTCA_sending_address = Address('localhost', 5003)
    LTCA_listening_address = Address('localhost', 5009)
    PCA_sending_address = Address('localhost', 5004)
    PCA_listening_address = Address('localhost', 5010)
    veh_sending_address = Address('localhost', 5005)
    veh_listening_address = Address('localhost', 5011)

    # Entities creation
    RA = Registration_Authority(ra_sending_address, ra_listening_address)
    VEH = Vehicule(veh_sending_address, veh_listening_address)
    LTCA = Long_Term_Certificate_Authority(
        LTCA_sending_address, LTCA_listening_address)
    PCA = Pseudonym_Certificate_Authority(
        PCA_sending_address, PCA_listening_address)
    LA1 = Link_Authority(la1_sending_address, la1_listening_address)
    LA2 = Link_Authority(la2_sending_address, la2_listening_address)

    # Recognition (linking entities)
    RA.add_vehicule(VEH)
    RA.add_LA1(LA1)
    RA.add_LA2(LA2)
    RA.add_LTCA(LTCA)
    RA.add_PCA(PCA)

    LTCA.add_RA(RA)
    LTCA.add_vehicule(VEH)

    VEH.add_RA(RA)
    VEH.add_PCA(PCA)
    VEH.add_LA1(LA1)
    VEH.add_LA2(LA2)
    VEH.add_PCA(PCA)

    PCA.add_LA1(RA)
    PCA.add_LA2(LA2)
    PCA.add_RA(RA)
    PCA.add_vehicule(VEH)

    LA1.add_PCA(PCA)
    LA1.add_RA(RA)
    LA1.add_vehicule(VEH)

    LA2.add_PCA(PCA)
    LA2.add_RA(RA)
    LA2.add_vehicule(VEH)

    # Start services
    RA.start()
    print("1")
    VEH.start()
    LTCA.start()
    PCA.start()
    LA1.start()
    LA2.start()

    time.sleep(4)
    print('start sending')

    public_key_bytes = VEH.get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    aes_key_LTCA = VEH.derive_aes_key(LTCA)
    aes_key_LA1 = VEH.derive_aes_key(LA1)
    aes_key_LA2 = VEH.derive_aes_key(LA2)
    aes_key_RA = VEH.derive_aes_key(RA)

    LA1_encryption = VEH.aes_encrypt(aes_key_LA1, b"LA_CERT_1")
    LA2_encryption = VEH.aes_encrypt(aes_key_LA2, b"LA_CERT_2")
    second_LA1_encryption = VEH.aes_encrypt(aes_key_RA, LA1_encryption)
    second_LA2_encryption = VEH.aes_encrypt(aes_key_RA, LA2_encryption)

    first_encryption = VEH.aes_encrypt(aes_key_LTCA, b"LT_CERT")
    second_encryption = VEH.aes_encrypt(aes_key_RA, first_encryption)

    message = {
        "PubKey": base64.b64encode(public_key_bytes).decode(),
        "CipherLTC": base64.b64encode(second_encryption).decode(),
        "CipherLA1": base64.b64encode(second_LA1_encryption).decode(),
        "CipherLA2": base64.b64encode(second_LA2_encryption).decode()
    }
    message_json = json.dumps(message)
    VEH.send(RA,  message_json.encode())
    # VEH.send(PCA,'hello'.encode('utf-8'))
    # VEH.send(RA,'hello'.encode('utf-8'))
    # VEH.send(RA,'hello'.encode('utf-8'))
