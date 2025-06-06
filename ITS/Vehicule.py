from .Entity import *
import threading
import json
import os
import base64
from pathlib import Path


class Vehicule (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.Pseudo_cert = []
        while True:
            # self.id = random.randint(0, int(5e12))
            self.filename = "VEH_"+str(self.id)+".json"
            self.file_path = Path(self.filename)
            if self.file_path.exists() == False:
                with open(self.filename, "w") as f:
                    # entree sous forme de {'LT_cert', 'LA1_cert','LA2_cert', 'PCs':[PC1, PC2, ....] }
                    file_init = dict()
                    json.dump(file_init, f)
                break

    def set_cert(self, LA1_cert, LA2_cert, LT_cert):
        self.LA1_certif = LA1_cert
        self.LA2_certif = LA2_cert
        self.LT_certif = LT_cert
        with open(self.filename, "r") as f:
            data: list = json.load(f)
            # TODO change this line after finding a cert generator
            data["LA1_cert"] = LA1_cert
            data["LA2_cert"] = LA2_cert
            data["LT_cert"] = LT_cert
            data["PCs"] = []
        with open(self.filename, "w") as f:
            json.dump(data, f)

    def set_PKs(self, Pkey_RA, Pkey_LTCA, Pkey_LA1, Pkey_LA2):
        self.Pkey_RA = Pkey_RA
        self.Pkey_LTCA = Pkey_LTCA
        self.Pkey_LA1 = Pkey_LA1
        self.Pkey_LA2 = Pkey_LA2

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
        print(
            f"\033[1;32mVehicule had received a message from {source_entity}\033[0m")
        if source_entity == "RA":
            data = packet.data.decode()
            json_data = json.loads(data)
            PC = base64.b64decode(json_data["PC"])
            aes_key = self.derive_aes_key_from_data(self.connected_Entities["PCA"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
            decrypt_PC = self.aes_decrypt(aes_key, PC)
            self.Pseudo_cert.append(base64.b64encode(decrypt_PC).decode())
            with open(self.filename, "r") as f:
                data: list = json.load(f)
                # TODO change this line after finding a cert generator
                data["PCs"].append(base64.b64encode(decrypt_PC).decode())
            with open(self.filename, "w") as f:
                json.dump(data, f)
        else:
            pass  # The source of the packet is not unknown

    def forward_and_empty_buffer(self, buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet = buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)

    def send_request(self):

        public_key_bytes = self.get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                              format=serialization.PublicFormat.SubjectPublicKeyInfo)
        aes_key_LTCA = self.derive_aes_key_from_data(self.Pkey_LTCA)
        aes_key_LA1 = self.derive_aes_key_from_data(self.Pkey_LA1)
        aes_key_LA2 = self.derive_aes_key_from_data(self.Pkey_LA2)
        aes_key_RA = self.derive_aes_key_from_data(self.Pkey_RA)

        LA1_encryption = self.aes_encrypt(
            aes_key_LA1, self.LA1_certif.encode())
        LA2_encryption = self.aes_encrypt(
            aes_key_LA2, self.LA2_certif.encode())
        LTC_encryption = self.aes_encrypt(
            aes_key_LTCA, self.LT_certif.encode())

        message = {
            "PubKey": base64.b64encode(public_key_bytes).decode(),
            "CipherLTC": base64.b64encode(LTC_encryption).decode(),
            "CipherLA1": base64.b64encode(LA1_encryption).decode(),
            "CipherLA2": base64.b64encode(LA2_encryption).decode()
        }
        message_json = json.dumps(message)
        print("\033[35mVEH send request\033[0m")
        self.send(self.connected_Entities["RA"],  message_json.encode())

    def start(self):
        veh_listening_thread = threading.Thread(
            target=self.listen_and_fill_buffer, args=(self.listening_address,))
        veh_listening_thread.start()
        forwarding_thread = threading.Thread(
            target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()

    def requestPC(self):
        pass
