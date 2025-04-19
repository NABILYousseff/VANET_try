from .Entity import *
import threading
import json
import os
import base64

class Vehicule (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.Pseudo_cert=[]

    def set_LA_cert(self,LA1_cert, LA2_cert, LTCA_cert):
        self.LA1_certif = LA1_cert
        self.LA2_certif = LA2_cert
        self.LT_certif  = LTCA_cert


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
        print('Vehicule had received a message from',source_entity)
        if source_entity == "RA":
            data=packet.data.decode()
            json_data=json.loads(data)
            PC=base64.b64decode(json_data["PC"])
            aes_key = self.derive_aes_key_from_data(self.connected_Entities["PCA"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))
            decrypt_PC = int(self.aes_decrypt(aes_key, PC))
            self.Pseudo_cert.append(decrypt_PC)
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
        
        aes_key_LTCA = self.derive_aes_key(self.connected_Entities["LTCA"])
        aes_key_LA1 = self.derive_aes_key(self.connected_Entities["LA1"])
        aes_key_LA2 = self.derive_aes_key(self.connected_Entities["LA2"])
        aes_key_RA = self.derive_aes_key(self.connected_Entities["RA"])

        LA1_encryption = self.aes_encrypt(aes_key_LA1, self.LA1_certif.encode())
        LA2_encryption = self.aes_encrypt(aes_key_LA2, self.LA2_certif.encode())
        second_LA1_encryption = self.aes_encrypt(aes_key_RA, LA1_encryption)
        second_LA2_encryption = self.aes_encrypt(aes_key_RA, LA2_encryption)

        first_encryption = self.aes_encrypt(aes_key_LTCA, b"LT_CERT")
        second_encryption = self.aes_encrypt(aes_key_RA, first_encryption)

        message = {
            "PubKey": base64.b64encode(public_key_bytes).decode(),
            "CipherLTC": base64.b64encode(second_encryption).decode(),
            "CipherLA1": base64.b64encode(second_LA1_encryption).decode(),
            "CipherLA2": base64.b64encode(second_LA2_encryption).decode()
        }
        message_json = json.dumps(message)
        self.send(self.connected_Entities["RA"],  message_json.encode())

    def start(self):
        veh_listening_thread = threading.Thread(target=self.listen_and_fill_buffer, args=(self.listening_address,))
        veh_listening_thread.start()
        forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()

    def requestPC(self):
        pass
