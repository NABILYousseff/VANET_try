from .Entity import *
import threading
import json
import base64
from pathlib import Path

class Pseudonym_Certificate_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule = 0
        while True:
            self.id = random.randint(0,int(5e12))
            self.filename = "PCA_"+str(self.id)+".json"
            self.file_path = Path(self.filename)
            if self.file_path.exists() == False:
                with open(self.filename, "w") as f:
                    #entree sous forme de [{'PC', 'PLV1','PLV2'}]
                    file_init=[]
                    json.dump(file_init, f)
                break

    def add_LA1(self, LA):
        self.connected_Entities["LA1"] = LA

    def add_LA2(self, LA):
        self.connected_Entities["LA2"] = LA

    def add_RA(self, RA):
        self.connected_Entities["RA"] = RA

    def packet_forwarding(self, packet: mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('PCA had received a message from ', source_entity)
        if source_entity == "RA":
            data=packet.data.decode()
            json_data=json.loads(data)
            PLV1=base64.b64decode(json_data["PLV1"])
            PLV2=base64.b64decode(json_data["PLV2"])
            veh_pub=base64.b64decode(json_data["Vehicule_pubkey"])
            
            aes_key = self.derive_aes_key_from_data(self.connected_Entities["LA1"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))
            decrypt_PLV1 = int(self.aes_decrypt(aes_key, PLV1))
            aes_key = self.derive_aes_key_from_data(self.connected_Entities["LA2"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))
            decrypt_PLV2 = int(self.aes_decrypt(aes_key, PLV2))
            PC=decrypt_PLV1+decrypt_PLV2 % self.p
            aes_PCA_VEH=self.derive_aes_key_from_data(veh_pub)
            encrypt_PC_for_VEH = self.aes_encrypt(
                        aes_PCA_VEH, str(PC).encode())
            
            ## loading file
            with open(self.filename,"r") as f:
                data:list=json.load(f)
                #TODO change this line after finding a cert generator
                data.append({ 'PC': PC, 'PLV1':decrypt_PLV1, 'PLV2':decrypt_PLV2})   #the la certif can be changed with a certificate content
            with open(self.filename,"w") as f:
                json.dump(data,f)
            
            message = {
                    "id": json_data["id"],
                    "Vehicule_pubkey": base64.b64encode(veh_pub).decode(),
                    "PC": base64.b64encode(encrypt_PC_for_VEH).decode()
            }
            message_json = json.dumps(message)
            self.send(self.connected_Entities['RA'], message_json.encode())
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