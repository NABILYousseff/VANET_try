from .Entity import *
import threading
import json
import os
import base64
import random
from pathlib import Path

class Link_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule = 0
        while True:
            self.id = random.randint(0,int(5e12))
            self.filename = "LA_"+str(self.id)+".json"
            self.file_path = Path(self.filename)
            if self.file_path.exists() == False:
                with open(self.filename, "w") as f:
                    #entree sous forme de [{'id':accorde par le certif, 'message':m1,'random':random, 'hash':chameleon hash, 'PLVs':[PLV1,PLV2,....]}]
                    file_init=[]
                    json.dump(file_init, f)
                break

        

    def add_RA(self, RA):
        self.connected_Entities["RA"] = RA

    def add_PCA(self, PCA):
        self.connected_Entities["PCA"] = PCA

    def add_vehicule(self, VEH):
        self.connected_vehicule += 1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)] = VEH
        id_veh=str(random.randint(0,int(5e12)))
        LA_certif='LA_cert'+id_veh                                                   # to change with a real cert
        m, r = int.from_bytes(os.urandom(32), 'big') % self.p, int.from_bytes(
                    os.urandom(32), 'big') % self.p
        H, _ = self.chameleon_hash_and_PLV(m, r)
        with open(self.filename,"r") as f:
            data:list=json.load(f)
            data.append({'id':LA_certif, 'message':m,'random':r, 'hash':H, 'PLVs':[]})
        with open(self.filename,"w") as f:
            json.dump(data,f)
        return LA_certif

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
            LA_cert = self.aes_decrypt(aes_key, LA_cipher).decode()
            with open(self.filename,"r") as f:
                file_content:list=json.load(f)
            valid_cert=False
            #Condition pour la verififcation de la certif
            for record_num in range(len(file_content)):
                if LA_cert == file_content[record_num]['id']:
                    valid_cert=True
                    aes_PC_LA_key = self.derive_aes_key_from_data(
                        self.connected_Entities["PCA"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))           #not
                    aes_RA_LA_key = self.derive_aes_key_from_data(
                        self.connected_Entities["RA"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))            #not
                    m1, r1 = file_content[record_num]["message"], file_content[record_num]["random"]
                    m2 = int.from_bytes(os.urandom(32), 'big') % self.p
                    r2 = self.find_collision(m1, r1, m2)
                    H, PLV = self.chameleon_hash_and_PLV(m2, r2)
                    assert(H==file_content[record_num]["hash"])
                    file_content[record_num]["PLVs"].append(PLV)
                    with open(self.filename,"w") as f:
                        json.dump(file_content,f)
                    encrypted_PLV_for_PCA = self.aes_encrypt(
                        aes_PC_LA_key, str(PLV).encode())
                    
                    message = {
                        "id": json_data["id"],
                        "PLV": base64.b64encode(encrypted_PLV_for_PCA).decode()
                    }
                    message_json = json.dumps(message)
                    encrypt_for_RA = self.aes_encrypt(aes_RA_LA_key,message_json.encode())
                    self.send(self.connected_Entities['RA'], encrypt_for_RA)
            if not valid_cert:
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
