from .Entity import *
import threading
import json
import os
import base64

class Vehicule (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)

    def add_LA1(self, LA):
        self.LA1_certif='LA1_cert'+str(self.id)
        self.connected_Entities["LA1"] = LA
        m, r = int.from_bytes(os.urandom(32), 'big') % self.p, int.from_bytes(
                    os.urandom(32), 'big') % self.p
        H, _ = LA.chameleon_hash_and_PLV(m, r, self.p, self.g)
        with open(LA.filename,"r") as f:
            data:list=json.load(f)
            #le id est a remplir par le certif
            data.append({'id':self.LA1_certif, 'message':m,'random':r, 'hash':H, 'PLVs':[]})
        with open(LA.filename,"w") as f:
            json.dump(data,f)
        

    def add_LA2(self, LA):
        self.connected_Entities["LA2"] = LA
        self.LA2_certif='L21_cert'+str(self.id)
        m, r = int.from_bytes(os.urandom(32), 'big') % self.p, int.from_bytes(
                    os.urandom(32), 'big') % self.p
        H, _ = LA.chameleon_hash_and_PLV(m, r, self.p, self.g)
        with open(LA.filename,"r") as f:
            data:list=json.load(f)
            #le id est a remplir par le certif
            data.append({'id':self.LA2_certif, 'message':m,'random':r, 'hash':H, 'PLVs':[]})
        with open(LA.filename,"w") as f:
            json.dump(data,f)

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
            aes_key = self.derive_aes_key(self.connected_Entities["PCA"])
            decrypt_PC = int(self.aes_decrypt(aes_key, PC))
        else:
            pass  # The source of the packet is not unknown

    def forward_and_empty_buffer(self, buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet = buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)

    def start(self):
        veh_listening_thread = threading.Thread(target=self.listen_and_fill_buffer, args=(self.listening_address,))
        veh_listening_thread.start()
        forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()
