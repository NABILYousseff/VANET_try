from .Entity import *
import threading
import json
import base64
from pathlib import Path

class Long_Term_Certificate_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule = 0
        self.id = random.randint(0,int(5e12))
        self.id = random.randint(0,int(5e12))
        self.filename = "LTCA_"+str(self.id)+".json"
        self.file_path = Path(self.filename)
        if self.file_path.exists() == False:
            with open(self.filename, "w") as f:
                #entree sous forme de [{'id':id in the content of LTC, 'LTC':Long term certif}]
                file_init=[]
                json.dump(file_init, f)

    def add_RA(self, RA):
        self.connected_Entities["RA"] = RA

    def newVehicule(self):
        id_veh=str(random.randint(0,int(5e12)))
        #TODO change this line after finding a cert generator
        LT_certif='LT_cert'+id_veh                                                   # to change with a real cert_content
        with open(self.filename,"r") as f:
            data:list=json.load(f)
            #TODO change this line after finding a cert generator
            data.append({'id':LT_certif, 'LTC':LT_certif})
        with open(self.filename,"w") as f:
            json.dump(data,f)
        return LT_certif

        

    def packet_processing(self, packet: mini_packet):
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
            LTC_decrypted = self.aes_decrypt(aes_key, LTC).decode()
            
            with open(self.filename,"r") as f:
                file_content:list=json.load(f)
            LTC_validity = "invalid" 
            for record in file_content:
                #TODO change this line after finding a cert generator to handle the comparaison
                if record['id'] == LTC_decrypted:
                    LTC_validity = "valid"     
            message = {
                "id": ID,
                "validity": LTC_validity
            }
            message_json = json.dumps(message)
            self.send(self.connected_Entities['RA'], message_json.encode())
        else:  # the source is unknown
            pass

    def forward_and_empty_buffer(self, buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet = buffer[0]
                self.packet_processing(packet)
                buffer.pop(0)

    def start(self):
        listening_thread = threading.Thread(
            target=self.listen_and_fill_buffer, args=(self.listening_address,))
        listening_thread.start()
        forwarding_thread = threading.Thread(
            target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()
