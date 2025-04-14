from .Entity import *
import threading
import json
import base64

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
            LTC_decrypted = self.aes_decrypt(aes_key, LTC)
            if LTC_decrypted == b"LT_CERT":
                self.LTC_validity[ID] = "valid"
            message = {
                "id": ID,
                "validity": self.LTC_validity[ID]
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
