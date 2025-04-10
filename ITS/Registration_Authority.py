import threading
from .Entity import *
import json
import os
import base64

class Registration_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule = 0
        self.PLVs = {}
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
        if source_entity == None:
            pass  # The source of the packet is not known
        elif source_entity == "LA1":
            aes_key = self.derive_aes_key(self.connected_Entities["LA1"])
            decrypt_data = self.aes_decrypt(aes_key, packet.data)
            data = decrypt_data.decode()
            json_data = json.loads(data)
            PLV = base64.b64decode(json_data["PLV"])
            self.PLVs["PLV1"] = PLV
            if "PLV2" in self.PLVs.keys():
                ID = base64.b64decode(json_data["id"])
                veh_pub = self.pubkeys_house[ID]

                message = {
                    "id": json_data["id"],
                    "Vehicule_pubkey": base64.b64encode(veh_pub).decode(),
                    "PLV1": base64.b64encode(self.PLVs["PLV1"]).decode(),
                    "PLV2": base64.b64encode(self.PLVs["PLV2"]).decode()
                }
                message_json = json.dumps(message)

                self.send(
                    self.connected_Entities["PCA"], message_json.encode())
            else:
                pass

        elif source_entity == "LA2":
            aes_key = self.derive_aes_key(self.connected_Entities["LA2"])
            decrypt_data = self.aes_decrypt(aes_key, packet.data)
            data = decrypt_data.decode()
            json_data = json.loads(data)
            PLV = base64.b64decode(json_data["PLV"])
            self.PLVs["PLV2"] = PLV
            if "PLV1" in self.PLVs.keys():
                ID = base64.b64decode(json_data["id"])
                veh_pub = self.pubkeys_house[ID]

                message = {
                    "id": json_data["id"],
                    "Vehicule_pubkey": base64.b64encode(veh_pub).decode(),
                    "PLV1": base64.b64encode(self.PLVs["PLV1"]).decode(),
                    "PLV2": base64.b64encode(self.PLVs["PLV2"]).decode()
                }
                message_json = json.dumps(message)

                self.send(
                    self.connected_Entities["PCA"], message_json.encode())
            else:
                pass

        elif source_entity == "LTCA":
            print('Sending Linkage certif to LA1 and LA2..')
            # verfying if response is true or false
            data = packet.data.decode()
            json_data = json.loads(data)
            found = False
            if json_data["validity"] == "valid":
                ID = json_data["id"]
                for quadruple in self.RA_buffer:
                    if quadruple[0] == base64.b64decode(ID):
                        found = True
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
                        message1_json = json.dumps(message1)
                        self.send(
                            self.connected_Entities['LA1'], message1_json.encode())
                        self.send(
                            self.connected_Entities['LA2'], message2_json.encode())
                if found is False:
                    print("id not found")
            else:
                print("LTC is invalid")
        elif source_entity == "PCA":
            received_data=packet.data.decode()
            json_data=json.loads(received_data)
            ID = base64.b64decode(json_data["id"])
            PC=base64.b64decode(json_data["PC"])
            veh_pub=base64.b64decode(json_data["Vehicule_pubkey"])
            for vehicule_record in self.RA_buffer:
                if vehicule_record[0]==ID:
                    message = {
                        "PC": base64.b64encode(PC).decode()
                    }
                    message_json = json.dumps(message)
                    self.send(vehicule_record[4],message_json.encode())
        else:  # the entity is a vehicule implement then a function to send LTC in data to LTCA
            # processing...
            ID = os.urandom(32)
            ID_to_send = base64.b64encode(ID).decode()
            VEH = self.connected_Entities[source_entity]
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
            self.send(self.connected_Entities['LTCA'], message_json.encode())

            self.RA_buffer.append(
                [ID, v_pub, Nested_LA1_Cipher.decode(), Nested_LA2_Cipher.decode(), VEH])
            self.pubkeys_house[ID] = vehicule_pubkey

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