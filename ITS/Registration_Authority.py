import threading
from .Entity import *
import json
import os
import base64

class Registration_Authority (Entity):
    """
    Registration Authority (RA) class handles the registration of vehicles,
    communication with other entities, and storage of vehicle-related data.
    """

    def __init__(self, sending_address: Address, listening_address: Address):
        """
        Initialize the Registration Authority (RA) with the given addresses.
        param
        -----
            sending_address : used for sending messages.
            listening_address : used for listening to incoming messages.
        """
        super().__init__(sending_address, listening_address)
        self.connected_vehicule = 0
        self.PLVs = {}
        self.RA_buffer = []
        self.pubkeys_house = {}

    def add_LA1(self, LA: Entity):
        """
        Add the first Local Authority (LA1) to the connected entities.
        param
        -----
            LA : The Local Authority to add.
        
        """
        self.connected_Entities["LA1"] = LA

    def add_LA2(self, LA: Entity):
        """
        Add the second Local Authority (LA2) to the connected entities.
        """
        self.connected_Entities["LA2"] = LA

    def add_PCA(self, PCA: Entity):
        """
        Add the Pseudonym Certificate Authority (PCA) to the connected entities.
        """
        self.connected_Entities["PCA"] = PCA

    def add_LTCA(self, LTCA: Entity):
        """
        Add the Long Term Certificate Authority (LTCA) to the connected entities.
        """
        self.connected_Entities["LTCA"] = LTCA

    def add_vehicule(self, VEH: Entity):
        self.connected_vehicule += 1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)] = VEH

    @override
    def packet_forwarding(self, packet: mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('RA received a message from ', source_entity)
        if source_entity == None:
            pass  # The source of the packet is not known
        
        # decrypting the data
        #aes_key = self.derive_aes_key_from_data(self.connected_Entities[source_entity].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
        #                                                format=serialization.PublicFormat.SubjectPublicKeyInfo))
        #decrypt_data = Cryptico.aes_decrypt(aes_key, packet.data)
        
        elif source_entity == "LA1" or source_entity == "LA2":
            # processing the data
            aes_key = self.derive_aes_key_from_data(self.connected_Entities[source_entity].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
            decrypt_data = Cryptico.aes_decrypt(aes_key, packet.data)
            data = decrypt_data.decode()
            json_data = json.loads(data)
            PLV = base64.b64decode(json_data["PLV"])
            ID = base64.b64decode(json_data["id"]) #Here
            self.PLVs[ID]["PLV"+source_entity[2]] = PLV
            otherPLV = "PLV1" if source_entity[2]=="2" else "PLV2"
            if otherPLV in self.PLVs[ID].keys():
                veh_pub = self.pubkeys_house[ID]

                message = {
                    "id": json_data["id"],
                    "Vehicule_pubkey": base64.b64encode(veh_pub).decode(),
                    "PLV1": base64.b64encode(self.PLVs[ID]["PLV1"]).decode(),
                    "PLV2": base64.b64encode(self.PLVs[ID]["PLV2"]).decode()
                }
                message_json = json.dumps(message)
                aes_PCA_key = self.derive_aes_key_from_data(
                        self.connected_Entities["PCA"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo))
                encrypt_for_PCA = Cryptico.aes_encrypt(aes_PCA_key, message_json.encode())
                self.send(
                    self.connected_Entities["PCA"], encrypt_for_PCA)
            else:
                pass
        
        elif source_entity == "LTCA":
            aes_key = self.derive_aes_key_from_data(self.connected_Entities[source_entity].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
            decrypt_data = Cryptico.aes_decrypt(aes_key, packet.data)
            # verfying if response is true or false
            data = decrypt_data.decode()
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
                        print('Sending Linkage certif to LA1..')
                        
                        aes_LA1_key = self.derive_aes_key_from_data(
                        self.connected_Entities["LA1"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo))
                        encrypt_for_LA1 = Cryptico.aes_encrypt(aes_LA1_key, message1_json.encode())
                        self.send(
                            self.connected_Entities['LA1'], encrypt_for_LA1)
                        
                        print('Sending Linkage certif to LA2..')
                        aes_LA2_key = self.derive_aes_key_from_data(
                            self.connected_Entities["LA2"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
                        encrypt_for_LA2 = Cryptico.aes_encrypt(aes_LA2_key, message2_json.encode())
                        self.send(
                            self.connected_Entities['LA2'], encrypt_for_LA2)
                if found is False:
                    print("id not found")
            else:
                print("LTC is invalid")

        elif source_entity == "PCA":
            aes_key = self.derive_aes_key_from_data(self.connected_Entities[source_entity].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
            decrypt_data = Cryptico.aes_decrypt(aes_key, packet.data)
            received_data=decrypt_data.decode()
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
                    aes_key = self.derive_aes_key_from_data(veh_pub)
                    encrypt_for_vehicule = Cryptico.aes_encrypt(aes_key, message_json.encode())
                    self.send(vehicule_record[4], encrypt_for_vehicule)
                    self.RA_buffer.remove(vehicule_record)
        else:  # The entity is a vehicle; process its registration request and forward the LTC request to the LTCA
            ID = os.urandom(32)
            self.PLVs[ID] = {}
            ID_to_send = base64.b64encode(ID).decode()
            VEH = self.connected_Entities[source_entity]
            data = packet.data.decode()
            json_data = json.loads(data)
            v_pub = json_data["PubKey"]

            # Decrypting the message
            aes_key = self.derive_aes_key_from_data(self.connected_Entities[source_entity].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
            json_data = Cryptico.aes_decrypt(aes_key, base64.b64decode(json_data["encrypted"].encode()))
            json_data = json.loads(json_data)
            LTC_Cipher = base64.b64decode(json_data["CipherLTC"])
            LA1_cipher = json_data["CipherLA1"]
            LA2_cipher = json_data["CipherLA2"]
            
            vehicule_pubkey = base64.b64decode(v_pub)
            message = {
                "id": ID_to_send,
                "Vehicule_pubkey": v_pub,
                "CipherLTC": base64.b64encode(LTC_Cipher).decode()
            }

            message_json = json.dumps(message)
            print('Sending LTC to LTCA')

            aes_RA_LTCA_key = self.derive_aes_key_from_data(
                        self.connected_Entities["LTCA"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo))
            encrypt_for_LTCA = Cryptico.aes_encrypt(aes_RA_LTCA_key, message_json.encode())
            self.send(self.connected_Entities['LTCA'], encrypt_for_LTCA)

            self.RA_buffer.append([ID, v_pub, LA1_cipher, LA2_cipher, VEH])
            self.pubkeys_house[ID] = vehicule_pubkey

    @override
    def forward_and_empty_buffer(self, buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet = buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)

    @override
    def start(self):
        ra_listening_thread = threading.Thread(
            target=self.listen_and_fill_buffer, args=(self.listening_address,))
        ra_listening_thread.start()
        ra_forwarding_thread = threading.Thread(
            target=self.forward_and_empty_buffer, args=(self.buffer,))
        ra_forwarding_thread.start()