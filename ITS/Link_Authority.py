from .Entity import *
import threading
import json
import os
import base64
import random
from pathlib import Path
from .certs_util import *


class Link_Authority (Entity):
    """Link Authority (LA) class handles the management of link certificates,
    """
    def __init__(self, sending_address, listening_address):
        """
        Initialize the Link Authority (LA) with the given addresses.

        param
        -----
            sending_address : used for sending messages.
            listening_address : used for listening to incoming messages.
        """
        super().__init__(sending_address, listening_address)
        self.connected_vehicule = 0

        cert_path = Path(f"ca/{self.__class__.__name__}_{self.id}.cert")
        if not cert_path.exists():
            print(f"[{self.__class__.__name__}] No cert found, generating one...")
            self.generate_own_cert()
        else:
            print(f"[{self.__class__.__name__}] Cert already exists.")
        while True:
            self.filename = "LA_"+str(self.id)+".json"
            self.file_path = Path(self.filename)
            if self.file_path.exists() == False:
                with open(self.filename, "w") as f:
                    file_init = []
                    json.dump(file_init, f)
                break

    def add_RA(self, RA: Entity):
        """        Add the Registration Authority (RA) to the connected entities.
        param
        -----
            RA : The Registration Authority to add.
        """
        self.connected_Entities["RA"] = RA

    def add_PCA(self, PCA: Entity):
        """        Add the Pseudonym Certificate Authority (PCA) to the connected entities.
        param
        -----
            PCA : The Pseudonym Certificate Authority to add.
        """
        self.connected_Entities["PCA"] = PCA

    def generate_own_cert(self):
        """
            Generate a new certificate for the Link Authority.
        """
        with open("ca/root_ca.key.pem", "rb") as f:
            root_priv = serialization.load_pem_private_key(
                f.read(), password=None)

        with open("ca/root_ca.cert", "rb") as f:
            issuer_cert_bytes = f.read()

        cert = build_authority_cert(
            self.get_Public_Key(),
            issuer_cert_bytes,
            issuer_priv=root_priv,
            subject_name=f"{self.__class__.__name__}_{self.id}",
            authority_type="authorization-authority"  # or authorization-authority
        )

        with open(f"ca/{self.__class__.__name__}_{self.id}.cert", "wb") as f:
            f.write(cert)

    def newVehicule(self, veh):
        """
        Generate a new certificate for the vehicle and store it in the LA's database.
        """
        my_cert_path = Path(f"ca/{self.__class__.__name__}_{self.id}.cert")
        issuer_cert_bytes = my_cert_path.read_bytes()

        cert_bytes = build_enrollment_cert(
            subject_pub=veh.get_Public_Key(),
            issuer_cert_bytes=issuer_cert_bytes,
            issuer_priv=self._Entity__Private_Key,
            subject_name=f"VEH_{veh.id}"
        )
        encoded = base64.b64encode(cert_bytes).decode()
        veh_Sk = ec.generate_private_key(
            ec.SECP256R1()).private_numbers().private_value
        m, r = int.from_bytes(os.urandom(32), 'big') % self.p, int.from_bytes(
            os.urandom(32), 'big') % self.p
        H = Cryptico.chameleon_hash(veh_Sk, m, r)
        with open(self.filename, "r") as f:
            data: list = json.load(f)
            data.append({'id': encoded, 'message': m, 'random': r, 'hash': H, 'PLVs': [], 'Sk': veh_Sk}) 
        with open(self.filename, "w") as f:
            json.dump(data, f)
        return encoded

    @override
    def packet_forwarding(self, packet: mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('LA had received message from ', source_entity)
        
        if source_entity == "RA":
            aes_key = self.derive_aes_key_from_data(self.connected_Entities[source_entity].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
            decrypt_data = Cryptico.aes_decrypt(aes_key, packet.data)
            data = decrypt_data.decode()
            json_data = json.loads(data)
            veh_pub = base64.b64decode(json_data["Vehicule_pubkey"])
            aes_key = self.derive_aes_key_from_data(
                veh_pub)
            LA_cipher = base64.b64decode(json_data["LA_cipher"])
            LA_cert = Cryptico.aes_decrypt(aes_key, LA_cipher)
            LA_correct_form = base64.b64decode(LA_cert)
            print("LA speaking : ...", LA_correct_form)
            validity = verify_cert_signature(
                LA_correct_form, self.get_Public_Key())
            if not validity:
                print("INVALID CERT")
                return
            else:
                print("[!!] Valid Signature ")
                print("[*] Opening database ...")
            with open(self.filename, "r") as f:
                file_content: list = json.load(f)
            valid_cert = False
            # Condition pour la verififcation de la certif
            for record_num in range(len(file_content)):
                if LA_cert.decode() == file_content[record_num]['id']:
                    valid_cert = True
                    aes_PC_LA_key = self.derive_aes_key_from_data(
                        self.connected_Entities["PCA"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))
                    m1, r1 = file_content[record_num]["message"], file_content[record_num]["random"]
                    veh_Sk = file_content[record_num]['Sk']
                    m2 = int.from_bytes(os.urandom(32), 'big') % self.p
                    r2 = Cryptico.find_collision(veh_Sk, m1, r1, m2)
                    H, PLV = Cryptico.chameleon_hash(
                        veh_Sk, m2, r2), Cryptico.group_addition(m2, r2)
                    assert (H == file_content[record_num]["hash"])
                    file_content[record_num]["PLVs"].append(PLV)
                    with open(self.filename, "w") as f:
                        json.dump(file_content, f)
                    encrypted_PLV_for_PCA = Cryptico.aes_encrypt(
                        aes_PC_LA_key, str(PLV).encode())

                    message = {
                        "id": json_data["id"],
                        "PLV": base64.b64encode(encrypted_PLV_for_PCA).decode(),
                        "security field": random.randint(0, int(5e12))
                    }
                    message_json = json.dumps(message)
                    # encrypt and send to RA
                    aes_RA_LA_key = self.derive_aes_key_from_data(
                        self.connected_Entities["RA"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo))
                    encrypt_for_RA = Cryptico.aes_encrypt(
                        aes_RA_LA_key, message_json.encode())
                    self.send(self.connected_Entities['RA'], encrypt_for_RA)
            if not valid_cert:
                print("Invalid LA cert")
        
        else:  # The source of the packet is not known
            pass
    
    @override
    def forward_and_empty_buffer(self, buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet = buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)

    def getLinkedPLVs(self, PLV_to_link):
        """
        Retrieve the linked PLVs for a given PLV.
        """
        with open(self.filename, "r") as f:
            file_content: list = json.load(f)
        for record in file_content:
            for PLV in record['PLVs']:
                if PLV == PLV_to_link:
                    return record['PLVs']
        print("no such PLV")
        return None

    @override
    def start(self):
        listening_thread = threading.Thread(
            target=self.listen_and_fill_buffer, args=(self.listening_address,))
        listening_thread.start()
        forwarding_thread = threading.Thread(
            target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()
