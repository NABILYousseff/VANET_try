from .Entity import *
import threading
import json
import base64
from pathlib import Path
from .certs_util import *
from pprint import pprint


class Pseudonym_Certificate_Authority (Entity):
    """
    Pseudonym Certificate Authority (PCA) class handles the generation of pseudonym certificates,
    communication with other entities, and storage of pseudonym-related data.
    """
    def __init__(self, sending_address: Address, listening_address: Address):
        """
        Initialize the Pseudonym Certificate Authority (PCA) with the given addresses.

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
            self.filename = "PCA_"+str(self.id)+".json"
            self.file_path = Path(self.filename)
            if self.file_path.exists() == False:
                with open(self.filename, "w") as f:
                    # entree sous forme de [{'PC', 'PLV1','PLV2'}]
                    file_init = []
                    json.dump(file_init, f)
                break

    def add_LA1(self, LA : Entity):
        """
        Adds the first Local Authority (LA1) to the connected entities.

        param
        -----
            LA : The Local Authority to add.
        """
        self.connected_Entities["LA1"] = LA

    def add_LA2(self, LA : Entity):
        """
        Adds the second Local Authority (LA2) to the connected entities.

        param
        -----
            LA : The Local Authority to add.
        """
        self.connected_Entities["LA2"] = LA

    def add_RA(self, RA : Entity):
        """
        Adds the Registration Authority (RA) to the connected entities.

        param
        -----
            RA : The Registration Authority to add.
        """
        self.connected_Entities["RA"] = RA

    def generate_own_cert(self):
        """
        Generate a self-signed certificate for the Pseudonym Certificate Authority (PCA).
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

    def getPLV(self, PC):
        """
        Get the PLV (Pseudonym Linkage Value) for a given Pseudonym Certificate (PC).
        """
        with open(self.filename, "r") as f:
            data: list = json.load(f)
        for i in range(len(data)):
            if data[i]['PC'] == PC:
                PLV1 = data[i]['PLV1']
                PLV2 = data[i]['PLV2']
                return [PLV1, PLV2]
        print("PCA: PC not found")
        return [None, None]

    def getLinkedPCs(self, PLVS):
        """
        Get the linked Pseudonym Certificates (PCs) for a given list of Pseudonym Linkage Values (PLV1, PLV2).
        """
        PCs = []
        with open(self.filename, "r") as f:
            data: list = json.load(f)
        for record in data:
            if record["PLV1"] in PLVS:
                PCs.append(record["PC"])
        return PCs
    
    @override
    def packet_forwarding(self, packet: mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('PCA had received a message from ', source_entity)
        if source_entity == "RA":
            aes_key = self.derive_aes_key_from_data(self.connected_Entities[source_entity].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
            decrypt_data = Cryptico.aes_decrypt(aes_key, packet.data)
            data = decrypt_data.decode()
            json_data = json.loads(data)
            PLV1 = base64.b64decode(json_data["PLV1"])
            PLV2 = base64.b64decode(json_data["PLV2"])
            veh_pub = base64.b64decode(json_data["Vehicule_pubkey"])

            aes_key = self.derive_aes_key_from_data(self.connected_Entities["LA1"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
            decrypt_PLV1 = int(Cryptico.aes_decrypt(aes_key, PLV1))
            aes_key = self.derive_aes_key_from_data(self.connected_Entities["LA2"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
            decrypt_PLV2 = int(Cryptico.aes_decrypt(aes_key, PLV2))
            LV = Cryptico.group_addition(decrypt_PLV1, decrypt_PLV2, self.p)
            priv_ephemeral_key = ec.generate_private_key(ec.SECP256R1())
            pub_ephemeral_key = priv_ephemeral_key.public_key()

            my_cert_path = Path(f"ca/{self.__class__.__name__}_{self.id}.cert")
            issuer_cert_bytes = my_cert_path.read_bytes()
            actual_PC = build_pseudonym_cert(
                subject_pub=pub_ephemeral_key, issuer_cert_bytes=issuer_cert_bytes,
                issuer_priv=self._Entity__Private_Key,
                subject_name=f"VEH_PSEUDO_{random.randint(0, 999999999)}",
                linkage_value=LV)

            aes_PCA_VEH = self.derive_aes_key_from_data(veh_pub)
            encrypt_PC_for_VEH = Cryptico.aes_encrypt(
                aes_PCA_VEH, actual_PC)

            # loading file
            with open(self.filename, "r") as f:
                data: list = json.load(f)
                data.append(
                    {'PC': base64.b64encode(actual_PC).decode(), 'LV': LV, 'PLV1': decrypt_PLV1, 'PLV2': decrypt_PLV2})
            with open(self.filename, "w") as f:
                json.dump(data, f)

            message = {
                "id": json_data["id"],
                "Vehicule_pubkey": base64.b64encode(veh_pub).decode(),
                "PC": base64.b64encode(encrypt_PC_for_VEH).decode()
            }
            message_json = json.dumps(message)
            aes_RA_key = self.derive_aes_key_from_data(
                        self.connected_Entities["RA"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo))
            encrypt_for_RA = Cryptico.aes_encrypt(aes_RA_key, message_json.encode())
            self.send(self.connected_Entities['RA'], encrypt_for_RA)
        else:  # the unknown
            pass
        
    @override
    def forward_and_empty_buffer(self, buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet = buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)

    @override
    def start(self):
        listening_thread = threading.Thread(
            target=self.listen_and_fill_buffer, args=(self.listening_address,))
        listening_thread.start()
        forwarding_thread = threading.Thread(
            target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()
