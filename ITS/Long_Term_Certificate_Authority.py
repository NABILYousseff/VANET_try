from enum import verify
from .Entity import *
import threading
import json
import base64
from pathlib import Path
from cryptography.x509 import load_pem_x509_certificate

from .certs_util import *


class Long_Term_Certificate_Authority (Entity):
    """Long Term Certificate Authority (LTCA) class handles the management of long-term certificates."""
    def __init__(self, sending_address, listening_address):
        """
        Initialize the Long Term Certificate Authority (LTCA) with the given addresses.
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

        self.filename = "LTCA_"+str(self.id)+".json"
        self.filename = "LTCA.json"
        self.file_path = Path(self.filename)
        if self.file_path.exists() == False:
            with open(self.filename, "w") as f:
                # entree sous forme de [{'id':id in the content of LTC, 'LTC':Long term certif}]
                file_init = []
                json.dump(file_init, f)

    def add_RA(self, RA: Entity):
        """Add the Registration Authority (RA) to the connected entities.
        param
        -----
            RA : The Registration Authority to add.
        """
        self.connected_Entities["RA"] = RA

    def generate_own_cert(self):
        """
        Generate a new certificate for the Long Term Certificate Authority.
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
            authority_type="authorization-authority"
        )

        with open(f"ca/{self.__class__.__name__}_{self.id}.cert", "wb") as f:
            f.write(cert)

    def newVehicule(self, veh: Entity):
        """
        Generate a new long-term certificate for a vehicle.
        """
        my_cert_path = Path(f"ca/{self.__class__.__name__}_{self.id}.cert")
        issuer_cert_bytes = my_cert_path.read_bytes()
        subject_name = f"VEH_{veh.id}"

        cert_bytes = build_enrollment_cert(
            subject_pub=veh.get_Public_Key(),
            issuer_cert_bytes=issuer_cert_bytes,
            issuer_priv=self._Entity__Private_Key,
            subject_name=subject_name
        )

        encoded = base64.b64encode(cert_bytes).decode()
        id_veh = str(random.randint(0, int(5e12)))

        with open(self.filename, "r") as f:
            data: list = json.load(f)
            data.append(
                {'id': id_veh, 'subject_name': subject_name, 'LT_cert': encoded})

        with open(self.filename, "w") as f:
            json.dump(data, f)

        return encoded

    @override
    def packet_processing(self, packet: mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('LTCA received a message from ', source_entity)
        
        if source_entity == "RA":
            aes_key = self.derive_aes_key_from_data(self.connected_Entities[source_entity].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
            decrypt_data = Cryptico.aes_decrypt(aes_key, packet.data)
            data = decrypt_data.decode()
            json_data = json.loads(data)
            ID = json_data["id"]
            vehicule_pubkey = base64.b64decode(
                json_data["Vehicule_pubkey"])
            print(vehicule_pubkey)
            LTC = base64.b64decode(json_data["CipherLTC"])
            print(LTC)
            aes_key = self.derive_aes_key_from_data(vehicule_pubkey)
            LTC_decrypted = Cryptico.aes_decrypt(aes_key, LTC)
            LTC_correct_form = base64.b64decode(LTC_decrypted)
            print("Checking ...", LTC_correct_form)
            print("-- LTC DECRYPTED --")
            LTC_pubkey = self.get_Public_Key()
            valid_signature = verify_cert_signature(
                LTC_correct_form, LTC_pubkey)
            if not valid_signature:
                print("Invalid Signature")
                return

            try:
                ltc_dict = spec.decode("CertificateAlias", LTC_correct_form)
                subject_name = ltc_dict["tbs"]["subjectInfo"]["subjectName"]
            except Exception as e:
                print("Failed to decode the cert; Reason --> ", e)
                return

            with open(self.filename, "r") as f:
                file_content = json.load(f)

            found = any(r.get("subject_name") ==
                        subject_name for r in file_content)

            if found:
                print(f"VALID CERT ISSUED TO : {subject_name}")
                validity = "valid"
            else:
                print("CERT SUBJECT NOT IN DATABASE -- UNKNOWN")
                validity = "unknown"

            message = {
                "id": ID,
                "validity": validity
            }
            message_json = json.dumps(message)
            aes_RA_RA_key = self.derive_aes_key_from_data(
                        self.connected_Entities["RA"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo))
            encrypt_for_RA = Cryptico.aes_encrypt(aes_RA_RA_key, message_json.encode())
            self.send(self.connected_Entities['RA'], encrypt_for_RA)

        else:  # the source is unknown
            pass

    @override
    def forward_and_empty_buffer(self, buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet = buffer[0]
                self.packet_processing(packet)
                buffer.pop(0)

    @override
    def start(self):
        listening_thread = threading.Thread(
            target=self.listen_and_fill_buffer, args=(self.listening_address,))
        listening_thread.start()
        forwarding_thread = threading.Thread(
            target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()
