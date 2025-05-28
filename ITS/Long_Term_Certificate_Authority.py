from enum import verify
from .Entity import *
import threading
import json
import base64
from pathlib import Path
from cryptography.x509 import load_pem_x509_certificate

from .certs_util import *


class Long_Term_Certificate_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule = 0

        cert_path = Path(f"ca/{self.__class__.__name__}_{self.id}.cert")
        if not cert_path.exists():
            print(f"[{self.__class__.__name__}] No cert found, generating one...")
            self.generate_own_cert()
        else:
            print(f"[{self.__class__.__name__}] Cert already exists.")

        # self.id = random.randint(0, int(5e12))
        self.filename = "LTCA_"+str(self.id)+".json"
        self.filename = "LTCA.json"
        self.file_path = Path(self.filename)
        if self.file_path.exists() == False:
            with open(self.filename, "w") as f:
                # entree sous forme de [{'id':id in the content of LTC, 'LTC':Long term certif}]
                file_init = []
                json.dump(file_init, f)

    def add_RA(self, RA):
        self.connected_Entities["RA"] = RA

    # def export_keys_for_certify(self, subject_entity, certs_dir: Path):
    #     certs_dir.mkdir(parents=True, exist_ok=True)

    #     subject_pub_path = certs_dir / \
    #         f"{subject_entity.__class__.__name__}_{subject_entity.id}_priv.key"
    #     issuer_priv_path = certs_dir / \
    #         f"{self.__class__.__name__}_{self.id}_priv.key"
    #     issuer_cert_path = certs_dir / \
    #         f"{self.__class__.__name__}_{self.id}.cert"

    # # Export subject public key
    #     # pub_key = subject_entity.get_Public_Key()
    #     # pub_numbers = pub_key.public_numbers()
    #     # x_bytes = pub_numbers.x.to_bytes(32, 'big')
    #     # y_bytes = pub_numbers.y.to_bytes(32, 'big')

    #     # ecc_point = EccPoint({
    #     #     'algorithm': 'ecdsa_nistp256',  # Assuming '0' means ecdsa_nistp256 in ETSI
    #     #     'field_size': 32,
    #     #     'type': 'uncompressed',
    #     #     'x': x_bytes,
    #     #     'y': y_bytes
    #     # })
    #     # pub_bytes = pub_key.public_bytes(
    #     #     encoding=serialization.Encoding.X962,  # uncompressed EC point
    #     #     format=serialization.PublicFormat.UncompressedPoint
    #     # )
    #     # asn1_pub = PublicKeyInfo({
    #     #     'algorithm': {
    #     #         'algorithm': 'ec',
    #     #         'parameters': {'named': 'secp256r1'}
    #     #     },
    #     #     'public_key': pub_bytes
    #     # })
    #     priv_num_subj = subject_entity._Entity__Private_Key.private_numbers().private_value
    #     # priv_bytes = priv_num.to_bytes(32, 'big')

    #     priv_key_subj = ECPrivateKey({
    #         'version': 'ecPrivkeyVer1',
    #         'private_key': priv_num_subj,
    #         'parameters': {'named': 'secp256r1'}
    #     })

# # Wrap it in PrivateKeyInfo
    #     wrapped_subj = PrivateKeyInfo({
    #         'version': 0,
    #         'private_key_algorithm': {
    #             'algorithm': 'ec',
    #             'parameters': {'named': 'secp256r1'}
    #         },
    #         'private_key': priv_key_subj
    #     })

    #     with open(subject_pub_path, "wb") as f:
    #         f.write(wrapped_subj.dump())

    # # Export issuer private key
    #     priv_num = self._Entity__Private_Key.private_numbers().private_value
    #     # priv_bytes = priv_num.to_bytes(32, 'big')

    #     priv_key = ECPrivateKey({
    #         'version': 'ecPrivkeyVer1',
    #         'private_key': priv_num,
    #         'parameters': {'named': 'secp256r1'}
    #     })

# # Wrap it in PrivateKeyInfo
    #     wrapped = PrivateKeyInfo({
    #         'version': 0,
    #         'private_key_algorithm': {
    #             'algorithm': 'ec',
    #             'parameters': {'named': 'secp256r1'}
    #         },
    #         'private_key': priv_key
    #     })

    #     with open(issuer_priv_path, "wb") as f:
    #         f.write(wrapped.dump())

    #     return subject_pub_path, issuer_priv_path, issuer_cert_path

    # def generate_cert_for_vehicle(self, veh, label="LTCA", certify_bin="/home/youssef/cacio_pepe/vanetza/bin/certify"):
    #     certs_dir = Path("certs")
    #     certs_dir.mkdir(exist_ok=True)

    # # Ensure issuer has a root cert
    #     issuer_cert_path = certs_dir / \
    #         f"{self.__class__.__name__}_{self.id}.cert"
    #     if not issuer_cert_path.exists():
    #         pub, priv, _ = self.export_keys_for_certify(self, certs_dir)
    #         subprocess.run([
    #             certify_bin, "generate-root",
    #             "--subject-key", str(priv),
    #             str(issuer_cert_path)
    #         ], check=True)

    # # Generate the cert for the VEH
    #     cert_path = certs_dir / \
    #         f"{veh.__class__.__name__}_{veh.id}_{label}.cert"
    #     pub, priv, _ = self.export_keys_for_certify(veh, certs_dir)
    #     subprocess.run([
    #         certify_bin, "generate-aa",
    #         "--sign-key", str(priv),
    #         "--sign-cert", str(issuer_cert_path),
    #         "--subject-key", str(pub),
    #         str(cert_path)
    #     ], check=True)
    #     cert_bytes = b""

    #     with open(cert_path, "rb") as f:
    #         cert_bytes += f.read()
    #     return cert_bytes

    def generate_own_cert(self):
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
    # id_veh = str(random.randint(0, int(5e12)))
    # # TODO change this line after finding a cert generator
    # # to change with a real cert_content
    # cert = self.generate_cert_for_vehicle(veh)
    # LT_certif = id_veh
    # with open(self.filename, "r") as f:
    #     data: list = json.load(f)

    #     # TODO change this line after finding a cert generator
    #     # data.append({'id': LT_certif, 'LTC': LT_certif})
    #     data.append(
    #         {'id': id_veh, 'LT_cert': base64.b64encode(cert).decode()})
    # with open(self.filename, "w") as f:
    #     json.dump(data, f)
    # return base64.b64encode(cert).decode()

    def packet_processing(self, packet: mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('LTCA received a message from ', source_entity)
        if source_entity == "RA":
            data = packet.data.decode()
            json_data = json.loads(data)
            ID = json_data["id"]
            vehicule_pubkey = base64.b64decode(
                json_data["Vehicule_pubkey"])
            print(vehicule_pubkey)
            LTC = base64.b64decode(json_data["CipherLTC"])
            print(LTC)
            aes_key = self.derive_aes_key_from_data(vehicule_pubkey)
            LTC_decrypted = self.aes_decrypt(aes_key, LTC)
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
                # ID = file_content['id']
            # for record in file_content:
            # TODO change this line after finding a cert generator to handle the comparaison

            found = any(r.get("subject_name") ==
                        subject_name for r in file_content)

            if found:
                print(f"VALID CERT ISSUED TO : {subject_name}")
                validity = "valid"
            else:
                print("CERT SUBJECT NOT IN DATABASE -- UNKNOWN")
                validity = "unknown"

            # if self.verify_cert_signature(LTC_decrypted, self.get_Public_Key().public_bytes(
            #         encoding=serialization.Encoding.PEM,
            #         format=serialization.PublicFormat.SubjectPublicKeyInfo)):
            #     print("✔️ Valid cert signature!")
            #     LTC_validity = "valid"
            # else:
            #     print("❌ Invalid cert signature!")
            #     return  # or handle rejection
                # if record['id'] == LTC_decrypted:
                #     LTC_validity = "valid"
            message = {
                "id": ID,
                "validity": validity
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
