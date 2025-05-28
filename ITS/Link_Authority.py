from .Entity import *
import threading
import json
import os
import base64
import random
from pathlib import Path
from .certs_util import *


class Link_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule = 0

        cert_path = Path(f"ca/{self.__class__.__name__}_{self.id}.cert")
        if not cert_path.exists():
            print(f"[{self.__class__.__name__}] No cert found, generating one...")
            self.generate_own_cert()
        else:
            print(f"[{self.__class__.__name__}] Cert already exists.")
        while True:
            # self.id = random.randint(0, int(5e12))
            self.filename = "LA_"+str(self.id)+".json"
            self.file_path = Path(self.filename)
            if self.file_path.exists() == False:
                with open(self.filename, "w") as f:
                    # entree sous forme de [{'id':id in the content of LA, 'message':m1,'random':random, 'hash':chameleon hash, 'PLVs':[PLV1,PLV2,....]}]
                    file_init = []
                    json.dump(file_init, f)
                break

    def add_RA(self, RA):
        self.connected_Entities["RA"] = RA

    def add_PCA(self, PCA):
        self.connected_Entities["PCA"] = PCA

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

    # def generate_cert_for_vehicle(self, veh, label="LA", certify_bin="/home/youssef/cacio_pepe/vanetza/bin/certify"):
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
        # id_veh = str(random.randint(0, int(5e12)))
        # TODO change this line after finding a cert generator
        # to change with a real cert_content
        # cert = self.generate_cert_for_vehicle(veh)
        my_cert_path = Path(f"ca/{self.__class__.__name__}_{self.id}.cert")
        issuer_cert_bytes = my_cert_path.read_bytes()

        cert_bytes = build_enrollment_cert(
            subject_pub=veh.get_Public_Key(),
            issuer_cert_bytes=issuer_cert_bytes,
            issuer_priv=self._Entity__Private_Key,
            subject_name=f"VEH_{veh.id}"
        )
        encoded = base64.b64encode(cert_bytes).decode()
        # LA_certif = 'LA_cert'+id_veh
        veh_Sk = ec.generate_private_key(
            ec.SECP256R1()).private_numbers().private_value
        m, r = int.from_bytes(os.urandom(32), 'big') % self.p, int.from_bytes(
            os.urandom(32), 'big') % self.p
        H = Cryptico.chameleon_hash(veh_Sk, m, r)
        with open(self.filename, "r") as f:
            data: list = json.load(f)
            # TODO change this line after finding a cert generator
            data.append({'id': encoded, 'message': m, 'random': r, 'hash': H, 'PLVs': [
            ], 'Sk': veh_Sk})  # the la certif can be changed with a certificate content
        with open(self.filename, "w") as f:
            json.dump(data, f)
        return encoded

    def packet_forwarding(self, packet: mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('LA had received message from ', source_entity)
        if source_entity == "RA":
            data = packet.data.decode()
            json_data = json.loads(data)
            veh_pub = base64.b64decode(json_data["Vehicule_pubkey"])
            # veh_id = int.from_bytes(base64.b64decode(json_data["id"]), 'big')
            aes_key = self.derive_aes_key_from_data(
                veh_pub)
            LA_cipher = base64.b64decode(json_data["LA_cipher"])
            LA_cert = self.aes_decrypt(aes_key, LA_cipher)
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
                # TODO change this line after finding a cert generator to handle the comparaison
                if LA_cert.decode() == file_content[record_num]['id']:
                    valid_cert = True
                    aes_PC_LA_key = self.derive_aes_key_from_data(
                        self.connected_Entities["PCA"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))  # not
                    aes_RA_LA_key = self.derive_aes_key_from_data(
                        self.connected_Entities["RA"].get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo))  # not
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
                    encrypted_PLV_for_PCA = self.aes_encrypt(
                        aes_PC_LA_key, str(PLV).encode())

                    message = {
                        "id": json_data["id"],
                        "PLV": base64.b64encode(encrypted_PLV_for_PCA).decode()
                    }
                    message_json = json.dumps(message)
                    encrypt_for_RA = self.aes_encrypt(
                        aes_RA_LA_key, message_json.encode())
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

    def getLinkedPLVs(self, PLV_to_link):
        with open(self.filename, "r") as f:
            file_content: list = json.load(f)
        for record in file_content:
            for PLV in record['PLVs']:
                if PLV == PLV_to_link:
                    return record['PLVs']
        print("no such PLV")
        return None

    def start(self):
        listening_thread = threading.Thread(
            target=self.listen_and_fill_buffer, args=(self.listening_address,))
        listening_thread.start()
        forwarding_thread = threading.Thread(
            target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()
