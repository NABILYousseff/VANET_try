from ITS import *
import time
import json
from cryptography.hazmat.primitives import serialization
import base64


if __name__ == '__main__':

    # Address INIT
    ra_sending_address = Address('localhost', 5000)
    ra_listening_address = Address('localhost', 5006)
    la1_sending_address = Address('localhost', 5001)
    la1_listening_address = Address('localhost', 5007)
    la2_sending_address = Address('localhost', 5002)
    la2_listening_address = Address('localhost', 5008)
    LTCA_sending_address = Address('localhost', 5003)
    LTCA_listening_address = Address('localhost', 5009)
    PCA_sending_address = Address('localhost', 5004)
    PCA_listening_address = Address('localhost', 5010)
    veh_sending_address = Address('localhost', 5005)
    veh_listening_address = Address('localhost', 5011)

    # Entities creation
    RA = Registration_Authority(ra_sending_address, ra_listening_address)
    VEH = Vehicule(veh_sending_address, veh_listening_address)
    LTCA = Long_Term_Certificate_Authority(
        LTCA_sending_address, LTCA_listening_address)
    PCA = Pseudonym_Certificate_Authority(
        PCA_sending_address, PCA_listening_address)
    LA1 = Link_Authority(la1_sending_address, la1_listening_address)
    LA2 = Link_Authority(la2_sending_address, la2_listening_address)

    # Recognition (linking entities)
    RA.add_vehicule(VEH)
    RA.add_LA1(LA1)
    RA.add_LA2(LA2)
    RA.add_LTCA(LTCA)
    RA.add_PCA(PCA)

    LTCA.add_RA(RA)
    LTCA.add_vehicule(VEH)

    VEH.add_RA(RA)
    VEH.add_PCA(PCA)
    VEH.add_LA1(LA1)
    VEH.add_LA2(LA2)
    VEH.add_PCA(PCA)

    PCA.add_LA1(LA1)
    PCA.add_LA2(LA2)
    PCA.add_RA(RA)
    PCA.add_vehicule(VEH)

    LA1.add_PCA(PCA)
    LA1.add_RA(RA)
    LA1.add_vehicule(VEH)

    LA2.add_PCA(PCA)
    LA2.add_RA(RA)
    LA2.add_vehicule(VEH)

    # Start services
    RA.start()
    print("__Starting programme__")
    VEH.start()
    LTCA.start()
    PCA.start()
    LA1.start()
    LA2.start()

    time.sleep(4)
    print('start sending')

    public_key_bytes = VEH.get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    aes_key_LTCA = VEH.derive_aes_key(LTCA)
    aes_key_LA1 = VEH.derive_aes_key(LA1)
    aes_key_LA2 = VEH.derive_aes_key(LA2)
    aes_key_RA = VEH.derive_aes_key(RA)

    LA1_encryption = VEH.aes_encrypt(aes_key_LA1, VEH.LA1_certif.encode())
    LA2_encryption = VEH.aes_encrypt(aes_key_LA2, VEH.LA2_certif.encode())
    second_LA1_encryption = VEH.aes_encrypt(aes_key_RA, LA1_encryption)
    second_LA2_encryption = VEH.aes_encrypt(aes_key_RA, LA2_encryption)

    first_encryption = VEH.aes_encrypt(aes_key_LTCA, b"LT_CERT")
    second_encryption = VEH.aes_encrypt(aes_key_RA, first_encryption)

    message = {
        "PubKey": base64.b64encode(public_key_bytes).decode(),
        "CipherLTC": base64.b64encode(second_encryption).decode(),
        "CipherLA1": base64.b64encode(second_LA1_encryption).decode(),
        "CipherLA2": base64.b64encode(second_LA2_encryption).decode()
    }
    message_json = json.dumps(message)
    VEH.send(RA,  message_json.encode())
    # VEH.send(PCA,'hello'.encode('utf-8'))
    # VEH.send(RA,'hello'.encode('utf-8'))
    # VEH.send(RA,'hello'.encode('utf-8'))
