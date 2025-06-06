from ITS import *
import time
from ITS.certs_util import *
from pprint import pprint
if __name__ == '__main__':

    # ---------------------------------- Address INIT ------------------------------------------------------
    ra_sending_address = Address('localhost', 50000)
    ra_listening_address = Address('localhost', 50006)
    la1_sending_address = Address('localhost', 50001)
    la1_listening_address = Address('localhost', 50007)
    la2_sending_address = Address('localhost', 50002)
    la2_listening_address = Address('localhost', 50008)
    LTCA_sending_address = Address('localhost', 50003)
    LTCA_listening_address = Address('localhost', 50009)
    PCA_sending_address = Address('localhost', 50004)
    PCA_listening_address = Address('localhost', 50010)
# ------------------------------- Entities creation  ---------------------------------------------------
    RA = Registration_Authority(ra_sending_address, ra_listening_address)
    LTCA = Long_Term_Certificate_Authority(
        LTCA_sending_address, LTCA_listening_address)
    PCA = Pseudonym_Certificate_Authority(
        PCA_sending_address, PCA_listening_address)
    LA1 = Link_Authority(la1_sending_address, la1_listening_address)
    LA2 = Link_Authority(la2_sending_address, la2_listening_address)
# -------------------------- Recognition (linking entities) --------------------------------------------
    initArch(RA, LTCA, LA1, LA2, PCA)
# --------------------------       Vehicule creation        --------------------------------------------
    VEH = newVehicule(50005, 50011, RA, LTCA, LA1, LA2, PCA)
    VEH2 = newVehicule(40007, 40400, RA, LTCA, LA1, LA2, PCA)


# -------------------------------- Main Program ---------------------------------------------------------
    print("-------------__Starting programme__-------------\n")

    # Starting services
    print("Starting services...\n")
    starting_service([RA, LTCA, PCA, LA1, LA2, VEH, VEH2])

    time.sleep(4)  # waiting_for_all_autorities_to_be_ready!!
    print("Services Started!!\n")

    #  *********** Sending request *****************
    VEH.send_request()
    # time.sleep(30)

    print("********* new reqquest *********")
    VEH2.send_request()

    # time.sleep(30)
    print("********* new reqquest *********")
    VEH.send_request()
    time.sleep(30)

    # *********  Malicious_behaviour_simulation ***********
    with open(VEH.filename, "r") as f:
        data: list = json.load(f)
        # VEH will use one of its PC to start a malicious behaviour
        PC_mali = data['PCs'][0]

    # *********** all VEH PCs revokated  ******************
    PC = base64.b64decode(PC_mali)
    print(PC)
    pseudonym_cert = spec.decode('CertificateAlias', PC)

    pprint(pseudonym_cert)
    LV = int.from_bytes(pseudonym_cert['tbs']['ld'])
    print(LV)

    print(
        f"\033[1;31mPCA & LA1 collaboration will revoke the following certificate: {revoke(LV, LA1, PCA)}, after a malicious behaviour stated by {PC_mali}\033[0m")
