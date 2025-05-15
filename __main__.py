from ITS import *
import time
import json
from cryptography.hazmat.primitives import serialization
import base64


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
    initArch(RA,LTCA,LA1,LA2,PCA)

#-------------------------------- Main Program ---------------------------------------------------------
    print("-------------__Starting programme__-------------\n")
    
    # Vehicule creation
    VEH = newVehicule(50005,50011,RA,LTCA,LA1,LA2,PCA)
    VEH2 = newVehicule(40007,40400,RA,LTCA,LA1,LA2,PCA)
   
    # Starting services
    print("Starting services...\n")
    RA.start()
    LTCA.start()
    PCA.start()
    LA1.start()
    LA2.start()
    VEH.start()
    VEH2.start()
    print("Services Started!!\n")

    time.sleep(4) # waiting_for_all_autorities_to_be_ready!!
    print('start sending')

    VEH.send_request()
    time.sleep(120)
    VEH2.send_request()