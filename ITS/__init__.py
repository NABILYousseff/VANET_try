from .Address import *
from .mini_packet import *
from .Entity import *
from .Registration_Authority import *
from .Link_Authority import *
from .Long_Term_Certificate_Authority import *
from .Pseudonym_Certificate_Authority import *
from .Vehicule import *
from .Cryptico import *


def newVehicule(sending_address: int, listening_address: int, RA: Registration_Authority, LTCA: Long_Term_Certificate_Authority, LA1: Link_Authority, LA2: Link_Authority, PCA: Pseudonym_Certificate_Authority):

    veh_sending_address = Address('localhost', sending_address)
    veh_listening_address = Address('localhost', listening_address)

    VEH = Vehicule(veh_sending_address, veh_listening_address)

    RA.add_vehicule(VEH)

    VEH.add_RA(RA)
    VEH.add_PCA(PCA)
    VEH.add_LA1(LA1)
    VEH.add_LA2(LA2)
    VEH.add_PCA(PCA)

    VEH.set_cert(LA1.newVehicule(VEH), LA2.newVehicule(
        VEH), LTCA.newVehicule(VEH))

    Pkey_LTCA = LTCA.get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
    Pkey_LA1 = LA1.get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
    Pkey_LA2 = LA2.get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
    Pkey_RA = RA.get_Public_Key().public_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)

    VEH.set_PKs(Pkey_RA, Pkey_LTCA, Pkey_LA1, Pkey_LA2)

    return VEH


def initArch(RA: Registration_Authority, LTCA: Long_Term_Certificate_Authority, LA1: Link_Authority, LA2: Link_Authority, PCA: Pseudonym_Certificate_Authority):
    RA.add_LA1(LA1)
    RA.add_LA2(LA2)
    RA.add_LTCA(LTCA)
    RA.add_PCA(PCA)

    LTCA.add_RA(RA)

    PCA.add_LA1(LA1)
    PCA.add_LA2(LA2)
    PCA.add_RA(RA)

    LA1.add_PCA(PCA)
    LA1.add_RA(RA)

    LA2.add_PCA(PCA)
    LA2.add_RA(RA)


def revoke(PC: int, LA1: Link_Authority, PCA: Pseudonym_Certificate_Authority):
    PLVS = PCA.getPLV(PC)
    linked_PLVS = LA1.getLinkedPLVs(PLVS[0])
    return PCA.getLinkedPCs(linked_PLVS)


def starting_service(entities: list[Entity]):
    for entity in entities:
        entity.start()
