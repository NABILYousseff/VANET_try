from .Address import *
from .mini_packet import *
from .Entity import *
from .Registration_Authority import *
from .Link_Authority import *
from .Long_Term_Certificate_Authority import *
from .Pseudonym_Certificate_Authority import *
from .Vehicule import *
from .Cryptico import *


def newVehicule(sending_address:int,listening_address:int,RA:Registration_Authority,LTCA:Long_Term_Certificate_Authority,LA1:Link_Authority,LA2:Link_Authority,PCA:Pseudonym_Certificate_Authority):
    
    veh_sending_address = Address('localhost', sending_address)
    veh_listening_address = Address('localhost', listening_address)

    VEH = Vehicule(veh_sending_address, veh_listening_address)

    RA.add_vehicule(VEH)
    

    VEH.add_RA(RA)
    VEH.add_PCA(PCA)
    VEH.add_LA1(LA1)
    VEH.add_LA2(LA2)
    VEH.add_PCA(PCA)
    
    VEH.set_LA_cert(LA1.newVehicule(), LA2.newVehicule(), LTCA.newVehicule())
    
    return VEH

def initArch():
    pass