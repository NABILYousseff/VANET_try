from abc import abstractmethod
import threading
from typing import override
from cryptography.hazmat.primitives.asymmetric import ec
import socket
import time

class Address:
    def __init__(self, ip_address, Port):
        self.ip_address:str = ip_address
        self.Port:int = Port

class mini_packet:
    def __init__(self, address: Address, data):
        self.address:Address = address
        self.data = data

class Entity:

    def __init__(self, sending_address: Address, listening_address: Address):
        self.__Private_Key=ec.generate_private_key(ec.SECP256R1())
        self.__Public_Key=self.__Private_Key.public_key()
        self.sending_address=sending_address
        self.listening_address=listening_address
        self.connected_Entities: dict[str,Entity]={}
        self.buffer:list[mini_packet]=[]

    def send(self, destination: "Entity",binary_msg: bin):
        while (True):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.sending_address.ip_address,self.sending_address.Port))
                s.connect((destination.listening_address.ip_address, destination.listening_address.Port))
                s.sendall(binary_msg)
                #print("data is sent from {} to {}".format(self.sending_address.Port,destination.listening_address.Port))       #Logs
                s.close()
                break
            except:
                pass
    
    # this fnct maybe will not be in use 
    def listen(self, address: Address):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address.ip_address, address.Port))
            s.listen(100)
            conn, addr = s.accept()
            with conn:
                data = conn.recv(4096)
                return addr,data
    
    def listen_and_fill_buffer(self,address: Address):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address.ip_address, address.Port))
            while True:
                s.listen(100)
                conn, addr = s.accept()
                source_address = Address(None,None)
                source_address.ip_address,source_address.Port=addr
                with conn:
                    data = conn.recv(4096)
                    packet = mini_packet(None,None)
                    packet.address,packet.data=source_address,data
                    self.buffer.append(packet)
    
    def get_Public_Key(self):
        return self.__Public_Key

    def get_Exchanged_Key(self,entity:"Entity"):
        return self.__Private_Key.exchange(ec.ECDH(), entity.get_Public_Key())

    #To see later
    def encrypt_message():
        pass
    
    #To see later
    def decrypt_received_msg(data,addr):
        pass
    
    def get_msg_Entity_source(self,address:Address):
        #On traite notre cas ou juste les port sont differents
        for name,entity in self.connected_Entities.items():
            if address.Port == entity.sending_address.Port:
                return name
        return None
    
    @abstractmethod
    def packet_forwarding(self):
        pass
    
    @abstractmethod
    def forward_and_empty_buffer(self):
        pass
    
    @abstractmethod
    def start(self):
        pass
    # A ne pas décommenter pour le moment
    """
    def send_request(address:Address, binary_msg):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((address.ip_address, address.Port))
            s.sendall(binary_msg)
            return 1
    
    def listen_for_response(address:Address):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address.ip_address, address.Port))
            s.listen() #nb de conx
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024)
            s.close()
            return data
        
    def send_and_listen(self,address:Address, binary_msg):
        self.send_request(address, binary_msg)
        time.sleep(1)
        return  self.listen_for_response(address)
    """


class  Registration_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule=0
        self.linkage_cert=[] # it will be used to verify that both LC1 and LC2 are created

    def add_LA1(self, LA):
        self.connected_Entities["LA1"]=LA

    def add_LA2(self, LA):
        self.connected_Entities["LA2"]=LA

    def add_PCA(self, PCA):
        self.connected_Entities["PCA"]=PCA

    def add_LTCA(self, LTCA):
        self.connected_Entities["LTCA"]=LTCA

    def add_vehicule(self, VEH):
        self.connected_vehicule+=1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)]=VEH

    def packet_forwarding(self,packet:mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('RA received a message from ', source_entity)
        time.sleep(3)
        if source_entity == None:
            pass    #The source of the packet is not known
        elif source_entity == "LA1":
            pass # implement a fonction waiting LA2 then sending both lc to PCA
        elif source_entity == "LA2":
            pass # implement a fonction waiting LA1 then sending both lc to PCA
        elif source_entity == "LTCA":
            print('Sending Linkage certif to LA1 and LA2..')
            #verfying if response is true or false
            self.send(self.connected_Entities['LA1'],packet.data)
            self.send(self.connected_Entities['LA2'],packet.data)
        elif source_entity == "PCA":
            print('Sending PCA to VEH')
            self.send(VEH,packet.data)
        else:   #the entity is a vehicule implement then a fonction to send LTC in data to LTCA
            #processing...
            print('Sending LTC to LTCA')
            self.send(self.connected_Entities['LTCA'],packet.data)


    def forward_and_empty_buffer(self,buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet=buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)


    def start(self):
        ra_listening_thread = threading.Thread(target=self.listen_and_fill_buffer, args=(self.listening_address,))
        ra_listening_thread.start()
        ra_forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        ra_forwarding_thread.start()


class Link_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule=0

    def add_RA(self, RA):
        self.connected_Entities["RA"]=RA

    def add_PCA(self, PCA):
        self.connected_Entities["PCA"]=PCA

    def add_vehicule(self, VEH):
        self.connected_vehicule+=1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)]=VEH

    def packet_forwarding(self,packet:mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('LA had received message from ', source_entity)
        if source_entity == "RA":
            #processing
            self.send(self.connected_Entities['RA'],packet.data)
        else:   #The source of the packet is not known
            pass
    
    def forward_and_empty_buffer(self,buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet=buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)


    def start(self):
        listening_thread = threading.Thread(target=self.listen_and_fill_buffer, args=(self.listening_address,))
        listening_thread.start()
        forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()


class Pseudonym_Certificate_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule=0
    
    def add_LA1(self, LA):
        self.connected_Entities["LA1"]=LA

    def add_LA2(self, LA):
        self.connected_Entities["LA2"]=LA

    def add_RA(self, RA):
        self.connected_Entities["RA"]=RA
    
    def add_vehicule(self, VEH):
        self.connected_vehicule+=1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)]=VEH


    def packet_forwarding(self,packet:mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print ('PCA had received a message from ',source_entity)
        if source_entity == "RA":
            self.send(self.connected_Entities['RA'],packet.data)
        else:   #the unknown
            pass
    
    def forward_and_empty_buffer(self,buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet=buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)


    def start(self):
        listening_thread = threading.Thread(target=self.listen_and_fill_buffer, args=(self.listening_address,))
        listening_thread.start()
        forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()





class Long_Term_Certificate_Authority (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
        self.connected_vehicule=0

    def add_RA(self, RA):
        self.connected_Entities["RA"]=RA
    
    def add_vehicule(self, VEH):
        self.connected_vehicule+=1
        self.connected_Entities["VEH_"+str(self.connected_vehicule)]=VEH


    def packet_forwarding(self,packet:mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        print('LTCA received a message from ',source_entity)
        if source_entity == "RA":
            self.send(self.connected_Entities['RA'],packet.data)
        else:   #the source is unknown
            pass
    
    def forward_and_empty_buffer(self,buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet=buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)


    def start(self):
        listening_thread = threading.Thread(target=self.listen_and_fill_buffer, args=(self.listening_address,))
        listening_thread.start()
        forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        forwarding_thread.start()




class Vehicule (Entity):
    def __init__(self, sending_address, listening_address):
        super().__init__(sending_address, listening_address)
    
    def add_LA1(self, LA):
        self.connected_Entities["LA1"]=LA

    def add_LA2(self, LA):
        self.connected_Entities["LA2"]=LA

    def add_PCA(self, PCA):
        self.connected_Entities["PCA"]=PCA

    def add_LTCA(self, LTCA):
        self.connected_Entities["LTCA"]=LTCA

    def add_RA(self, RA):
        self.connected_Entities["RA"]=RA

    def packet_forwarding(self,packet:mini_packet):
        source_entity = self.get_msg_Entity_source(packet.address)
        if source_entity == "RA":
            pass
        else:
            pass    #The source of the packet is not unknown
    
    def forward_and_empty_buffer(self,buffer: list[mini_packet]):
        while True:
            if len(buffer) != 0:
                packet=buffer[0]
                self.packet_forwarding(packet)
                buffer.pop(0)


    def start(self):
        veh_listening_thread = threading.Thread(target=self.listen_and_fill_buffer, args=(self.listening_address,))
        veh_listening_thread.start()
        
        #forwarding_thread = threading.Thread(target=self.forward_and_empty_buffer, args=(self.buffer,))
        #forwarding_thread.start()


if __name__ == '__main__':

    # Address INIT
    ra_sending_address   = Address('localhost', 5000)
    ra_listening_address = Address('localhost', 5006)
    la1_sending_address  = Address('localhost', 5001)
    la1_listening_address = Address('localhost', 5007)
    la2_sending_address  = Address('localhost', 5002)
    la2_listening_address = Address('localhost', 5008)
    LTCA_sending_address = Address('localhost', 5003)
    LTCA_listening_address = Address('localhost', 5009)
    PCA_sending_address  = Address('localhost', 5004)
    PCA_listening_address = Address('localhost', 5010)
    veh_sending_address  = Address('localhost', 5005)
    veh_listening_address = Address('localhost', 5011)

    # Entities creation
    RA = Registration_Authority(ra_sending_address, ra_listening_address)
    VEH = Vehicule(veh_sending_address, veh_listening_address)
    LTCA = Long_Term_Certificate_Authority(LTCA_sending_address, LTCA_listening_address)
    PCA = Pseudonym_Certificate_Authority(PCA_sending_address, PCA_listening_address)
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

    PCA.add_LA1(RA)
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
    print("1")
    VEH.start()
    LTCA.start()
    PCA.start()
    LA1.start()
    LA2.start()

    time.sleep(4)
    print('start sending')
    VEH.send(RA,'hello'.encode('utf-8'))
    #VEH.send(PCA,'hello'.encode('utf-8'))
    #VEH.send(RA,'hello'.encode('utf-8'))
    #VEH.send(RA,'hello'.encode('utf-8'))