class Address:
    """
    Class representing an address with an IP and port for network communication.
    This class encapsulates the IP address and port number for communication.
    """
    def __init__(self, ip_address:str, port:int):
        self.ip_address: str = ip_address
        self.Port: int = port