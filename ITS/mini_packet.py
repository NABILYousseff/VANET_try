from .Address import *

class mini_packet:
    """
    A class representing a mini packet for data transmission.
    """
    def __init__(self, address: Address, data):
        self.address: Address = address
        self.data = data