from .Address import *

class mini_packet:
    def __init__(self, address: Address, data):
        self.address: Address = address
        self.data = data