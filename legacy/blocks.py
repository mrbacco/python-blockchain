###################################################
# this code implements a basic blockchain program #
# creaton of blocks                               #
# author: and_bac 2019                            #
###################################################

import datetime as date
import hashlib
from random import randint

class Block(): # generation of the class called Block, every block will be an instance of this class
    def __init__(self, nonce, timestamp, data, prev_hash = ""):
        self.nonce = nonce
        self.timestamp = str(date.datetime.now())
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.hash_calc()
    
    @staticmethod
    def big_ben_block(): # this generates the genesis block
        return Block("0", date.datetime.now(), "0", "")

    def hash_calc(self): # function to create the hash of the new block
        hash_block = (str(self.prev_hash) +
                      str(self.data) +
                      str(self.timestamp) +
                      str(self.nonce)
                      )
        h = hashlib.sha3_256(hash_block.encode()).hexdigest().encode()
        return h
