##################################################
# this code implements a basic blockchain 
# 
# author: mrbacco 2019-2020
# 
# this is the file that creates the class
# that is gonna be used for the creation
# of each block       
##################################################

import hashlib
import json
import datetime as date

class Block(): # generation of the class called Block, every block will be an instance of this class
    def __init__(self, index, timestamp, data, prev_hash = ''):
        self.index = index
        self.timestamp = str(date.datetime.now())
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.hash_calc() #defining a function to calculate the hash see below

    #function to create the hash from the parameters of the blocks
    def hash_calc(self): #self means that the function contains nothing
        hash_block=json.dumps( #using the method jason.dumps that allows to serialize the objects in a json format
            { # this is the dictionary that is gonna be used to define the parameters of the block
                "index":self.index, 
                "timestamp": self.timestamp, 
                "data":self.data, 
                "prev_hash": self.prev_hash
            },
        ).encode() #needs to be encoded to be passed to the hash function
        return hashlib.sha3_256(hash_block).hexdigest() # creation of the hash from the block parameters as defined in the class

    def printhashes(self):
        print("previous hash :", self.prev_hash)
        print("current hash :", self.hash)

    def __str__(self): # returning the string representation of the objects so that when I print in the console I can read something
        string="index: " +str(self.index) +"\n"
        string+="timestamp; " +str(self.timestamp) +"\n"
        string+="data: " +str(self.data) +"\n"
        string+="prev_hash: " +str(self.prev_hash) +"\n"
        string+="hash: " +str(self.hash) +"\n"
        return string

new_block = Block(1, "01/01/1970", 100)
# print(str(new_block))
