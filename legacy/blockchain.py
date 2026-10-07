###################################################
# this code implements a basic blockchain program #
# creaton of chain                                #
# author: and_bac 2019                            #
###################################################

from blocks import Block
import datetime as date

add_blocks = int(input("please enter the number of blocks to create the blockhain: "))

bac_chain = [Block.big_ben_block()]

print("The genesis block or block 0 is created with the following Hash and timestamp: " % bac_chain[0].hash, bac_chain[0].timestamp)

for i in range(1, add_blocks):
    bac_chain.append(Block(bac_chain[i-1].hash,"Block number %d" % i, date.datetime.now()))
    print("Block #%d created" % i)
    print("Hash: %s" % bac_chain[-1].hash)
    print("timestamp: %s" % bac_chain[-1].timestamp +"\n")
