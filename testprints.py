import bencodepy
from socket import *
from bitarray import bitarray
import requests     # http requests
import hashlib      # SHA1 hashing for info hash
import binascii     # use unhexlify to convert ascii hex sequences into binary
import random       # create the local peer id
import math         # you'll need to use the ceil function in a few places
import sys
import re
from string import ascii_letters, digits
import urllib
import struct

flag = b'!IB'
flag = bencodepy.encode(flag)
fun = 94
ppp = fun.to_bytes(6, byteorder='big')
print("pee (00136 in bytes) ", ppp)
test2 = bencodepy.encode(fun)
print("new bencoded string", test2)

helper = struct.pack(">I", 13)
#helper = '\x00\x00\x01\x03\x06'
print(helper)
help2 = struct.pack(">I", 6)
print(help2)
total = helper + help2
print(total)
help3 = 13
help4 = help3.to_bytes(4, byteorder='big')
print(help4)
help5 = 6
help6 = help5.to_bytes(1, byteorder='big')
print(help6)
help7 =  help4 + help6
print(help7)
help8 = 16384
help9 = help8.to_bytes(4, byteorder='big')
print(help9)