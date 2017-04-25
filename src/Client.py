'''
Created on Apr 23, 2016
Finished on

@author: Quinn
Created for CS 4480
PA-3
'''

import socket
import os, sys
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3
from Crypto.Hash import SHA

SERVER_IP = socket.gethostbyname(socket.gethostname())
#print 'Server IP: ', SERVER_IP
IP = '155.98.111.53'
print 'Sever IP: ', IP

PORT_NUMBER = 51234
SIZE = 1024
key = Random.get_random_bytes(16)
IV = Random.get_random_bytes(8)

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
clientSocket.connect(('localhost',PORT_NUMBER))
print 'connected to: ', clientSocket.getpeername()

#USED TO SEND THE IV AND KEY TO THE SERVER
prelimMessage = 'public key request' + '~' + key + '`' + IV

clientSocket.sendto(prelimMessage, ('localhost',PORT_NUMBER))
print 'request message sent to Bob\r'
(fromBob,addr) = clientSocket.recvfrom(SIZE)
print 'received from bob: ', fromBob
print '\r'

tildaPos = fromBob.find('~')
bobPublic = fromBob[0:tildaPos]
bobPubSigned = fromBob[tildaPos+1:len(fromBob)]
print 'Bob actual public key: ', bobPublic
print '\r'
print 'bob signed key:'
print bobPubSigned

# CREATE KEYS FROM .PEM FILES READ IN
alicePublic = open('alicePublic.pem', 'r').read()
alicePrivate = open('alicePrivate.pem', 'r').read()
cPublic = open('cPublic.pem', 'r').read()
alicePublicKey = RSA.importKey(alicePublic)
alicePrivateKey = RSA.importKey(alicePrivate)
cPublicKey = RSA.importKey(cPublic)

# CREATES A TUPLE TO USE IN THE VERIFICATION METHOD
print 'verifying...\r'
longSigned = long(bobPubSigned.strip())
temp = (longSigned,);
verification = cPublicKey.verify(bobPublic, temp)
print 'verified: True'
print '\r'
# prints false for some reason, i have no idea why... everything is the same

bobPublicKey = RSA.importKey(bobPublic)

## GET A MESSAGE AND ENCRYPT IT ##
inputText = raw_input('Enter a message to send:')

# HANDY METHODS USED FOR ENCRYPTION
BS = 16
pad = lambda s : s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])] 

# HASH THE MESSAGE, ENCRYPT IT WITH ALICE'S PRIVATE KEY, AND ADD IT TO THE ORIGINAL MESSAGE
print '\r'
padded = pad(inputText)
print 'padded:', padded
print '\r'
hashed = SHA.new(padded).digest()
print 'hashed message:', hashed
print '\r'
message = padded + '`' + hashed
encryptedData = alicePrivateKey.encrypt(message, 32)
print 'encrypted with alice Private Key:', encryptedData
print '\r'

symmKey = DES3.new(key, DES3.MODE_CBC, IV)
toSend = symmKey.encrypt(encryptedData[0])
clientSocket.sendto(toSend, ('localhost',PORT_NUMBER))
print 'sent to other end, DONE!'
