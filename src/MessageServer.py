'''
Created on Apr 23, 2016
Finished on

@author: Quinn
Created for CS 4480
PA-3
'''
import socket
import os, sys
#import subprocess
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3
from Crypto.Hash import SHA

PORT_NUMBER = 51234
SIZE = 1024
flag = False

hostName = socket.gethostbyname(socket.gethostname())
print 'hostName: ', hostName

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print 'got a socket: ', serverSocket.fileno()
serverSocket.bind(('localhost',PORT_NUMBER))
print 'bound to: ', serverSocket.getsockname()

(req,addr) = serverSocket.recvfrom(SIZE)

tildaPos = req.find('~')
barPos = req.find('`')
requestStr = req[0:tildaPos]
key = req[tildaPos+1:barPos]
IV = req[barPos+1:len(req)]

print 'request from other end: ', requestStr
if requestStr == 'public key request':
    flag = True

bobPublic = open('bobPublic.pem', 'r').read()
bobPrivate = open('bobPrivate.pem', 'r').read()
cPrivate = open('cPrivate.pem', 'r').read()
alicePublic = open('alicePublic.pem', 'r').read()
alicePrivate = open('alicePrivate.pem','r').read()

bobPrivateKey = RSA.importKey(bobPrivate)
bobPublicKey = RSA.importKey(bobPublic)
cPrivateKey = RSA.importKey(cPrivate)
alicePublicKey = RSA.importKey(alicePublic)
alicePrivateKey = RSA.importKey(alicePrivate)

if flag: 
    
    # ENCODE THE PUBLIC KEY WE HAVE WITH C PUBLIC
    bobPubSigned = cPrivateKey.sign(bobPublic, 16)
    toSend= bobPublic + '~' + str(bobPubSigned[0]).strip()
    serverSocket.sendto(toSend, addr)
    print 'sent Bob signed public key to other side'
    print '\r'
    
    (message,addr) = serverSocket.recvfrom(SIZE)   
    print 'got message: ', message
    print '\r'
    
    # DECRYPT MESSAGE USING SYMMETRIC KEY
    symmKey = DES3.new(key, DES3.MODE_CBC, IV)
    received = symmKey.decrypt(message)
    print 'after 1st stage decryption:', received
    print '\r'
    
    # DECRYPT WITH ALICE'S PUBLIC KEY
    temp = (received,)
    receivedDecrypted = alicePrivateKey.decrypt(temp)
    #receivedDecrypted = alicePublicKey._decrypt(temp)
    # only works with alice's private key, not with her public key...    
    print 'after 2nd stage decryption:', receivedDecrypted
    print '\r'
    
    aposPos = receivedDecrypted.find('`')
    paddedMessage = receivedDecrypted[0:aposPos]
    hashedMessage = receivedDecrypted[aposPos+1:len(receivedDecrypted)]
    
    BS = 16
    unpad = lambda s : s[:-ord(s[len(s)-1:])] 
    
    # VERIFY THE MESSAGE BY REHASHING THE PADDED ONE
    toVerify = SHA.new(paddedMessage).digest()
    verified = (toVerify == hashedMessage)
    print 'verified message integrity:', verified
    print '\r'
    
    # PRINT THE MESSAGE WE GOT FROM THE OTHER SIDE
    actualMessage = unpad(paddedMessage)
    print 'Message sent from the other side:'
    print actualMessage
    
inputText =  raw_input('Enter Y for statistics, N to skip: ')

if inputText.capitalize() == 'Y':
    print 'number of Keys in file: 5'
    print 'SHA1 used for Digest'
    print 'DES3 used for Symmetric Key encryption'
    print 'RSA used for message encryption and integrity'
    print '\r'
    print '1st Stage Decryption: Decryption from the symmetric key encrypted message with our own' 
    print 'identical symmetric key'
    print '\r'
    print '2nd Stage Decryption: Involves re-hashing the padded message and checking integrity of the' 
    print 'padded message as well as unpadding the message' 
    