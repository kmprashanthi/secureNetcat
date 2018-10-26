from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys
import socket
import os

def read_chunks(fileObj, chunkSize=1024):
    # file is getting chunked in sizes of 1024
    while True:
        data = fileObj.buffer.read(chunkSize)
        if not data:
            break
        yield data

def write_chunks(fileObj,plaintext):
    # plaintext is written in STDOUT
    fileObj.buffer.write(plaintext) 

def encrypt_data(data, key, header, salt):
    # encryption occurs here
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data) 
    message = salt + cipher.nonce + header + tag + ciphertext # the fields are appended to be sent as a single message
    return message

def decrypt_data(message):
    # decryption of data takes place here
    try:
        # extracting data based on field lengths 
        salt = message[:8]
        nonce = message[8:24]
        header = message[24:30]
        tag = message[30:46]
        ciphertext = message[46:]

        keyPos = sys.argv.index('--key')+1
        keyPlain = sys.argv[keyPos]
        key = PBKDF2(keyPlain, salt,32)
                   
        cipher = AES.new (key, AES.MODE_GCM, nonce)
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    # handling integrity issues
    except :
        plaintext=b'Integrity Check Failed !!'
    return plaintext

# incase of listening port, a server is invoked
if '-l' in sys.argv: 
    #setting up ports & server
    portServer = int(sys.argv[-1]) 
    host_name = socket.gethostname()
    host = socket.gethostbyname(host_name)

    #socket connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, portServer))
        s.listen()
        connection, address = s.accept()
        fileObj = sys.stdout
        with connection:
            while True:
                message = connection.recv(1024) #receive the data from client
                if not message:
                    break
                plaintext = decrypt_data(message)
                if plaintext == b'Integrity Check Failed !!':  #check if any chunk of the message had integrity issue while decrypting
                    fileObj.buffer.write(b'Integrity check failed')
                    break
                write_chunks(fileObj, plaintext)

#incase of client being called
else :

    #getting port & host
    portClient = int(sys.argv[-1])
    if sys.argv[-2] != '-l' or sys.argv[-4] != '--key':
        host = sys.argv[-2]

    # getting key from arguments
    keyPos = sys.argv.index('--key')+1
    keyPlain = sys.argv[keyPos]
    salt = os.urandom(8)   # creating the salt value dynamically and sending it across the connection
    header = b'header'
    key = PBKDF2(keyPlain, salt,32) #using PBKDF2 to convert 
    fileObj=sys.stdin
    i=0
    for data in read_chunks(fileObj):
        message = encrypt_data(data, key, header, salt)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, portClient))
            s.sendall(message)  # send data across

# README 
# The code doesnt satisfy the following conditions as far as tested
# Fails to send in both direction simultaneously
# Run-time error (e.g., crash) on large input , works only on small files
