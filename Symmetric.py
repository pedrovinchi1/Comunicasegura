
import base64
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generateSymmetricKey():
    return (os.urandom(32))
def encryptSymmetric(key,data):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key),  modes.GCM(nonce))

    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()

    padded_data = padder.update(data)

    padded_data += padder.finalize()

    
    encryptedMessage = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(nonce+encryptedMessage).decode("utf-8")

def decryptSymmetric(key,data):
    data = base64.b64decode(data)
    nonce = data[:12]
    encryptedMessage = data[12:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))

    
    decryptor = cipher.decryptor()

    decryptedPaddedMessage = decryptor.update(encryptedMessage) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()

    decryptedMessage = unpadder.update(decryptedPaddedMessage) + unpadder.finalize()

       
    return decryptedMessage

