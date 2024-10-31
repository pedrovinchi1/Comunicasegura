import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generateAsymmetricKeys():
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
     
        )
        
        public_key = private_key.public_key()

        return (private_key,public_key)
def serializeAsymmetricKeys(key):
    return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
           
        )
def deserilizeAsymmetricKeys(key):
    return serialization.load_pem_public_key(key)
def encryptAsymmetric(key,data):
    cipheredData = key.encrypt(
                data,
                padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label = None
                )
            )
    
    
    return base64.b64encode(cipheredData)
def decryptAsymmetric(key,data):
    data = base64.b64decode(data)
    return key.decrypt(data,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
                    )
def generateAsymmetricSignature(key,data):
    signBytes = key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
    signHash = base64.b64encode(signBytes).decode("utf-8")
    
    return  signHash
def verifiyAsymmetricSignature(sign,key,data):
    sign = base64.b64decode(sign.encode("utf-8"))
    return  key.verify(
        sign,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256())
