from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

class HSM:
    def __init__(self) -> None:
        # This is used to save the dict from user to its private key.
        self.private_keys = dict()  # uid => private key object.
    
    '''
    @param user: User generate the keypair mapping the user.
    @return: None
    
    @desc: The private key is stored in the HSM and cannot be
        transmitted to outside.
    '''
    def generate_keypair(self, user: str) -> ec.EllipticCurvePublicKey:
        # Generate ECC private key
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        # save the private key into the dictionary
        self.private_keys.update({user: private_key})
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print('[simulator] Info: A key pair generated for {}:\n\n{}'.format(user, public_pem.decode()))
        
        return public_key

    '''
    @param user: the user who has a private key.
    @return: private key of the user
    
    @desc: This is a simulator, for the reality, the private key should
        be archived in PKCS#8 format and be encrypted.
    '''
    def get_keypair(self, user: str) -> ec.EllipticCurvePrivateKey:
        if user not in self.private_keys:
            print('\033[31m[simulator] Error: Here is no private key for {}.\033[0m'.format(user))
            return None
        return self.private_keys.get(user)
    
    def remove_keypair(self, user: str) -> None:
        self.private_keys.pop(user, None)
        
    '''
    @param user: the user who has the private key.
    @param data: the raw data.
    @return: signature of the raw data with user's private key, return
        None if that user have no private key.
    '''
    def sign(self, user: str, data: bytes) -> bytes:
        if user not in self.private_keys:
            print('\033[31m[simulator] Error: Here is no private key for {}.\033[0m'.format(user))
            return None
        private_key = self.private_keys.get(user)
        signature = private_key.sign(
            data=data,
            signature_algorithm=ec.ECDSA(hashes.SHA256())
        )
        return signature

    
if __name__ == '__main__':
    hsm = HSM()
    public_key = hsm.generate_keypair('RootCA')
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signature = hsm.sign('PolicyCA', b'HelloWorld')
    if signature:
        print('The signature of \"Hello World\" is {}'.format(signature.hex()))
    signature = hsm.sign('RootCA', b'This is Root CA.')
    if signature:
        try:
            public_key.verify(
                signature=signature,
                data=b'This is Root CA.',
                signature_algorithm=ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            print('invalid')
        except:
            print('error')
