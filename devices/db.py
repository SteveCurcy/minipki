# This is a simulated Database to store mapping from user to cert
from cryptography import x509

class DB:
    def __init__(self) -> None:
        # This is used to save the dict from user to its certificate.
        self.certificates = dict()
    
    def update(self, user: str, certificate: x509.Certificate) -> None:
        self.certificates.update({user: certificate})
    
    def delete(self, user: str) -> None:
        self.certificates.pop(user, None)
    
    def retrive(self, user: str) -> x509.Certificate:
        if user not in self.certificates:
            print('\033[31m[simulator] Error: Here is no certificate for {}.\033[0m'.format(user))
            return None
        return self.certificates.get(user)
