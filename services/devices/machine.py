from abc import ABC, abstractmethod
from cryptography import x509

class Machine(ABC):
    def __init__(self) -> None:
        self.certificate = None
        self.cert_chain = list()    # This stores the chain of trust
        self.private_key = None
    
    def deploy(self, certificate: x509.Certificate, cert_chain: list[x509.Certificate]) -> None:
        self.certificate = certificate
        self.cert_chain.extend(cert_chain)
    
    @abstractmethod
    def request_cert(self, ca: object) -> None:
        pass
    
    @abstractmethod
    def get_cert(self) -> object:
        pass
