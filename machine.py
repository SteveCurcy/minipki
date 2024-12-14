from abc import ABC, abstractmethod
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pyroute2 import IPRoute, netns, NetNS
import uuid

from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from devices import HSM, LDAP, DB
from services import CA
import utils


'''
@class Machine: This is the super class for all endpoints meant to communicate.
@desc: There is a unique uuid derived by timestamp for every device. For
    security communication, everyone should have a certificate to prove itself.
    And they use a chain of certs to verify others' certifcates.
    They may have the following behaviors:
    1. flush into a chain of certificates. use case: initialization or modified.
    2. flush into a ceertificate, use case: initial or changed.
    3. can verify a certificate by using the cert-chain.
    4. can check if the certificate is unexpired by accessing the OCSP.
    4. connect the command line of machine to run some directs.
    5. service() only for server to support some services, can be override.
'''
class Machine(ABC):
    def __init__(self, hostname) -> None:
        self.__hostname = hostname
        self.__uuid = str(uuid.uuid1())
        self.__certificate = None
        self.__cert_chain = dict()  # CA's name to CA's cert
        self.__private_key = None
        netns.setns(self.__uuid)    # create a namespace for this machine.
    
    def __del__(self) -> None:
        netns.remove(self.__uuid)
        pass
    
    '''
    @param type: what do you wanna flush into the machine, which MUST be one of:
        'cert': only flush a certificate.
        'chain': only flush a certificate chain.
        'both': flush both certificate and the chain.
    @param cert: the Certificate to be flushed.
    @param chain: the cert chain to be flushed.
    @return: bool means flush successfully or not.
    
    @desc: when you flush a certificate or both into the machine, this function
        will verify the validition of the certificate by provided chain.
    '''
    def flush(self, type: str='cert', cert: x509.Certificate=None, chain: dict[x509.Name: x509.Certificate]=None) -> bool:
        if type == 'cert':
            if not self.verify(cert):
                print(f'\033[31m[simulator] Error: Cert cannot be verified by chain.\033[0m')
                return False
            self.__certificate = cert
        elif type == 'chain':
            self.__cert_chain = chain
        elif type == 'both':
            if not self.verify(cert, chain=chain):
                print(f'\033[31m[simulator] Error: Cert cannot be verified by chain.\033[0m')
                return False
            self.__certificate = cert
            self.__cert_chain = chain
        else:
            print(f'\033[31m[simulator] Error: Unknown Type \'{uuid}\'.\033[0m')
            return False
        return True
    
    '''
    @param certificate: which is to be verified.
    @param chain: the specific chain of certificate if need.
    @return: True or False, which means Ok or not.
    '''
    def verify(self, certificate: x509.Certificate, chain: dict[x509.Name: x509.Certificate]=None) -> bool:
        if not chain:
            chain = self.__cert_chain
        while certificate.issuer in chain:
            ca_cert = chain.get(certificate.issuer)
            if ca_cert.subject == certificate.issuer:
                return True
            try:
                ca_cert.public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    hashes.SHA256()
                )
            except Exception as e:
                print(f"[MiniPKI] Certificate verification failed: {e}")
                return False
        return False

    '''
    @desc: provide a command line for user to execute some operations.
    '''
    def cli(self) -> None:
        help_text = f'''
Usage: COMMAND [OPTION] [ARGS]

help                    Show this help message
exit                    quit from this command line
set
  hostname [HOSTNAME]   set the hostname of this device
'''
        while True:
            command = input(f'[{self.__hostname}]# ').split()
            if not len(command):
                continue
            if len(command) > 1:
                args = command[1:]
            command = command[0]
            if command == 'set':
                if args[0] == 'hostname':
                    self.set_hostname(args[1])
            elif command == 'help':
                print(help_text)
            elif command == 'exit':
                return None
            else:
                print(help_text)
    
    def get_cert(self) -> x509.Certificate:
        return self.__certificate
    
    def get_hostname(self) -> str:
        return self.__hostname

    def set_hostname(self, hostname: str) -> None:
        self.__hostname = hostname

if __name__ == '__main__':
    hsm = HSM()
    db = DB()
    ldap = LDAP()
    # ocsp = OCSP(ldap)
    root = CA('RootCA', hsm, db, ldap, None)
    subca = CA('SubCA', hsm, db, ldap, root)
    
    # simulate the client to request a certificate
    client_private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "ShanDong"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "QingZhou"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MiniPKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com"),
    ])

    # Create the CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        client_private_key, hashes.SHA256()
    )
    client_certificate = subca.issue(csr)
    print(f'[MiniPKI] Info: client\'s cert is\n{utils.certificate_str(client_certificate)}')
    machine = Machine('faker')
    root_cert, sub_cert = root.get_cert(), subca.get_cert()
    machine.flush('both', cert=client_certificate, chain={
        root_cert.subject: root_cert,
        sub_cert.subject: sub_cert
    })
    print(machine.verify(client_certificate))
    machine.cli()
