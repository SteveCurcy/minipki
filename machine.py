from abc import ABC, abstractmethod
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from pyroute2 import IPRoute, netns, NetNS
from multiprocessing import Process
import uuid
import os

from cryptography.x509.oid import NameOID
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
'''
class Machine(ABC):
    def __init__(self, hostname: str) -> None:
        self.__uuid = str(uuid.uuid1())
        self.__hostname = hostname
        self.__private_key = None
        self.__certificate = None
        self.__cert_chain = dict()  # CA's name to CA's cert
        self.__address = None
        self.__veth_idx = None
    
    '''
    @param bridgename: which bridge wanna connect to.
    @desc: turn the machine on and specify a bridge to communicate with other
        machines.
    '''
    def poweron(self, bridgename: str) -> None:
        if not os.path.exists(f'/var/run/netns/{self.__uuid}'):
            netns.create(self.__uuid)    # create a namespace for this machine.
        self.__ns = NetNS(self.__uuid)
        
        # create a link to bridge
        ipr = IPRoute()
        self.__ns.link('add', ifname='trust-plat-veth', peer='trust-br-veth', kind='veth')
        self.__veth_idx = self.__ns.link_lookup(ifname='trust-plat-veth')[0]
        br_veth_idx = self.__ns.link_lookup(ifname='trust-br-veth')[0]
        br_idx = ipr.link_lookup(ifname=bridgename)[0]
        ipr.link('set',
            index=br_veth_idx,
            master=br_idx
        )
    
    def poweroff(self) -> None:
        self.__address = None
        self.__veth_idx = None
        # self.__ns.addr('delete', index=self.__veth_idx)
        self.__ns.close()
        netns.remove(self.__uuid)
    
    '''
    @param type: what do you wanna flush into the machine, which MUST be one of:
        'cert': only flush a certificate.
        'both': flush both certificate and the chain.
    @param private_key: the sk corresponding to the certificate.
    @param cert: the Certificate to be flushed.
    @param chain: the cert chain to be flushed.
    @return: bool means flush successfully or not.
    
    @desc: when you flush a certificate or both into the machine, this function
        will verify the validition of the certificate by provided chain.
    '''
    def flush(self, type: str='cert', private_key: ec.EllipticCurvePrivateKey=None, cert: x509.Certificate=None, chain: dict[x509.Name: x509.Certificate]=None) -> bool:
        if type == 'cert' and private_key and cert:
            if not self.verify(cert):
                print(f'\033[31m[simulator] Error: Cert cannot be verified by chain.\033[0m')
                return False
            self.__private_key = private_key
            self.__certificate = cert
        elif type == 'both' and private_key and cert and chain:
            if not self.verify(cert, chain=chain):
                print(f'\033[31m[simulator] Error: Cert cannot be verified by chain.\033[0m')
                return False
            self.__certificate = cert
            self.__cert_chain = chain
        else:
            print(f'\033[31m[simulator] Error: Unknown Type \'{uuid}\' or wrong parameters.\033[0m')
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
        Different kind Endpoint may provide different functions.
    '''
    @abstractmethod
    def cli(self) -> None:
        pass
    
    @property
    def uuid(self) -> str:
        return self.__uuid
    
    @property
    def certificate(self) -> x509.Certificate:
        return self.__certificate
    
    @property
    def hostname(self) -> str:
        return self.__hostname

    @hostname.setter
    def hostname(self, hostname: str) -> None:
        self.__hostname = hostname
    
    @property
    def address(self) -> str:
        return self.__address
    
    '''
    @param addr: the address wanna set to this machine.
    @desc: change the veth's address as well
    '''
    @address.setter
    def address(self, addr: str) -> None:
        if not self.__address:
            self.__ns.addr('add', index=self.__veth_idx, address=addr, mask=24)
        else:
            self.__ns.addr('replace', index=self.__veth_idx, address=addr, mask=24)
        self.__address = addr
    
    def encrypt(self, data: bytes, public_key: ec.EllipticCurvePublicKey) -> bytes:
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt(self, data: bytes) -> bytes:
        return self.__private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


class Server(Machine):
    def __init__(self, hostname):
        super().__init__(hostname)
        self.__service_process = None
    
    def service(self) -> None:
        netns.setns(self.uuid)
    
    def start(self) -> None:
        self.__service_process = Process(target=self.start, args=(self, ))

    def stop(self) -> None:
        self.__service_process.terminate()
    
    def cli(self) -> None:
        while True:
            command = input()
            print(command)
            
        

if __name__ == '__main__':
    ipr = IPRoute()
    ipr.link('add', ifname="br", kind="bridge")
    ipr.link('set', index=ipr.link_lookup(ifname='br')[0], state='up')
    server = Server('server')
    server.poweron('br')
    server.address = '192.168.0.1'
    server.cli()
    server.poweroff()
    ipr.link('del', ifname='br')
