from abc import ABC, abstractmethod
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from pyroute2 import IPRoute, netns, NetNS
from multiprocessing import Process, Queue
import socket
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
    
    # create a link to bridge. Note that use the default netns, or it's hard
    # to move the veth into the default ns.
    ipr = IPRoute()
    ipr.link('add', ifname='trust-plat-veth', peer='trust-br-veth', kind='veth')
    # get and save the index of veth
    self.__veth_idx = ipr.link_lookup(ifname='trust-plat-veth')[0]
    br_veth_idx = ipr.link_lookup(ifname='trust-br-veth')[0]
    br_idx = ipr.link_lookup(ifname=bridgename)[0]
    # set the state and ns for veth, and attach it into bridge.
    ipr.link('set', index=br_veth_idx, master=br_idx, state='up')
    ipr.link('set', index=self.__veth_idx, state='up', net_ns_fd=self.uuid)
  
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
    self.__service_port = 233
  
  @property
  def service_port(self) -> int:
    return self.__service_port

  @service_port.setter
  def service_port(self, port: int) -> None:
    self.__service_port = port
  
  # This is the service function, which is a simple demo.
  # If you wanna provide a complicate service, override this method.
  def service(self) -> None:
    netns.setns(self.uuid)

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind the socket to the address and port
    server_socket.bind((self.address, self.__service_port))
    print(f"[MiniPKI] {self.hostname}: listening on {self.address}:{self.__service_port}.")
    server_socket.listen(5)  # Allow up to 5 pending connections

    while True:
      # Accept a new connection
      client_socket, client_address = server_socket.accept()
      print(f"[MiniPKI] {self.hostname}: connected by {client_address}.")

      # Receive a message
      data = client_socket.recv(1024)
      print(f"[MiniPKI] {self.hostname}: Received \"{data.decode()}\".")

      # Send a response
      client_socket.send(b"Hello, Client!")
      client_socket.close()
  
  def start(self) -> None:
    self.__service_process = Process(target=self.service, args=())
    self.__service_process.start()

  def stop(self) -> None:
    self.__service_process.terminate()
    self.__service_process = None
  
  def cli(self) -> None:
    while True:
      command = input(f'[{self.hostname}]$ ').split()
      if not len(command):
        continue
      if command[0] == 'exit':
        break


def test_connect(addr: str, port: int) -> None:
  ipr = IPRoute()
  ipr.link('add', ifname='test-veth', peer='test-br-veth', kind='veth')
  # get and save the index of veth
  veth_idx = ipr.link_lookup(ifname='test-veth')[0]
  br_veth_idx = ipr.link_lookup(ifname='test-br-veth')[0]
  br_idx = ipr.link_lookup(ifname='br')[0]
  # set the state and ns for veth, and attach it into bridge.
  ipr.link('set', index=br_veth_idx, master=br_idx, state='up')
  ipr.link('set', index=veth_idx, state='up')
  ipr.addr('add', index=veth_idx, address='192.168.0.1', mask=24)

  # Create a standard TCP socket
  c_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  result = c_socket.connect_ex((addr, port))
  if result == 0:
    print(f"[MiniPKI] Client: connected to {addr}:{port}.")
  else:
    print(f"[MiniPKI] Error: failed to connect to {addr}:{port}.")
    return None

  # Send a message
  c_socket.send(b"Hello, Server!")
  print("[MiniPKI] Client: Message sent!")

  # Receive a response
  response = c_socket.recv(1024)
  print(f"[MiniPKI] Client: Received \"{response.decode()}\".")
  c_socket.close()

  ipr.link('del', ifname='test-veth')
  ipr.close()
    

if __name__ == '__main__':
  ipr = IPRoute()
  ipr.link('add', ifname="br", kind="bridge")
  ipr.link('set', index=ipr.link_lookup(ifname='br')[0], state='up')
  server = Server('server')
  server.poweron('br')
  server.address = '192.168.0.2'
  server.start()
  import time
  time.sleep(1)

  test_connect(server.address, server.service_port)

  server.stop()
  server.poweroff()
  ipr.link('del', ifname='br')
