from abc import ABC, abstractmethod
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from pyroute2 import IPRoute, netns, NetNS
from multiprocessing import Process, Queue
import socket
import pickle
import os

from cryptography.x509.oid import NameOID
from devices import HSM, LDAP, DB
from services import CA
import utils


'''
@class Machine: This is the super class for all endpoints meant to communicate.
@desc: There is a unique hostname for every device. For
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
  veth_id = 0
  
  def get_next_veth() -> str:
    tmp = Machine.veth_id
    Machine.veth_id += 1
    return str(tmp)
  
  def __init__(self, hostname: str) -> None:
    self.__hostname = hostname
    self.__private_key = None
    self.__certificate = None
    self.__cert_chain = dict()  # CA's name to CA's cert
    self.__address = None
    self.__veth_idx = None
    self.__cmd_map = {
      'help': self.help,
    }
    self.__help_text = ''
  
  def help(self) -> None:
    print(f'''
Usage: COMMAND [OPTION] [ARGS]
exit              Exit the Command Line
help              Show This message
{self.__help_text}
''')
  
  '''
  @param bridgename: which bridge wanna connect to.
  @desc: turn the machine on and specify a bridge to communicate with other
    machines.
  '''
  def poweron(self, bridgename: str) -> None:
    if not os.path.exists(f'/var/run/netns/{self.hostname}'):
      netns.create(self.hostname)    # create a namespace for this machine.
    self.__ns = NetNS(self.hostname)
    
    # create a link to bridge. Note that use the default netns, or it's hard
    # to move the veth into the default ns.
    ipr = IPRoute()
    self.__my_veth = Machine.get_next_veth()
    self.__peer_veth = Machine.get_next_veth()
    ipr.link('add', ifname=self.__my_veth, peer=self.__peer_veth, kind='veth')
    # get and save the index of veth
    self.__veth_idx = ipr.link_lookup(ifname=self.__my_veth)[0]
    br_veth_idx = ipr.link_lookup(ifname=self.__peer_veth)[0]
    br_idx = ipr.link_lookup(ifname=bridgename)[0]
    # set the state and ns for veth, and attach it into bridge.
    ipr.link('set', index=br_veth_idx, master=br_idx, state='up')
    ipr.link('set', index=self.__veth_idx, state='up', net_ns_fd=self.hostname)
    ipr.close()
  
  def poweroff(self) -> None:
    self.__address = None
    self.__veth_idx = None
    # self.__ns.addr('delete', index=self.__veth_idx)
    self.__ns.close()
    netns.remove(self.hostname)
  
  def init_certificate(self, address: tuple) -> None:
    netns.pushns(self.hostname)
    
    c_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = c_socket.connect_ex(address)
    if result == 0:
      print(f"[MiniPKI] {self.hostname}: connected to {address}.")
    else:
      print(f"[MiniPKI] Error: failed to connect to {address}.")
      netns.popns()
      return None

    tp_cert = pickle.loads(c_socket.recv(1024))
    c_socket.send(pickle.dumps({
      'status': 'ok',
      'request': {
        'type': 'csr',
        'csr': utils.serialize_csr(self.get_csr())
      }
    }))
    res = pickle.loads(c_socket.recv(4096))
    self.certificate = utils.load_cert(res['certificate'])
    self.chain = utils.load_chain(res['chain'])
    c_socket.close()
    netns.popns()
  
  def check_cert(self, address: tuple, sn: int) -> bool:
    netns.pushns(self.hostname)
    
    c_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = c_socket.connect_ex(address)
    if result == 0:
      print(f"[MiniPKI] {self.hostname}: connected to {address}.")
    else:
      print(f"[MiniPKI] Error: failed to connect to {address}.")
      netns.popns()
      return False
    
    c_socket.send(pickle.dumps(sn))
    res = pickle.loads(c_socket.recv(1024))
    c_socket.close()
    
    netns.popns()
    return res
  
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
      print(f'\033[31m[simulator] Error: Unknown Type \'{type}\' or wrong parameters.\033[0m')
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

  def get_csr(self) -> x509.CertificateSigningRequest:
    self.__private_key = ec.generate_private_key(ec.SECP256R1())
    return x509.CertificateSigningRequestBuilder().subject_name(
      self.get_subject()
    ).sign(self.__private_key, hashes.SHA256())

  '''
  @desc: provide a command line for user to execute some operations.
    Different kind Endpoint may provide different functions.
  '''
  def cli(self) -> None:
    while True:
      cmd = input(f'[{self.hostname}]$ ')
      if cmd == '':
        continue
      if cmd == 'exit':
        break
      cmd = cmd.split()
      args = cmd[1:]
      cmd = cmd[0]
      if cmd in self.__cmd_map:
        tar_func = self.__cmd_map.get(cmd)
        tar_func(*args)
      else:
        self.help()
  
  def get_subject(self, C: str='CN', S: str='ShanDong', L: str='QingZhou', O: str='MiniPKI') -> x509.Name:
    return x509.Name([
      x509.NameAttribute(NameOID.COUNTRY_NAME, C),
      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, S),
      x509.NameAttribute(NameOID.LOCALITY_NAME, L),
      x509.NameAttribute(NameOID.ORGANIZATION_NAME, O),
      x509.NameAttribute(NameOID.COMMON_NAME, self.hostname),
    ])
  
  def quick_up(self, bridge: str, address: str) -> None:
    self.poweron(bridge)
    self.address = address
  
  def quick_down(self) -> None:
    self.poweroff()
  
  @property
  def certificate(self) -> x509.Certificate:
    return self.__certificate
  
  @certificate.setter
  def certificate(self, cert: x509.Certificate) -> None:
    self.__certificate = cert
  
  @property
  def chain(self) -> dict:
    return self.__cert_chain
  
  @chain.setter
  def chain(self, cert_chain: dict) -> None:
    self.__cert_chain = cert_chain
  
  @property
  def hostname(self) -> str:
    return self.__hostname

  @hostname.setter
  def hostname(self, hostname: str) -> None:
    self.__hostname = hostname
  
  @property
  def address(self) -> str:
    return self.__address

  @property
  def help_text(self) -> str:
    return self.__help_text
  
  @help_text.setter
  def help_text(self, text: str) -> None:
    self.__help_text = text
  
  def set_cmd_map(self, cmd_map: dict) -> None:
    self.__cmd_map.update(cmd_map)
  
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
  
  def quick_up(self, bridge, address):
    super().quick_up(bridge, address)
    self.start()
  
  def quick_down(self):
    self.stop()
    super().quick_down()
  
  @property
  def service_port(self) -> int:
    return self.__service_port

  @service_port.setter
  def service_port(self, port: int) -> None:
    self.__service_port = port
  
  '''
  @desc: This is the service method, will listen on a specific port
    and call the method `work` to cope the requests.
  '''
  def service(self) -> None:
    netns.setns(self.hostname)

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
      self.work(client_socket, client_address)
      client_socket.close()

  '''
  @param client_socket: which client's request will be handled.
  @param client_address: the address connected to this server.
  @desc: This is the real logic method to cope with the client requests.
    So, if you wanna design the custom logic, override this method.
  '''
  def work(self, c_socket: socket, c_address: tuple) -> None:
    print(f"[MiniPKI] {self.hostname}: connected by {c_address}.")
    # Receive a message
    data = c_socket.recv(1024)
    print(f"[MiniPKI] {self.hostname}: Received \"{data.decode()}\".")
    # Send a response
    c_socket.send(b"Hello, Client!")
  
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


class OCSP(Server):
  def __init__(self, hostname: str):
    super().__init__(hostname)
    self.__ldap = LDAP()
    
  def get_ldap(self) -> LDAP:
    return self.__ldap
  
  def work(self, c_socket: socket, c_address: tuple) -> None:
    sn = int(pickle.loads(c_socket.recv(1024)))
    if sn == -1:
      c_socket.send(pickle.dumps(False))
      c_socket.close()
      return None
    c_socket.send(pickle.dumps(self.__ldap.get(sn)))
    c_socket.close()


class TrustPlat(Server):
  def __init__(self, hostname: str, ocsp: OCSP):
    super().__init__(hostname)
    self.__hsm = HSM()
    self.__db = DB()
    self.__ldap = ocsp.get_ldap()
    self.__root = CA('Root CA', self.__hsm, self.__db, self.__ldap)
    self.__ext = CA('External CA', self.__hsm, self.__db, self.__ldap, self.__root)
    self.__client = CA('Client CA', self.__hsm, self.__db, self.__ldap, self.__root)
    s_cert = self.__ext.issue(self.get_csr())
    self.certificate = s_cert
    self.chain = {
      'Root CA': self.__root.certificate,
      'External CA': self.__ext.certificate,
      'Client CA': self.__client.certificate
    }
  
  '''
  @param type: what kind of certificate do you wanna request:
    subject: for the Endpoint who need TrustPlat generate a key pair as well.
    csr: for the regular certificate request.
  @param subject: provide the infomation about the endpoint if type == subject
  @param csr: provide the CSR if type == csr
  '''
  def request(self, type: str='csr', subject: x509.Name=None, csr: x509.CertificateSigningRequest=None) -> dict:
    c_chain = utils.serialize_chain(self.chain)
    if type == 'subject' and subject:
      c_private_key = self.__hsm.generate_keypair()
      csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
      ).sign(c_private_key, hashes.SHA256())
      c_cert = self.__client.issue(csr)
      return {
        'private key': utils.serialize_key(c_private_key),
        'certificate': utils.serialize_cert(c_cert),
        'chain': c_chain
      }
    elif type == 'csr' and csr:
      csr = utils.load_csr(csr)
      return {
        'certificate': utils.serialize_cert(self.__ext.issue(csr)),
        'chain': c_chain
      }
    return None
  
  def work(self, c_socket: socket, c_address: tuple) -> None:
    c_socket.send(pickle.dumps({
      'status': 'ok',
      'certificate': utils.serialize_cert(self.certificate)
    }))
    req = pickle.loads(c_socket.recv(1024))
    if req['status'] == 'error':
      return None
    res = self.request(
      type=req['request'].get('type'),
      subject=req['request'].get('subject', None),
      csr=req['request'].get('csr', None)
    )
    if not res:
      c_socket.send(pickle.dumps({
        'status': 'error',
        'msg': 'Wrong parameters.'
      }))
      return None
    res.update({'status': 'ok'})
    c_socket.send(pickle.dumps(res))


class Client(Machine):
  def __init__(self, hostname):
    super().__init__(hostname)
  
  def connect(self, addr: str, port: int) -> bool:
    netns.pushns(self.hostname)

    # Create a standard TCP socket
    c_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = c_socket.connect_ex((addr, port))
    if result == 0:
      print(f"[MiniPKI] {self.hostname}: connected to {addr}:{port}.")
    else:
      print(f"[MiniPKI] Error: failed to connect to {addr}:{port}.")
      netns.popns()
      return False

    self.work(c_socket)
    
    c_socket.close()
    netns.popns()
  
  def work(self, c_socket: socket) -> None:
    # Send a message
    c_socket.send(b"Hello, Server!")
    print(f"[MiniPKI] {self.hostname}: Message sent!")
    # Receive a response
    response = c_socket.recv(1024)
    print(f"[MiniPKI] {self.hostname}: Received \"{response.decode()}\".")
    

if __name__ == '__main__':
  ipr = IPRoute()
  ipr.link('add', ifname="br", kind="bridge")
  ipr.link('set', index=ipr.link_lookup(ifname='br')[0], state='up')
  ocsp = OCSP('OCSP')
  trust_plat = TrustPlat('TrustPlat', ocsp)
  server = Server('Server')
  client = Client('Client')
  trust_plat.quick_up('br', '192.168.0.254')
  ocsp.quick_up('br', '192.168.0.253')
  server.quick_up('br', '192.168.0.2')
  client.quick_up('br', '192.168.0.1')
  import time
  time.sleep(1)
  client.init_certificate(('192.168.0.254', 233))
  server.init_certificate(('192.168.0.254', 233))
  time.sleep(1)
  print(client.check_cert(('192.168.0.253', 233), client.certificate.serial_number))
  client.connect(server.address, server.service_port)
  server.quick_down()
  client.quick_down()
  ocsp.quick_down()
  trust_plat.quick_down()
  ipr.link('del', ifname='br')
