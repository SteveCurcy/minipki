from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from cryptography import x509


class DB:
  def __init__(self) -> None:
    # This is used to save the dict from user to its certificate.
    self.__certificates = dict()
  
  def update(self, uuid: str, certificate: x509.Certificate) -> None:
    self.__certificates.update({uuid: certificate})
  
  def delete(self, uuid: str) -> x509.Certificate:
    return self.__certificates.pop(uuid, None)
  
  def retrive(self, uuid: str) -> x509.Certificate:
    if uuid not in self.__certificates:
      print(f'\033[31m[simulator] Error: Here is no certificate for {uuid}.\033[0m')
      return None
    return self.__certificates.get(uuid)


class HSM:
  def __init__(self) -> None:
    # This is used to save the dict from user to its private key.
    self.__private_keys = dict()  # uuid => private key object.
  
  '''
  @param uuid: the ID of entity for applying a keypair. uuid is unique and
    can be used to identify the entity, like computer, ECU or people, etc.
  @return: Public Key
  
  @desc: The private key for CA is stored in the HSM and cannot be
    transmitted to outside.
  '''
  def generate_keypair_and_store(self, uuid: str) -> ec.EllipticCurvePublicKey:
    # Generate ECC private key
    private_key = ec.generate_private_key(ec.SECP256R1())
    # save the private key into the dictionary
    self.__private_keys.update({uuid: private_key})
    return private_key.public_key()
  
  '''
  @return: A keypair containing private key and public.
  
  @desc: This method is used to generate keys for some entity with
    low security level. In this project, CA is the most important
    entity, and the client or server is at a low level. But, In
    real situation, the keypair generated should be packed in some
    specific format, like PKCS#12.
    And this key pair is unnessary to store in HSM.
  '''
  def generate_keypair(self) -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())
  
  def remove_keypair(self, uuid: str) -> None:
    self.__private_keys.pop(uuid, None)
  
  '''
  @param uuid: ID of CA.
  @param type: what kind of data to be signed. There is three types:
    'data': bytes, the common type
    'cert': to sign a certificate
    'csr' : to sign a Certificate Request
  @param data: pass this if you choose 'data' type or not specify the type.
  @param cert_unsigned: A certificate without signature, which is to
    be signed use CA's private key. Pass this if you choose 'cert' type.
  @param csr_unsigned: A certificate signing request, if you choose 'csr' type.
  @return: a certificate with signature.
  
  @desc: This sign method is specificly used to sign certificate, 'cause
    it's different with the common sign process of other data.
  '''
  def sign(self, uuid: str, type: str='data', data: bytes=None, cert_unsigned: x509.CertificateBuilder=None, csr_unsigned: x509.CertificateSigningRequestBuilder=None):
    sk_ca = self.__private_keys.get(uuid, None)
    if not sk_ca:
      print(f'\033[31m[MiniPKI] Error: Here is no private key for {uuid}.\033[0m')
      return None
    if type == 'data':
      return sk_ca.sign(
        data=data,
        signature_algorithm=ec.ECDSA(hashes.SHA256())
      )
    elif type == 'cert':
      return cert_unsigned.sign(sk_ca, hashes.SHA256())
    elif type == 'csr':
      return csr_unsigned.sign(sk_ca, hashes.SHA256())
    else:
      return None


class LDAP:
  def __init__(self) -> None:
    # This is used to save the dict from cert's SN to its status.
    self.__status = set()
  
  def update(self, sn: int) -> None:
    self.__status.add(sn)
  
  def get(self, sn: int) -> bool:
    return sn in self.__status
  
  def delete(self, sn: int) -> None:
    self.__status.remove(sn)


if __name__ == '__main__':
  hsm = HSM()
  public_key = hsm.generate_keypair_and_store('RootCA')
  signature = hsm.sign('PolicyCA', b'HelloWorld')
  if signature:
    print(f'[MiniPKI] The signature of \"Hello World\" is {signature.hex()}')
  signature = hsm.sign('RootCA', data=b'This is Root CA.')
  if signature:
    try:
      public_key.verify(
        signature=signature,
        data=b'This is Root CA.',
        signature_algorithm=ec.ECDSA(hashes.SHA256())
      )
      print(f'[MiniPKI] The signature of \"Hello World\" by RootCA is {signature.hex()}')
    except InvalidSignature:
      print('[MiniPKI] Error: invalid signature, which cannot be verified.')
    except:
      print('[MiniPKI] Error: Unknown error.')