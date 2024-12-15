from datetime import datetime, timedelta
from devices import DB, HSM, LDAP
import utils
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


class OCSP:
  def __init__(self, ldap: LDAP) -> None:
    self.__ldap = ldap
  
  def fresh(self, sn: int) -> None:
    self.__ldap.update(sn)
  
  def expire(self, sn: int) -> None:
    self.__ldap.delete(sn)
  
  def check(self, sn: int) -> bool:
    return self.__ldap.get(sn)


class CA:
  '''
  @param name: name of this CA.
  @param hsm: which HSM this CA use.
  @param db: where the certificates to store.
  @param ocsp: which ocsp this CA sync the status.
  @param issuer: the father CA to sign this CA.
  
  @desc: pretend all the CAs are from the same location, just for simulation
  '''
  def __init__(self, name: str, hsm: HSM, db: DB, ldap: LDAP, issuer: 'CA' = None) -> None:
    self.__name = name
    self.__db = db
    self.__hsm = hsm
    self.__ldap = ldap
    self.__public_key = hsm.generate_keypair_and_store(name)
    
    # after info's initialization, to request a certificate for itself
    subject = x509.Name([
      x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "ShanDong"),
      x509.NameAttribute(NameOID.LOCALITY_NAME, "QingZhou"),
      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MiniPKI"),
      x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    # Here! request the certificate from your issuer if the issuer is 
    # not empty. Or, sign a certificate itself, cause it's the Root.
    if issuer:
      csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
      )
      csr = hsm.sign(name, type='csr', csr_unsigned=csr)
      self.certificate = issuer.issue(csr)
    else:
      self.certificate = x509.CertificateBuilder().subject_name(
        subject
      ).issuer_name(
        subject
      ).public_key(
        self.__public_key
      ).serial_number(
        x509.random_serial_number()
      ).not_valid_before(
        datetime.now()
      ).not_valid_after(
        datetime.now() + timedelta(days=365*30)
      )
      self.certificate = hsm.sign(name, type='cert', cert_unsigned=self.certificate)
  
  '''
  @param csr: the Certificate Signing Request
  @return: A certificate according to the CSR
  
  @desc: use own private key to issue a certificate according to the CSR
    and store the mapping from Common name to the certificate, and flush
    the status onto the OCSP.
  '''
  def issue(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
    certificate = x509.CertificateBuilder().subject_name(
      csr.subject
    ).issuer_name(
      self.certificate.subject
    ).public_key(
      self.__public_key
    ).serial_number(
      x509.random_serial_number()
    ).not_valid_before(
      datetime.now()
    ).not_valid_after(
      datetime.now() + timedelta(days=365*5)
    )
    certificate = self.__hsm.sign(self.__name, type='cert', cert_unsigned=certificate)
    # update the certificate into the database and sync the status
    # to the OCSP for checking
    self.__db.update(utils.get_CN_from_subject(csr.subject), certificate)
    self.__ldap.update(certificate.serial_number)
    
    return certificate
  
  def revoke(self, user: str) -> None:
    to_be_removed = self.__db.delete(user)
    self.__ldap.delete(to_be_removed.serial_number)
  
  def get_cert(self) -> x509.Certificate:
    return self.certificate
  
  def get_name(self) -> str:
    return self.__name


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
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
    x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com"),
  ])

  # Create the CSR
  csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
    client_private_key, hashes.SHA256()
  )
  client_certificate = subca.issue(csr)
  # print(f'Client request and get a certificate:\n{utils.certificate_str(client_certificate)}')
  # check the certificate's status
  # print(f'Client\'s status is {"good" if ocsp.check(client_certificate.serial_number) else "expired"}')
  subca.revoke('www.example.com')
  print(f'[MiniPKI] Info: Now the certificate is revoked.')
  # print(f'Client\'s status is {"good" if ocsp.check(client_certificate.serial_number) else "expired"}')
