from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def public_key_str(public_key: ec.EllipticCurvePublicKey) -> str:
  return public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
  ).decode()

def certificate_str(certificate: x509.Certificate) -> str:
  return f'''
Subject: {str(certificate.subject)[6:-2]}
Issuer: {str(certificate.issuer)[6:-2]}
Invalid Before: {certificate.not_valid_before_utc}
Invalid After: {certificate.not_valid_after_utc}
Public Key:
{certificate.public_key().public_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()}Signature Algorithm: SHA256_with_ECDSA_PSS
'''

def serialize_cert(certificate: x509.Certificate) -> bytes:
  return certificate.public_bytes(
    encoding=serialization.Encoding.DER
  )

def serialize_key(key: ec.EllipticCurvePrivateKey) -> bytes:
  return key.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
  )

def serialize_csr(csr: x509.CertificateSigningRequest) -> bytes:
  return csr.public_bytes(
    encoding=serialization.Encoding.DER
  )

def serialize_chain(chain: dict) -> dict:
  for key in chain:
    chain[key] = serialize_cert(chain[key])
  return chain

def load_chain(chain: dict) -> dict:
  for key in chain:
    chain[key] = load_cert(chain[key])
  return chain

def load_csr(csr: bytes) -> x509.CertificateSigningRequest:
  return x509.load_der_x509_csr(csr)

def load_key(key: bytes) -> ec.EllipticCurvePrivateKey:
  return serialization.load_der_private_key(
    key,
    password=None
  )

def load_cert(cert: bytes) -> x509.Certificate:
  return x509.load_der_x509_certificate(cert)

def get_CN_from_subject(subject: x509.Name) -> str:
  return subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value