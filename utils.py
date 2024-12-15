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

def get_CN_from_subject(subject: x509.Name) -> str:
  return subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value