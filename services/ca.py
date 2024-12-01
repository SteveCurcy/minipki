from datetime import datetime, timedelta
from devices import DB, HSM
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

class CA:
    '''
    @dev: pretend all the CAs are from the same location, just for simulation
    '''
    def __init__(self, name: str, hsm: HSM, db: DB, issuer: 'CA' = None) -> None:
        self.name = name
        self.hsm = hsm
        self.db = db
        self.issuer = issuer
        self.public_key = hsm.generate_keypair(name)
        self.private_key = hsm.get_keypair(name)
        
        print(f'[simulator] Info: CA \'{name}\' is initializing.')
        
        # after info's initialization, to request a certificate for itself
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Certificate Authority'),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ])
        # the issuer is itself if the param 'issuer' is None.
        if issuer:
            issuer_subject = issuer.get_cert().subject
            issuer_name = issuer.get_name()
        else:
            issuer_subject = subject
            issuer_name = name

        self.certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer_subject
        ).public_key(
            self.public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now()
        ).not_valid_after(
            datetime.now() + timedelta(days=365*30)
        ).sign(
            hsm.get_keypair(issuer_name), hashes.SHA256()
        )
        
        certificate_pem = self.certificate.public_bytes(serialization.Encoding.PEM)
        print(f'[simulator] Info: cert of {name} is issued:\n{certificate_pem.decode()}')
    
    def issue(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
        pass
    
    def revoke(self, user: str) -> None:
        pass
    
    def get_cert(self) -> x509.Certificate:
        return self.certificate
    
    def get_name(self) -> str:
        return self.name


if __name__ == '__main__':
    hsm = HSM()
    db = DB()
    root = CA('RootCA', hsm, db, None)
    subca = CA('SubCA', hsm, db, root)
    
