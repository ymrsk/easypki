from typing import Optional, List, Tuple
from easypki import build_x509
from easypki import build_rsa
from easypki import utils
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization


class BuildPKI():
    def __init__(
        self,
        *,
        ca_cert: x509.Certificate = None,
        ca_key: rsa.RSAPrivateKey = None
    ):
        self.ca_cert: x509.Certificate = ca_cert
        self.ca_key: rsa.RSAPrivateKey = ca_key
        self.ca_csr: x509.CertificateSigningRequest = None
        self.crl_cert: x509.CertificateRevocationList = None
        self.crl_key: rsa.RSAPrivateKey = None
        self.end_entity_cert: x509.Certificate = None
        self.end_entity_key: rsa.RSAPrivateKey = None
        self.end_entity_csr: x509.CertificateSigningRequest = None
        self.pkcs12: bytes = None
        self.end_entity_dir_name: str = 'end_entity_certificate'
    
    def make_private_key(
        self
    ):
        return build_rsa.make_private_key()

    def make_ca(
        self,
        *,
        country_name: Optional[str] = None,
        state_or_province_name: Optional[str] = None,
        locality_name: Optional[str] = None,
        organization_name: Optional[str] = None,
        organization_unit_name: Optional[str] = None,
        common_name: Optional[str] = 'Private RootCA',
        email_address: Optional[str] = None,
        cert_expire_days: int = 36500,
        ca_key_password: int = None
    ) -> Tuple[bytes, bytes, bytes]:
        """selfsign ca certificate
        Returns:
            tuple(pem file): cert, key, csr
        """
        key = self.make_private_key()
        csr = build_x509.make_csr(
            key=key,
            country_name=country_name,
            state_or_province_name=state_or_province_name,
            locality_name=locality_name,
            organization_name=organization_name,
            organization_unit_name=organization_unit_name,
            common_name=common_name,
            email_address=email_address,
            san=None)
        cert = build_x509.make_base_certificate(
            cert_type='selfsign',
            ca_cert=None,
            csr=csr,
            key=key,
            cert_expire_days=cert_expire_days)
        cert = build_x509.add_basic_constraints(
            builder=cert,
            is_ca=True,
            path_length=0,
            critical=True)
        cert = build_x509.add_keyusage(
            builder=cert,
            key_cert_sign=True,
            crl_sign=True,
            critical=True)
        cert = build_x509.add_extended_key_useage(
            builder=cert, server=True, client=True)
        cert = build_x509.add_sign(cert, key)
        cert = utils.convert_instance_to_pem(cert, ca_key_password)
        key = utils.convert_instance_to_pem(key)
        csr = utils.convert_instance_to_pem(csr)
        self.ca_cert = cert
        self.ca_key = key
        self.ca_csr = csr
        return cert, key, csr

    def make_crl(
        self,
        *,
        end_entity_cert: bytes = None,
        expire_date: int = 7,
        effective_date: int = 0,
        crl_cert: bytes = None,
        crl_key: bytes = None,
        crl_key_password: str = None,
        ca_cert: bytes = None
    ):
        end_entity_cert = utils.validate_cert(end_entity_cert, self.end_entity_cert)
        if crl_cert or self.crl_cert:
            crl_cert = utils.validate_cert(crl_cert, self.crl_cert)
        ca_cert = utils.validate_cert(ca_cert, self.ca_cert)
        crl_key = utils.validate_key(crl_key, self.crl_key, crl_key_password)
        crl = build_x509.make_crl(
            crl_key=crl_key,
            ca_cert=ca_cert,
            expire_cert=end_entity_cert,
            expire_date=expire_date,
            effective_date=effective_date,
            crl_cert=crl_cert,
        )
        crl = utils.convert_instance_to_pem(crl)
        key = utils.convert_instance_to_pem(crl_key)
        self.crl_cert = crl
        self.crl_key = key
        return crl, key
    
    def make_server(
        self,
        *,
        ca_cert: bytes = None,
        ca_key: bytes = None,
        ca_key_password: str = None,
        country_name: Optional[str] = None,
        state_or_province_name: Optional[str] = None,
        locality_name: Optional[str] = None,
        organization_name: Optional[str] = None,
        organization_unit_name: Optional[str] = None,
        common_name: Optional[str] = 'www.example.com',
        email_address: Optional[str] = None,
        san: List[str] = None,
        cert_expire_days: int = 365,
        cert_password: str = None
    ):
        """
        server certificate
        """
        ca_cert = utils.validate_cert(ca_cert, self.ca_cert)
        ca_key = utils.validate_key(ca_key, self.ca_key, ca_key_password)
        key: rsa.RSAPrivateKey = self.make_private_key()
        csr = build_x509.make_csr(
            key=key,
            country_name=country_name,
            state_or_province_name=state_or_province_name,
            locality_name=locality_name,
            organization_name=organization_name,
            organization_unit_name=organization_unit_name,
            common_name=common_name,
            email_address=email_address,
            san=san)
        cert = build_x509.make_base_certificate(
            cert_type='casign',
            ca_cert=ca_cert,
            csr=csr,
            key=key,
            cert_expire_days=cert_expire_days)
        if san:
            cert = build_x509.add_subject_alternative_name(
                builder=cert,
                san=san)
        cert = build_x509.add_subject_key_identifier(
            builder=cert, publick_key=key.public_key())
        cert = build_x509.add_keyusage(
            builder=cert,
            digital_signature=True,
            key_encipherment=True,
            critical=True)
        cert = build_x509.add_extended_key_useage(
            builder=cert, server=True)
        cert = build_x509.add_sign(cert, ca_key)
        cert = utils.convert_instance_to_pem(cert)
        key = utils.convert_instance_to_pem(key, cert_password)
        csr = utils.convert_instance_to_pem(csr)
        self.end_entity_cert = cert
        self.end_entity_key = key
        self.end_entity_csr = csr
        self.prev_proc = 'end_entity'
        return cert, key, csr
    
    def make_client(
        self,
        *,
        ca_cert: bytes = None,
        ca_key: bytes = None,
        ca_key_password: Optional[str] = None,
        country_name: Optional[str] = None,
        state_or_province_name: Optional[str] = None,
        locality_name: Optional[str] = None,
        organization_name: Optional[str] = None,
        organization_unit_name: Optional[str] = None,
        common_name: Optional[str] = 'user name',
        email_address: Optional[str] = None,
        cert_expire_days: int = 30,
        cert_key_password: str = None
    ):
        """
        client certificate
        """
        ca_cert = utils.validate_cert(ca_cert, self.ca_cert)
        ca_key = utils.validate_key(ca_key, self.ca_key, ca_key_password)
        key: rsa.RSAPrivateKey = self.make_private_key()
        csr: x509.CertificateSigningRequestBuilder = build_x509.make_csr(
            key=key,
            country_name=country_name,
            state_or_province_name=state_or_province_name,
            locality_name=locality_name,
            organization_name=organization_name,
            organization_unit_name=organization_unit_name,
            common_name=common_name,
            email_address=email_address,
            san=None)
        cert = build_x509.make_base_certificate(
            cert_type='casign',
            ca_cert=ca_cert,
            csr=csr,
            key=key,
            cert_expire_days=cert_expire_days)
        cert = build_x509.add_subject_key_identifier(
            builder=cert, publick_key=key.public_key())
        cert = build_x509.add_keyusage(
            builder=cert,
            digital_signature=True,
            key_encipherment=True,
            critical=True)
        cert = build_x509.add_extended_key_useage(
            builder=cert, client=True)
        cert = build_x509.add_sign(cert, ca_key)
        cert = utils.convert_instance_to_pem(cert)
        key = utils.convert_instance_to_pem(key, cert_key_password)
        csr = utils.convert_instance_to_pem(csr)
        self.end_entity_cert = cert
        self.end_entity_key = key
        self.end_entity_csr = csr
        self.prev_proc = 'end_entity'
        return cert, key, csr
    
    def make_pkcs12(
        self,
        *,
        ca_cert: bytes = None,
        client_cert: bytes = None,
        client_key: bytes = None,
        certificate_name: str = "client certificate",
        password: Optional[str] = None,
    ) -> bytes:
        """make pkcs12
        """
        ca_cert = utils.validate_cert(ca_cert, self.ca_cert)
        client_cert = utils.validate_cert(client_cert, self.end_entity_cert)
        client_key = utils.validate_key(client_key, self.end_entity_key)
        if isinstance(ca_cert, x509.Certificate) and \
            isinstance(client_cert, x509.Certificate) and \
                isinstance(client_key, rsa.RSAPrivateKey):
            if password:
                set_encryption = serialization.BestAvailableEncryption(password.encode())
            else:
                set_encryption = serialization.NoEncryption()

            pkcs12_data_binary = pkcs12.serialize_key_and_certificates(
                name=certificate_name.encode(),
                key=client_key,
                cert=client_cert,
                cas=[ca_cert],
                encryption_algorithm=set_encryption
            )
            self.pkcs12 = pkcs12_data_binary
            self.prev_proc = 'pkcs12'
            return pkcs12_data_binary
