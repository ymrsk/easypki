try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal
from typing import Optional, List
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import ipaddress
import re
from easypki import utils


def make_csr(
    key: rsa.RSAPrivateKey,
    country_name: Optional[str] = None,
    state_or_province_name: Optional[str] = None,
    locality_name: Optional[str] = None,
    organization_name: Optional[str] = None,
    organization_unit_name: Optional[str] = None,
    common_name: Optional[str] = None,
    email_address: Optional[str] = None,
    san: List[str] = None
) -> x509.CertificateSigningRequest:
    """Make Certificate Signing Request
    """
    if not common_name:
        raise ValueError('Please enter a value for common name.')
    csr_builder = x509.CertificateSigningRequestBuilder()
    subject = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name) if country_name is not None else None,
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name)if state_or_province_name is not None else None,
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name) if locality_name is not None else None,
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name) if organization_name is not None else None,
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit_name) if organization_unit_name is not None else None,
        x509.NameAttribute(NameOID.COMMON_NAME, common_name) if common_name is not None else None,
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address) if email_address is not None else None,
    ]
    subject = list(filter(None, subject))
    csr_builder = csr_builder.subject_name(x509.Name(subject))
    if san:
        csr_builder = add_subject_alternative_name(
            builder=csr_builder,
            san=san
        )
    return add_sign(csr_builder, key)


def make_crl(
    crl_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    expire_cert: x509.Certificate,
    expire_date: int = 1,
    effective_date: int = 2,
    crl_cert: x509.CertificateRevocationList = None,
):
    crl_builder = x509.CertificateRevocationListBuilder()
    common_name = utils.extract_rootca_name(ca_cert)
    crl_builder: x509.CertificateRevocationListBuilder = crl_builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))
    dt = datetime.datetime.utcnow()
    crl_builder = crl_builder.last_update(dt)
    expire_date = datetime.timedelta(expire_date)
    crl_builder = crl_builder.next_update(dt + expire_date)
    # make revoked crl
    # Add registered crl certificate
    if crl_cert:
        for r in crl_cert:
            crl_builder = crl_builder.add_revoked_certificate(r)
    # Add new crl certificate
    revoked_cert = x509.RevokedCertificateBuilder()
    epired_serial = expire_cert.serial_number
    revoked_cert = revoked_cert.serial_number(epired_serial)
    effective_date = datetime.timedelta(effective_date)
    revoked_cert = revoked_cert.revocation_date(dt + effective_date)
    revoked_cert = revoked_cert.build()
    cert = crl_builder.add_revoked_certificate(revoked_cert)
    crl = cert.sign(
        crl_key, algorithm=hashes.SHA256()
    )
    return crl


def make_base_certificate(
    cert_type: Literal['casign', 'selfsign'],
    ca_cert: Optional[x509.Certificate],
    csr: x509.CertificateSigningRequest,
    key: rsa.RSAPrivateKey,
    cert_expire_days: int,
) -> x509.CertificateBuilder:
    """Make x509.v1 Certificate
    """
    if not isinstance(cert_expire_days, int):
        raise ValueError('cert_expire_days input value int.')
    if cert_type == 'selfsign':
        issuer_name = csr.subject
    elif cert_type == 'casign':
        issuer_name = ca_cert.issuer
    else:
        raise ValueError('')
    cert = x509.CertificateBuilder()
    cert = cert.subject_name(csr.subject)
    cert = cert.issuer_name(issuer_name)
    cert = cert.public_key(key.public_key())
    cert = cert.serial_number(x509.random_serial_number())
    cert = cert.not_valid_before(datetime.datetime.utcnow())
    cert = cert.not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=cert_expire_days)
    )
    return cert


######################################
# certificate x509 v3 extensions
######################################


def add_subject_alternative_name(
    builder: x509.CertificateSigningRequestBuilder,
    san: List[str]
):
    if san is not None:
        san_list = []
        for san_value in san:
            if isinstance(san_value, str):
                try:
                    ip = ipaddress.ip_address(san_value)
                    san_list.append(x509.IPAddress(ip))
                except BaseException:
                    search = r'^([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$'
                    if re.match(search, san_value):
                        san_list.append(x509.DNSName(san_value))
                    pass
        return builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )


def add_extended_key_useage(
    builder: x509.CertificateBuilder,
    server=False,
    client=False,
    code=False,
    email=False,
    time=False,
    ocsp=False,
    critical=False
):
    extended_key_usage_lists = [
        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH if server is True else None,
        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH if client is True else None,
        x509.oid.ExtendedKeyUsageOID.CODE_SIGNING if code is True else None,
        x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION if email is True else None,
        x509.oid.ExtendedKeyUsageOID.TIME_STAMPING if time is True else None,
        x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING if ocsp is True else None,
    ]
    extended_key_usage_lists = list(filter(None, extended_key_usage_lists))
    return builder.add_extension(
        x509.ExtendedKeyUsage(extended_key_usage_lists),
        critical=critical
    )


def add_subject_key_identifier(
    builder: x509.CertificateBuilder,
    publick_key: rsa.RSAPrivateKey,
    critical: str = False
):
    return builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(publick_key),
        critical=critical
    )


def add_keyusage(
    builder: x509.CertificateBuilder,
    digital_signature=False,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False,
    critical=False
):
    return builder.add_extension(
        x509.KeyUsage(
            digital_signature=digital_signature,
            content_commitment=content_commitment,
            key_encipherment=key_encipherment,
            data_encipherment=data_encipherment,
            key_agreement=key_agreement,
            key_cert_sign=key_cert_sign,
            crl_sign=crl_sign,
            encipher_only=encipher_only,
            decipher_only=decipher_only
        ),
        critical=critical
    )


def add_basic_constraints(
    builder: x509.CertificateSigningRequestBuilder,
    is_ca: bool = False,
    path_length: int = 0,
    critical: bool = False
):
    return builder.add_extension(
        x509.BasicConstraints(
            ca=is_ca,
            path_length=path_length
        ),
        critical=critical
    )


def add_sign(
    builder: x509.CertificateSigningRequestBuilder,
    private_key: rsa.RSAPrivateKey,
    algorithm=hashes.SHA256()
):
    return builder.sign(private_key, algorithm)
