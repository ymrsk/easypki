from typing import Union, Optional
import os
import re
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from easypki import build_rsa


def convert_instance_to_pem(
    instance: Union[x509.Certificate, x509.CertificateSigningRequest, rsa.RSAPrivateKey, x509.CertificateRevocationList],
    password: Optional[str] = None
):
    if isinstance(instance, x509.Certificate):
        return instance.public_bytes(serialization.Encoding.PEM)
    elif isinstance(instance, x509.CertificateSigningRequest):
        return instance.public_bytes(serialization.Encoding.PEM)
    elif isinstance(instance, rsa.RSAPrivateKey):
        if password:
            set_password = serialization.BestAvailableEncryption(password.encode())
        else:
            set_password = serialization.NoEncryption()
        return instance.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=set_password
        )
    elif isinstance(instance, x509.CertificateRevocationList):
        return instance.public_bytes(serialization.Encoding.PEM)
    else:
        raise TypeError('instance Type error')


def convert_pem_to_instance(
    pem: bytes,
    password: str = None
) -> x509.Certificate:
    if re.match(b'-----BEGIN CERTIFICATE-----', pem):
        instance = x509.load_pem_x509_certificate(pem)
        if isinstance(instance, x509.Certificate):
            return instance
    elif re.match(b'-----BEGIN CERTIFICATE REQUEST-----', pem):
        instance = x509.load_pem_x509_csr(pem)
        if isinstance(instance, x509.CertificateSigningRequest):
            return instance
    elif re.match(b'-----BEGIN RSA PRIVATE KEY-----', pem):
        if password:
            set_password = password.encode()
        elif not password:
            set_password = None
        instance = serialization.load_pem_private_key(pem, set_password)
        if isinstance(instance, rsa.RSAPrivateKey):
            return instance
    elif re.match(b'-----BEGIN X509 CRL-----', pem):
        instance = x509.load_pem_x509_crl(pem)
        if isinstance(instance, x509.CertificateRevocationList):
            return instance
    else:
        return None


def load_pem_file(
    file_path: str,
    password: str = None
) -> Union[x509.Certificate, x509.CertificateSigningRequest, x509.CertificateRevocationList, rsa.RSAPrivateKey]:
    with open(file_path, "rb") as f:
        pem = f.read()
        return convert_pem_to_instance(pem=pem, password=password)


def convert_space_to_underscore(string: str):
    return string.replace(' ', '_')


def extract_rootca_name(instance: x509.Certificate) -> str:
    basic_const = instance.extensions.get_extension_for_class(x509.BasicConstraints)
    if basic_const.value.ca is True:
        for attribute in instance.subject:
            if attribute.oid.dotted_string == '2.5.4.3':
                return attribute.value
    return None


def extract_certificate_expire_days(
    instance: x509.Certificate
) -> str:
    if isinstance(instance, x509.Certificate):
        return str(instance.not_valid_before)


def extract_crl_list(crl: x509.CertificateRevocationList):
    pass


def make_directory(dir_name: str) -> None:
    if os.path.isabs(dir_name):
        current_path = os.getcwd()
        dir_path = os.path.join(current_path, dir_name)
    else:
        dir_path = dir_name
    try:
        os.makedirs(dir_path)
    except FileExistsError as e:
        raise FileExistsError(e)
    

def verify_cert_key(cert: x509.Certificate, key: rsa.RSAPrivateKey):
    publick_key = key.public_key()
    try:
        publick_key.verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm
        )
    except BaseException:
        return False
    return True


def validate_cert(
    pem_variable: bytes,
    instance_variable: x509.Certificate,
):
    if pem_variable:
        return convert_pem_to_instance(pem_variable)
    if instance_variable:
        return convert_pem_to_instance(instance_variable)
    else:
        raise ValueError('Please store the certificate')


def validate_key(
    pem_variable: Optional[bytes],
    instance_variable: Optional[rsa.RSAPrivateKey],
    key_password: str = None
):
    if pem_variable:
        return convert_pem_to_instance(pem_variable, key_password)
    if instance_variable:
        return convert_pem_to_instance(instance_variable, key_password)
    else:
        return build_rsa.make_private_key(key_size=2048)
