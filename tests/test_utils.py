from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from easypki import utils
import os
from datetime import datetime
import uuid
import time


def test_cert_convert_instance_to_pem(generate_test_ca_cert_instance):
    crt, key, csr = generate_test_ca_cert_instance
    crt: x509.Certificate = crt
    pem = utils.convert_instance_to_pem(crt)
    assert isinstance(pem, bytes)


def test_csr_convert_instance_to_pem(generate_test_ca_cert_instance):
    crt, key, csr = generate_test_ca_cert_instance
    csr: x509.Certificate = csr
    pem = utils.convert_instance_to_pem(csr)
    assert isinstance(pem, bytes)


def test_key_nopass_convert_instance_to_pem(generate_test_ca_cert_instance):
    crt, key, csr = generate_test_ca_cert_instance
    key: x509.Certificate = key
    pem = utils.convert_instance_to_pem(key)
    assert isinstance(pem, bytes)


def test_key_pass_convert_instance_to_pem(generate_test_ca_cert_instance):
    crt, key, csr = generate_test_ca_cert_instance
    key: x509.Certificate = key
    pem = utils.convert_instance_to_pem(key, "test")
    assert isinstance(pem, bytes)


def test_cert_convert_pem_to_instance(generate_test_ca_cert_pem):
    cert, key, csr = generate_test_ca_cert_pem
    cert = utils.convert_pem_to_instance(cert)
    assert isinstance(cert, x509.Certificate)


def test_csr_convert_pem_to_instance(generate_test_ca_cert_pem):
    cert, key, csr = generate_test_ca_cert_pem
    csr = utils.convert_pem_to_instance(csr)
    assert isinstance(csr, x509.CertificateSigningRequest)


def test_key_nopass_convert_pem_to_instance(generate_test_ca_cert_pem):
    cert, key, csr = generate_test_ca_cert_pem
    key = utils.convert_pem_to_instance(key)
    assert isinstance(key, rsa.RSAPrivateKey)


def test_key_pass_convert_pem_to_instance(generate_test_key_pass_pem):
    result = utils.convert_pem_to_instance(generate_test_key_pass_pem, "test")
    assert isinstance(result, rsa.RSAPrivateKey)


def test_get_entity_ca_point_list():
    assert True


def test_convert_space_to_underscore():
    result = utils.convert_space_to_underscore("test test")
    assert "test_test" == result


def test_extract_rootca_name(generate_test_base_client_fullset_instance):
    ca_crt, ca_key, ca_csr, client_crt, client_key, client_csr, pkcs12 = generate_test_base_client_fullset_instance
    result = utils.extract_rootca_name(ca_crt)
    assert result == "Private RootCA"


def test_extract_certificate_expire_days(generate_test_base_client_fullset_instance):
    ca_crt, ca_key, ca_csr, client_crt, client_key, client_csr, pkcs12 = generate_test_base_client_fullset_instance
    result = utils.extract_certificate_expire_days(ca_crt)
    tdatetime = datetime.strptime(result, '%Y-%m-%d %H:%M:%S')
    assert isinstance(tdatetime, datetime)


def test_make_directory_absolute_path_(tmpdir):
    result = str(uuid.uuid4())
    dir_name = result.replace("-", "")
    dir_path = os.path.join(tmpdir, dir_name)
    utils.make_directory(dir_path)


def test_make_directory_relative_path():
    result = str(uuid.uuid4())
    dir_name = result.replace("-", "")
    utils.make_directory(dir_name)
    time.sleep(1)
    os.rmdir(dir_name)


def test_verify_cert_key(generate_test_ca_cert_instance):
    cert, key, csr = generate_test_ca_cert_instance
    assert utils.verify_cert_key(cert, key)
