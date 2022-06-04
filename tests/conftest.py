import pytest
from cryptography import x509
from easypki import pki
from easypki import build_rsa, build_x509
from easypki import utils


@pytest.fixture(scope="function")
def generate_test_ca_cert_instance():
    """Create a PEM-formatted certificate and delete it when finished"""
    prv_pki = pki.BuildPKI()
    cert, key, csr = prv_pki.make_ca()
    cert = utils.convert_pem_to_instance(cert)
    key = utils.convert_pem_to_instance(key)
    csr = utils.convert_pem_to_instance(csr)
    yield cert, key, csr
    del prv_pki


@pytest.fixture(scope="function")
def generate_test_ca_cert_pem():
    """Create a PEM-formatted certificate and delete it when finished"""
    prv_pki = pki.BuildPKI()
    cert, key, csr = prv_pki.make_ca()
    yield cert, key, csr
    del prv_pki


@pytest.fixture(scope="function")
def generate_test_base_cert_instance():
    """generate test base instance"""
    prv_pki = pki.BuildPKI()
    ca_crt, ca_key, ca_csr = prv_pki.make_ca()
    crt_key = build_rsa.make_private_key()
    ca_crt = utils.convert_pem_to_instance(ca_crt)
    ca_key = utils.convert_pem_to_instance(ca_key)
    crt_csr: x509.CertificateSigningRequest = build_x509.make_csr(
        crt_key,
        country_name=None,
        state_or_province_name=None,
        locality_name=None,
        organization_name=None,
        organization_unit_name=None,
        common_name='example.com',
        email_address=None,
        san=None
    )
    crt_builder = build_x509.make_base_certificate(
        cert_type='casign',
        ca_cert=ca_crt,
        csr=crt_csr,
        key=crt_key,
        cert_expire_days=365
    )
    yield crt_builder, crt_key, ca_crt, ca_key
    del prv_pki


@pytest.fixture(scope="function")
def generate_test_base_cert_fullset_instance():
    prv_pki = pki.BuildPKI()
    ca_crt, ca_key, ca_csr = prv_pki.make_ca()
    srv_crt, srv_key, srv_csr = prv_pki.make_server()
    ca_crt = utils.convert_pem_to_instance(ca_crt)
    ca_key = utils.convert_pem_to_instance(ca_key)
    ca_csr = utils.convert_pem_to_instance(ca_csr)
    srv_crt = utils.convert_pem_to_instance(srv_crt)
    srv_key = utils.convert_pem_to_instance(srv_key)
    srv_csr = utils.convert_pem_to_instance(srv_csr)
    yield ca_crt, ca_key, ca_csr, srv_crt, srv_key, srv_csr
    del prv_pki


@pytest.fixture(scope="function")
def generate_test_base_client_fullset_instance():
    prv_pki = pki.BuildPKI()
    ca_crt, ca_key, ca_csr = prv_pki.make_ca()
    client_crt, client_key, client_csr = prv_pki.make_client()
    pkcs12 = prv_pki.make_pkcs12()
    ca_crt = utils.convert_pem_to_instance(ca_crt)
    ca_key = utils.convert_pem_to_instance(ca_key)
    ca_csr = utils.convert_pem_to_instance(ca_csr)
    client_crt = utils.convert_pem_to_instance(client_crt)
    client_key = utils.convert_pem_to_instance(client_key)
    client_csr = utils.convert_pem_to_instance(client_csr)
    yield ca_crt, ca_key, ca_csr, client_crt, client_key, client_csr, pkcs12
    del prv_pki


@pytest.fixture(scope="function")
def generate_test_key_nopass_pem():
    prvpki = pki.BuildPKI()
    crt, key, csr = prvpki.make_ca()
    key: x509.Certificate = key
    yield utils.convert_instance_to_pem(key)
    del prvpki


@pytest.fixture(scope="function")
def generate_test_key_pass_pem():
    prvpki = pki.BuildPKI()
    crt, key, csr = prvpki.make_ca()
    key = utils.convert_pem_to_instance(key)
    key: x509.Certificate = key
    yield utils.convert_instance_to_pem(key, "test")
    del prvpki
