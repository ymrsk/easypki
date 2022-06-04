import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from easypki import build_x509
from easypki import build_rsa

params = [
    ("JP", "Tokyo", "Shibuya-ku", "example Inc", "example unit", "PrivateRootCA", None, None),
    (None, None, None, None, None, "example.com", None, None),
    (None, None, None, None, None, "example.com", None, ["192.168.1.1", "www.example.com"]),
]


@pytest.mark.parametrize(
    "country_n,state_or_province_n,locality_n,org_n,org_un,common_n,email,san",
    params
)
def test_make_csr(country_n, state_or_province_n, locality_n, org_n, org_un, common_n, email, san):
    key = build_rsa.make_private_key()
    csr: x509.CertificateSigningRequest = build_x509.make_csr(
        key,
        country_name=country_n,
        state_or_province_name=state_or_province_n,
        locality_name=locality_n,
        organization_name=org_n,
        organization_unit_name=org_un,
        common_name=common_n,
        email_address=email,
        san=san
    )
    cmn_n = csr.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)
    assert isinstance(csr, x509.CertificateSigningRequest)
    assert common_n == cmn_n[0].value


@pytest.mark.parametrize(
    "country_n,state_or_province_n,locality_n,org_n,org_un,common_n,email,san",
    params
)
def test_make_base_certificate_selfsign(
    country_n, state_or_province_n, locality_n, org_n, org_un, common_n, email, san
):
    key = build_rsa.make_private_key()
    csr = build_x509.make_csr(
        key,
        country_name=country_n,
        state_or_province_name=state_or_province_n,
        locality_name=locality_n,
        organization_name=org_n,
        organization_unit_name=org_un,
        common_name=common_n,
        email_address=email,
        san=san
    )
    cert = build_x509.make_base_certificate(cert_type='selfsign', ca_cert=None, csr=csr, key=key, cert_expire_days=30)
    assert isinstance(cert, x509.CertificateBuilder)


@pytest.mark.parametrize(
    "country_n,state_or_province_n,locality_n,org_n,org_un,common_n,email,san", params
)
def test_make_base_certificate_ca(
    generate_test_ca_cert_instance,
    country_n, state_or_province_n, locality_n, org_n, org_un, common_n, email, san
):
    ca_crt, _, _ = generate_test_ca_cert_instance
    key = build_rsa.make_private_key()
    csr = build_x509.make_csr(
        key,
        country_name=country_n,
        state_or_province_name=state_or_province_n,
        locality_name=locality_n,
        organization_name=org_n,
        organization_unit_name=org_un,
        common_name=common_n,
        email_address=email,
        san=san
    )
    cert = build_x509.make_base_certificate(cert_type='casign', ca_cert=ca_crt, csr=csr, key=key, cert_expire_days=30)
    assert isinstance(cert, x509.CertificateBuilder)


def test_make_crl(generate_test_base_cert_fullset_instance):
    key = build_rsa.make_private_key()
    ca_crt, ca_key, ca_csr, srv_crt, srv_key, srv_csr = generate_test_base_cert_fullset_instance
    crl = build_x509.make_crl(
        crl_key=key,
        ca_cert=ca_crt,
        expire_cert=srv_crt,
        expire_date=1,
        effective_date=0
    )
    assert isinstance(crl, x509.CertificateRevocationList)
    

san_list = [
    ["192.168.1.1"],
    ["192.168.1.1", "www.example.com"],
    ["192.168.1.1", "www.example.com", "*.example.com"],
    ["192.168.1.1", "www.example.com", "*.example.com", "example.net"]
]


@pytest.mark.parametrize(
    "san", san_list
)
def test_add_subject_alternative_name(generate_test_base_cert_instance, san):
    crt_builder, crt_key, ca_crt, ca_key = generate_test_base_cert_instance
    crt_builder = build_x509.add_subject_alternative_name(crt_builder, san)
    assert isinstance(crt_builder, x509.CertificateBuilder)


def test_add_extended_key_useage(generate_test_base_cert_instance):
    crt_builder, crt_key, ca_crt, ca_key = generate_test_base_cert_instance
    crt_builder = build_x509.add_extended_key_useage(crt_builder, server=True)
    assert isinstance(crt_builder, x509.CertificateBuilder)


def test_add_subject_key_identifier(generate_test_base_cert_instance):
    crt_builder, crt_key, ca_crt, ca_key = generate_test_base_cert_instance
    crt_builder: x509.CertificateBuilder = crt_builder
    crt_key: rsa.RSAPrivateKey = crt_key
    crt_builder = build_x509.add_subject_key_identifier(crt_builder, crt_key.public_key())
    assert isinstance(crt_builder, x509.CertificateBuilder)


def test_add_keyusage(generate_test_base_cert_instance):
    crt_builder, crt_key, ca_crt, ca_key = generate_test_base_cert_instance
    crt_builder: x509.CertificateBuilder = crt_builder
    crt_key: rsa.RSAPrivateKey = crt_key
    crt_builder = build_x509.add_keyusage(crt_builder, key_encipherment=True)
    assert isinstance(crt_builder, x509.CertificateBuilder)


def test_add_basic_constraints(generate_test_base_cert_instance):
    crt_builder, crt_key, ca_crt, ca_key = generate_test_base_cert_instance
    crt_builder: x509.CertificateBuilder = crt_builder
    crt_key: rsa.RSAPrivateKey = crt_key
    crt_builder = build_x509.add_basic_constraints(crt_builder, is_ca=True)
    assert isinstance(crt_builder, x509.CertificateBuilder)


def test_add_sign(generate_test_base_cert_instance):
    crt_builder, crt_key, ca_crt, ca_key = generate_test_base_cert_instance
    crt_builder: x509.CertificateBuilder = crt_builder
    crt_key: rsa.RSAPrivateKey = crt_key
    crt = build_x509.add_sign(crt_builder, crt_key)
    assert isinstance(crt, x509.Certificate)
