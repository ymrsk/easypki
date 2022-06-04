from easypki import pki
from easypki import utils
import pytest
import os


def test_build_pki():
    prvpki = pki.BuildPKI()
    prvpki.make_ca()
    
    prvpki.make_server()
    prvpki.make_crl()
    
    prvpki.make_client()
    prvpki.make_crl()

    prvpki.make_pkcs12()
    del prvpki


def test_make_server(tmpdir):
    prvpki = pki.BuildPKI()
    ca_cert, ca_key, ca_csr = prvpki.make_ca()
    server_cert, server_key, server_csr = prvpki.make_server(
        ca_cert=ca_cert,
        ca_key=ca_key,
    )
    with open(os.path.join(tmpdir, 'server_cert.crt'), 'wb') as f:
        f.write(server_cert)
    with open(os.path.join(tmpdir, 'server_key.key'), 'wb') as f:
        f.write(server_key)
    server_cert_ins = utils.convert_pem_to_instance(server_cert)
    ca_key = utils.convert_pem_to_instance(ca_key)
    assert utils.verify_cert_key(server_cert_ins, ca_key)


def test_make_client():
    prvpki = pki.BuildPKI()
    ca_cert, ca_key, ca_csr = prvpki.make_ca()
    client_cert, client_key, client_csr = prvpki.make_client(
        ca_cert=ca_cert,
        ca_key=ca_key,
    )
    client_cert = utils.convert_pem_to_instance(client_cert)
    ca_key = utils.convert_pem_to_instance(ca_key)
    assert utils.verify_cert_key(client_cert, ca_key)


def test_make_pkcs12():
    prvpki = pki.BuildPKI()
    ca_cert, ca_key, ca_csr = prvpki.make_ca()
    client_cert, client_key, client_csr = prvpki.make_client(
        ca_cert=ca_cert,
        ca_key=ca_key,
    )
    pkcs12 = prvpki.make_pkcs12(
        ca_cert=ca_cert,
        client_cert=client_cert,
        client_key=client_key
    )
    print(pkcs12)
    assert True


def test_make_crl_new_create(tmpdir):
    prvpki = pki.BuildPKI()
    ca_cert, ca_key, ca_csr = prvpki.make_ca()
    server_cert, server_key, server_csr = prvpki.make_server(
        ca_cert=ca_cert,
        ca_key=ca_key,
    )
    crl, key = prvpki.make_crl(
        end_entity_cert=server_cert,
        ca_cert=ca_cert
    )
    with open(os.path.join(tmpdir, 'crl.crl'), 'wb') as f:
        f.write(crl)
    crl = utils.convert_pem_to_instance(crl)
    key = utils.convert_pem_to_instance(key)
    assert True


def test_make_crl_repeat(tmpdir):
    prvpki = pki.BuildPKI()
    ca_cert, ca_key, ca_csr = prvpki.make_ca()
    server_cert1, server_key, server_csr = prvpki.make_server(
        common_name='example.com',
        ca_cert=ca_cert,
        ca_key=ca_key,
    )
    crl, key = prvpki.make_crl(
        end_entity_cert=server_cert1,
        ca_cert=ca_cert
    )
    server_cert2, server_key, server_csr = prvpki.make_server(
        common_name='example.net',
        ca_cert=ca_cert,
        ca_key=ca_key,
    )
    crl, key = prvpki.make_crl(
        crl_cert=crl,
        crl_key=key,
        end_entity_cert=server_cert2,
        ca_cert=ca_cert
    )
    print(tmpdir)
    with open(os.path.join(tmpdir, 'crl.crl'), 'wb') as f:
        f.write(crl)
    with open(os.path.join(tmpdir, 'server1.crt'), 'wb') as f:
        f.write(server_cert1)
    with open(os.path.join(tmpdir, 'server2.crt'), 'wb') as f:
        f.write(server_cert2)
    assert True


def test_readme_one(tmpdir):
    # make instance
    private_pki = pki.BuildPKI()

    # make ca cert
    ca_cert, ca_key, ca_csr = private_pki.make_ca(
        country_name='JP',
        organization_name='Example Company',
        common_name='Private RootCA',
        cert_expire_days=36500
    )

    # make server cert
    server_cert, server_key, server_csr = private_pki.make_server(
        ca_cert=ca_cert,
        ca_key=ca_key,
        common_name='example.com',
        san=['192.168.1.1', '*.example.com', 'example.net'],
        cert_expire_days=365
    )

    # make client cert
    client_cert, client_key, client_csr = private_pki.make_client(
        ca_cert=ca_cert,
        ca_key=ca_key,
        common_name='user name',
        email_address='admin@example.com',
        cert_expire_days=365
    )

    # make pkcs12 data
    pkcs12 = private_pki.make_pkcs12(
        ca_cert=ca_cert,
        client_cert=client_cert,
        client_key=client_key
    )

    # make crl
    crl_cert, crl_key = private_pki.make_crl(
        end_entity_cert=server_cert,
        expire_date=7,
        ca_cert=ca_cert,
    )
    print(pkcs12)


def test_readme_two(tmpdir):
    prvpki = pki.BuildPKI()
    ca_cert, ca_key, ca_csr = prvpki.make_ca(
        common_name='Private RootCA'
    )
    server_cert, server_key, server_csr = prvpki.make_server(
        common_name='example.com'
    )
    client_cert, client_key, client_csr = prvpki.make_client()

    pkcs12 = prvpki.make_pkcs12()
    print(pkcs12)


def test_readme_three(tmpdir):
    prvca = pki.BuildPKI()
    ca_cert, ca_key, ca_csr = prvca.make_ca(
        common_name='Private RootCA'
    )
    del prvca
    
    prvpki = pki.BuildPKI(
        ca_cert=ca_cert,
        ca_key=ca_key
    )
    server_cert, server_key, server_csr = prvpki.make_server(
        common_name='example.com'
    )
    client_cert, client_key, client_csr = prvpki.make_client()

    pkcs12 = prvpki.make_pkcs12()
    print(pkcs12)


params = {
    'pki_1': (
        {'ca': {
            'country_name': 'JP',
            'state_or_province_name': 'Tokyo',
            'locality_name': 'Shibuya-ku',
            'organization_name': 'example company',
            'common_name': 'Private RootCA',
            'email_address': 'admin@example.com',
            'cert_expire_days': 365000
        }},
        {'server': {
            'country_name': 'US',
            'state_or_province_name': 'Tokyo',
            'locality_name': 'Shibuya-ku',
            'organization_name': 'example company',
            'common_name': 'www.example.com',
            'email_address': 'admin@example.com',
            'san': ['www1.example.com', 'www2.example.com', '192.168.1.1', '10.1.1.1'],
            'cert_expire_days': 365
                
        }},
        {'client': {
            'country_name': 'US',
            'state_or_province_name': 'Tokyo',
            'locality_name': 'Shibuya-ku',
            'organization_name': 'example company',
            'common_name': 'www.example.com',
            'email_address': 'admin@example.com',
            'cert_expire_days': 30
        }},
        {'pkcs12': {
            'password': 'test',
            'certificate_name': 'test_a'
        }},
        {'save_file': {
            'file_prefix': 'test',
            'password': 'test',
            'end_entity_dir_name': 'end_entity_dir_name'
        }}
    )
}


@pytest.mark.parametrize(
    'cert_ca, cert_server, cert_client, pkcs12, save_file',
    list(params.values()), ids=list(params.keys()))
def test_build_pki_fulla(tmpdir, cert_ca, cert_server, cert_client, pkcs12, save_file):
    print(tmpdir)
    print(cert_ca)
    print(cert_server)
    print(cert_client)
    print(pkcs12)
    print(save_file)
    assert True
