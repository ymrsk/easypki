# easypki

Build a Private Certificate Authority (PKI).


### Feature

- Issuing a CA certificate
- Issuing a server certificate
- Issuing a client certificate
- Issuing a pkcs12 file containing the client certificate and CA certificate
- Issuance of CRL certificate

### Setup

```shell
pip install easypki
```

### How to use

#### Certificate creation

```python
# module import
from easypki import pki

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
    san=['192.168.1.1', '*.example.com', 'example.net']
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
    expire_cert=server_cert,
    expire_date=7,
    crl_cert=crl_cert,
    ca_cert=ca_cert,
)


# save file
# 格納した変数とファイル名を指定してください
with open('ca_cert.pem','wb') as f:
    f.write(ca_cert)
```

Variables output from the instance method are saved in pem data format, so they can be saved as they are.

The certificate is also stored in the instance variable.
Therefore, you can also create it as follows.

```python
    prvpki = pki.BuildPKI()
    ca_cert, ca_key, ca_csr = prvpki.make_ca(
        common_name='Private RootCA'
    )
    server_cert, server_key, server_csr = prvpki.make_server(
        common_name='example.com'
    )
    client_cert, client_key, client_csr = prvpki.make_client()

    pkcs12 = prvpki.make_pkcs12()
```

If you already have a CA certificate and CA key created
It can also be created as follows.

```python
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
```



