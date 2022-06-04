from easypki.build_rsa import make_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

params = [512, 1024, 2048, 4096]


@pytest.mark.parametrize("key_size", params)
def test_make_private_key(key_size):
    key_instance = make_private_key(key_size)
    assert isinstance(key_instance, rsa.RSAPrivateKey)
