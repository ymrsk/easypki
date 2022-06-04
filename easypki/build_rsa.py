from cryptography.hazmat.primitives.asymmetric import rsa

####################################################
# generate private key
####################################################


def make_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """generate private key

    Args:
        key_size (int, optional): キーサイズ 512/1024/2048/4096 デフォルト値 2048

    Returns:
        rsa.RSAPrivateKey instance
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key
