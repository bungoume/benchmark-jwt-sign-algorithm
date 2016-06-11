from benchmarker import Benchmarker

import jwt
import random
import subprocess


def gen_secret(length=86):
    chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    return ''.join(random.choice(chars) for x in range(length))


keys = {}

# Generate RSA key
for key_length in ["512", "1024", "2048", "3072", "4096"]:
    priv_fn = "rsa{}_priv.pem".format(key_length)
    pub_fn = "rsa{}_pub.pem".format(key_length)

    # private key
    subprocess.call((
        "openssl1 genpkey -algorithm rsa "
        "-pkeyopt rsa_keygen_pubexp:65537 -pkeyopt rsa_keygen_bits:{} "
        "-outform pem -out {}").format(key_length, priv_fn), shell=True)
    # public key
    subprocess.call("openssl1 rsa -in {} -pubout -out {}".format(priv_fn, pub_fn), shell=True)
    with open(priv_fn)as f:
        keys[priv_fn] = f.read()
    with open(pub_fn) as f:
        keys[pub_fn] = f.read()


# Generate ECDSA key
for curve_name in ["secp224r1", "prime256v1", "secp384r1", "secp521r1"]:
    priv_fn = "{}_priv.pem".format(curve_name)
    pub_fn = "{}_pub.pem".format(curve_name)

    # private key
    subprocess.call((
        "openssl1 genpkey -algorithm EC "
        "-pkeyopt ec_paramgen_curve:{} -pkeyopt ec_param_enc:named_curve "
        "-outform pem -out {}").format(curve_name, priv_fn), shell=True)
    subprocess.call("openssl1 ec -in {} -pubout -out {}".format(priv_fn, pub_fn), shell=True)
    with open(priv_fn)as f:
        keys[priv_fn] = f.read()
    with open(pub_fn) as f:
        keys[pub_fn] = f.read()


token = {
    "iss": "token.example.com",
    # "aud": "client_id",
    "sub": "user_id",
    "exp": 1500000000,
    "iat": 1000000000,
    "jti": "ABCDEF",
}


loop = 10000
with Benchmarker(width=30) as bench:
    @bench("encode-hs256-5")
    def _(bm):
        key = gen_secret(5)
        for _ in range(loop):
            jwt.encode(token, key, algorithm="HS256")

    @bench("decode-hs256-5")
    def _(bm):
        key = gen_secret(5)
        encoded = jwt.encode(token, key, algorithm='HS256')
        for _ in range(loop):
            jwt.decode(encoded, key=key, algorithms=["HS256"])

    @bench("encode-hs256-86")
    def _(bm):
        key = gen_secret(86)
        for _ in range(loop):
            jwt.encode(token, key, algorithm="HS256")

    @bench("decode-hs256-86")
    def _(bm):
        key = gen_secret(86)
        encoded = jwt.encode(token, key, algorithm='HS256')
        for _ in range(loop):
            jwt.decode(encoded, key=key, algorithms=["HS256"])

    @bench("encode-rs256-rsa512")
    def _(bm):
        for _ in range(loop):
            jwt.encode(token, keys["rsa512_priv.pem"], algorithm="RS256")

    @bench("decode-rs256-rsa512")
    def _(bm):
        encoded = jwt.encode(token, keys["rsa512_priv.pem"], algorithm='RS256')
        for _ in range(loop):
            jwt.decode(encoded, key=keys["rsa512_pub.pem"], algorithms=["RS256"])

    @bench("encode-rs256-rsa1024")
    def _(bm):
        for _ in range(loop):
            jwt.encode(token, keys["rsa1024_priv.pem"], algorithm="RS256")

    @bench("decode-rs256-rsa1024")
    def _(bm):
        encoded = jwt.encode(token, keys["rsa1024_priv.pem"], algorithm='RS256')
        for _ in range(loop):
            jwt.decode(encoded, key=keys["rsa1024_pub.pem"], algorithms=["RS256"])

    @bench("encode-rs256-rsa2048")
    def _(bm):
        for _ in range(loop):
            jwt.encode(token, keys["rsa2048_priv.pem"], algorithm="RS256")

    @bench("decode-rs256-rsa2048")
    def _(bm):
        encoded = jwt.encode(token, keys["rsa2048_priv.pem"], algorithm='RS256')
        for _ in range(loop):
            jwt.decode(encoded, key=keys["rsa2048_pub.pem"], algorithms=["RS256"])

    @bench("encode-rs256-rsa3072")
    def _(bm):
        for _ in range(loop):
            jwt.encode(token, keys["rsa3072_priv.pem"], algorithm="RS256")

    @bench("decode-rs256-rsa3072")
    def _(bm):
        encoded = jwt.encode(token, keys["rsa3072_priv.pem"], algorithm='RS256')
        for _ in range(loop):
            jwt.decode(encoded, key=keys["rsa3072_pub.pem"], algorithms=["RS256"])

    @bench("encode-rs256-rsa4096")
    def _(bm):
        for _ in range(loop):
            jwt.encode(token, keys["rsa4096_priv.pem"], algorithm="RS256")

    @bench("decode-rs256-rsa4096")
    def _(bm):
        encoded = jwt.encode(token, keys["rsa4096_priv.pem"], algorithm='RS256')
        for _ in range(loop):
            jwt.decode(encoded, key=keys["rsa4096_pub.pem"], algorithms=["RS256"])

    @bench("encode-es256-secp224r1")
    def _(bm):
        for _ in range(loop):
            jwt.encode(token, keys["secp224r1_priv.pem"], algorithm="ES256")

    @bench("decode-es256-secp224r1")
    def _(bm):
        encoded = jwt.encode(token, keys["secp224r1_priv.pem"], algorithm='ES256')
        for _ in range(loop):
            jwt.decode(encoded, key=keys["secp224r1_pub.pem"], algorithms=["ES256"])

    @bench("encode-es256-prime256v1")
    def _(bm):
        for _ in range(loop):
            jwt.encode(token, keys["prime256v1_priv.pem"], algorithm="ES256")

    @bench("decode-es256-prime256v1")
    def _(bm):
        encoded = jwt.encode(token, keys["prime256v1_priv.pem"], algorithm='ES256')
        for _ in range(loop):
            jwt.decode(encoded, key=keys["prime256v1_pub.pem"], algorithms=["ES256"])

    @bench("encode-es256-secp384r1")
    def _(bm):
        for _ in range(loop):
            jwt.encode(token, keys["secp384r1_priv.pem"], algorithm="ES256")

    @bench("decode-es256-secp384r1")
    def _(bm):
        encoded = jwt.encode(token, keys["secp384r1_priv.pem"], algorithm='ES256')
        for _ in range(loop):
            jwt.decode(encoded, key=keys["secp384r1_pub.pem"], algorithms=["ES256"])

    @bench("encode-es256-secp521r1")
    def _(bm):
        for _ in range(loop):
            jwt.encode(token, keys["secp521r1_priv.pem"], algorithm="ES256")

    @bench("decode-es256-secp521r1")
    def _(bm):
        encoded = jwt.encode(token, keys["secp521r1_priv.pem"], algorithm='ES256')
        for _ in range(loop):
            jwt.decode(encoded, key=keys["secp521r1_pub.pem"], algorithms=["ES256"])
