from benchmarker import Benchmarker

import jwt
import random
import subprocess
import uuid


def gen_secret(length=86):
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(random.choice(chars) for x in range(length))


keys = {}

# openssl = "/usr/local/Cellar/libressl/3.1.4/bin/openssl"
openssl = "/usr/local/Cellar/openssl@1.1/1.1.1g/bin/openssl"

# Generate RSA key
for key_length in ["512", "1024", "2048", "3072", "4096"]:
    priv_fn = f"rsa{key_length}_priv.pem"
    pub_fn = f"rsa{key_length}_pub.pem"

    # private key
    cmd = (
        f"{openssl} genpkey -algorithm RSA "
        "-pkeyopt rsa_keygen_pubexp:65537 "
        f"-pkeyopt rsa_keygen_bits:{key_length} "
        f"-outform pem -out {priv_fn}"
    )
    print(cmd)
    subprocess.call(cmd, shell=True)
    # public key
    subprocess.call(f"{openssl} pkey -in {priv_fn} -pubout -out {pub_fn}", shell=True)
    with open(priv_fn) as f:
        keys[priv_fn] = f.read()
    with open(pub_fn) as f:
        keys[pub_fn] = f.read()

# Generate RSA-PSS key(?)
priv_fn = "rsa2048_pss_priv.pem"
pub_fn = "rsa2048_pss_pub.pem"

# private key
cmd = (
    f"{openssl} genpkey -algorithm RSA-PSS "
    "-pkeyopt rsa_keygen_pubexp:65537 "
    "-pkeyopt rsa_keygen_bits:2048 "
    f"-outform pem -out {priv_fn}"
)
print(cmd)
subprocess.call(cmd, shell=True)
# public key
subprocess.call(f"{openssl} pkey -in {priv_fn} -pubout -out {pub_fn}", shell=True)
with open(priv_fn) as f:
    keys[priv_fn] = f.read()
with open(pub_fn) as f:
    keys[pub_fn] = f.read()

# Generate ECDSA key
for curve_name in ["secp224r1", "prime256v1", "secp256k1", "secp384r1", "secp521r1"]:
    priv_fn = f"{curve_name}_priv.pem"
    pub_fn = f"{curve_name}_pub.pem"

    # private key
    cmd = (
        f"{openssl} genpkey -algorithm EC "
        f"-pkeyopt ec_paramgen_curve:{curve_name} "
        "-pkeyopt ec_param_enc:named_curve "
        f"-outform pem -out {priv_fn}"
    )
    print(cmd)
    subprocess.call(cmd, shell=True)
    subprocess.call(f"{openssl} pkey -in {priv_fn} -pubout -out {pub_fn}", shell=True)
    with open(priv_fn) as f:
        keys[priv_fn] = f.read()
    with open(pub_fn) as f:
        keys[pub_fn] = f.read()

# Generate EdDSA key
for curve_name in ["ed25519", "ed448"]:
    priv_fn = f"{curve_name}_priv.pem"
    pub_fn = f"{curve_name}_pub.pem"

    # private key
    cmd = f"{openssl} genpkey -algorithm ED25519 -outform pem -out {priv_fn}"
    print(cmd)
    subprocess.call(cmd, shell=True)
    subprocess.call(f"{openssl} pkey -in {priv_fn} -pubout -out {pub_fn}", shell=True)
    with open(priv_fn) as f:
        keys[priv_fn] = f.read()
    with open(pub_fn) as f:
        keys[pub_fn] = f.read()


token = {
    "iss": "token.example.com",
    # "aud": "client_id",
    "sub": "user_id" + str(uuid.uuid4()),
    "exp": 1800000000,
    "iat": 1000000000,
    "jti": "ABCDEF",
    "given_name": "Jane",
    "family_name": "Doe",
    "gender": "female",
    "birthdate": "1970-01-01",
    "email": "janedoe@example.com",
    "picture": "http://example.com/janedoe/me.jpg",
}

# print(jwt.encode(token, keys["ed25519_priv.pem"], algorithm="EdDSA"))
# print(jwt.encode(token, keys["prime256v1_priv.pem"], algorithm="ES256"))

with Benchmarker(10000, width=30) as bench:

    @bench("sign-hs256-43")
    def _(bm):
        key = gen_secret(43)
        with bm:
            for _ in bm:
                jwt.encode(token, key, algorithm="HS256")

    @bench("verify-hs256-43")
    def _(bm):
        key = gen_secret(43)
        encoded = jwt.encode(token, key, algorithm="HS256")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=key, algorithms=["HS256"])

    @bench("sign-hs512-86")
    def _(bm):
        key = gen_secret(86)
        with bm:
            for _ in bm:
                jwt.encode(token, key, algorithm="HS512")

    @bench("verify-hs512-86")
    def _(bm):
        key = gen_secret(86)
        encoded = jwt.encode(token, key, algorithm="HS512")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=key, algorithms=["HS512"])

    @bench("sign-rs256-rsa512")
    def _(bm):
        for _ in bm:
            jwt.encode(token, keys["rsa512_priv.pem"], algorithm="RS256")

    @bench("verify-rs256-rsa512")
    def _(bm):
        encoded = jwt.encode(token, keys["rsa512_priv.pem"], algorithm="RS256")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=keys["rsa512_pub.pem"], algorithms=["RS256"])

    @bench("sign-rs256-rsa1024")
    def _(bm):
        for _ in bm:
            jwt.encode(token, keys["rsa1024_priv.pem"], algorithm="RS256")

    @bench("verify-rs256-rsa1024")
    def _(bm):
        encoded = jwt.encode(token, keys["rsa1024_priv.pem"], algorithm="RS256")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=keys["rsa1024_pub.pem"], algorithms=["RS256"])

    @bench("sign-rs256-rsa2048")
    def _(bm):
        for _ in bm:
            jwt.encode(token, keys["rsa2048_priv.pem"], algorithm="RS256")

    @bench("verify-rs256-rsa2048")
    def _(bm):
        encoded = jwt.encode(token, keys["rsa2048_priv.pem"], algorithm="RS256")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=keys["rsa2048_pub.pem"], algorithms=["RS256"])

    @bench("sign-rs512-rsa2048")
    def _(bm):
        for _ in bm:
            jwt.encode(token, keys["rsa2048_priv.pem"], algorithm="RS512")

    @bench("verify-rs512-rsa2048")
    def _(bm):
        encoded = jwt.encode(token, keys["rsa2048_priv.pem"], algorithm="RS512")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=keys["rsa2048_pub.pem"], algorithms=["RS512"])

    @bench("sign-ps256-rsa2048")
    def _(bm):
        for _ in bm:
            jwt.encode(token, keys["rsa2048_priv.pem"], algorithm="PS256")

    @bench("verify-ps256-rsa2048")
    def _(bm):
        encoded = jwt.encode(token, keys["rsa2048_priv.pem"], algorithm="PS256")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=keys["rsa2048_pub.pem"], algorithms=["PS256"])

    @bench("sign-rs256-rsa3072")
    def _(bm):
        for _ in bm:
            jwt.encode(token, keys["rsa3072_priv.pem"], algorithm="RS256")

    @bench("verify-rs256-rsa3072")
    def _(bm):
        encoded = jwt.encode(token, keys["rsa3072_priv.pem"], algorithm="RS256")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=keys["rsa3072_pub.pem"], algorithms=["RS256"])

    @bench("sign-rs256-rsa4096")
    def _(bm):
        for _ in bm:
            jwt.encode(token, keys["rsa4096_priv.pem"], algorithm="RS256")

    @bench("verify-rs256-rsa4096")
    def _(bm):
        encoded = jwt.encode(token, keys["rsa4096_priv.pem"], algorithm="RS256")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=keys["rsa4096_pub.pem"], algorithms=["RS256"])

    @bench("sign-es256-secp224r1")
    def _(bm):
        for _ in bm:
            jwt.encode(token, keys["secp224r1_priv.pem"], algorithm="ES256")

    @bench("verify-es256-secp224r1")
    def _(bm):
        encoded = jwt.encode(token, keys["secp224r1_priv.pem"], algorithm="ES256")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=keys["secp224r1_pub.pem"], algorithms=["ES256"])

    @bench("sign-es256-prime256v1")
    def _(bm):
        for _ in bm:
            jwt.encode(token, keys["prime256v1_priv.pem"], algorithm="ES256")

    @bench("verify-es256-prime256v1")
    def _(bm):
        encoded = jwt.encode(token, keys["prime256v1_priv.pem"], algorithm="ES256")
        with bm:
            for _ in bm:
                jwt.decode(
                    encoded, key=keys["prime256v1_pub.pem"], algorithms=["ES256"]
                )

    @bench("sign-es256-secp384r1")
    def _(bm):
        for _ in bm:
            jwt.encode(token, keys["secp384r1_priv.pem"], algorithm="ES256")

    @bench("verify-es256-secp384r1")
    def _(bm):
        encoded = jwt.encode(token, keys["secp384r1_priv.pem"], algorithm="ES256")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=keys["secp384r1_pub.pem"], algorithms=["ES256"])

    @bench("sign-es256-secp521r1")
    def _(bm):
        for _ in bm:
            jwt.encode(token, keys["secp521r1_priv.pem"], algorithm="ES256")

    @bench("verify-es256-secp521r1")
    def _(bm):
        encoded = jwt.encode(token, keys["secp521r1_priv.pem"], algorithm="ES256")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=keys["secp521r1_pub.pem"], algorithms=["ES256"])

    @bench("sign-eddsa-ed25519")
    def _(bm):
        for _ in bm:
            jwt.encode(token, keys["ed25519_priv.pem"], algorithm="EdDSA")

    @bench("verify-eddsa-ed25519")
    def _(bm):
        encoded = jwt.encode(token, keys["ed25519_priv.pem"], algorithm="EdDSA")
        with bm:
            for _ in bm:
                jwt.decode(encoded, key=keys["ed25519_pub.pem"], algorithms=["EdDSA"])
