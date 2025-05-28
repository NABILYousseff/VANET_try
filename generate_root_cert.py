from ITS.certs_util import build_root_ca_cert
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pathlib import Path

# 1. Generate EC key
root_key = ec.generate_private_key(ec.SECP256R1())
root_cert_bytes = build_root_ca_cert(root_key, subject_name="ROOT_CA")

Path("ca").mkdir(exist_ok=True)

# 2. Save ETSI Root CA cert (ASN.1 DER)
with open("ca/root_ca.cert", "wb") as f:
    f.write(root_cert_bytes)

# 3. Save Private Key (PEM)
with open("ca/root_ca.key.pem", "wb") as f:
    f.write(root_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

# 4. Optional: Save Public Key (PEM)
with open("ca/root_ca.pub.pem", "wb") as f:
    f.write(root_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("ETSI-format Root CA cert and keys saved in ./ca/")
