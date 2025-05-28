from base64 import decode
from pprint import pprint
from certs_util import (
    build_root_ca_cert,
    build_enrollment_cert,
    verify_cert_signature,
    spec
)
from cryptography.hazmat.primitives.asymmetric import ec

# 1. Generate issuer (LTCA) key and cert
ltca_key = ec.generate_private_key(ec.SECP256R1())
ltca_cert = build_root_ca_cert(
    ltca_key, subject_name="LTCA_ROOT")  # self-signed for now

# 2. Generate a vehicle key and LTC using LTCA
veh_key = ec.generate_private_key(ec.SECP256R1())
ltc = build_enrollment_cert(
    subject_pub=veh_key.public_key(),
    issuer_cert_bytes=ltca_cert,
    issuer_priv=ltca_key,
    subject_name="Vehtest"
)
decoded = spec.decode("CertificateAlias", ltc)
pprint(decoded)

# Verify LTC
ltca_pub = ltca_key.public_key()
is_valid = verify_cert_signature(ltc, ltca_pub)

print(" LTC Signature Valid!" if is_valid else " LTC Signature INVALID")
