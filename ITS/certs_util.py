import hashlib
import asn1tools
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature
import hashlib

# Compile ASN.1
spec = asn1tools.compile_files([
    'asn/Ieee1609Dot2BaseTypes.asn',
    'asn/Etsi_flattened.asn'
], 'per')


def build_enrollment_cert(subject_pub: ec.EllipticCurvePublicKey, issuer_cert_bytes: bytes, issuer_priv: ec.EllipticCurvePrivateKey, subject_name: str) -> bytes:
    """
    Builds an ETSI 103 097 enrollment certificate.

    param
    -----
        subject_pub : Public key of the subject.
        issuer_cert_bytes : DER-encoded certificate of the issuer.
        issuer_priv : Private key of the issuer.
        subject_name : Name of the subject, truncated to 32 bytes.
    return
    ------
        bytes : DER-encoded certificate.
    """
    now = int(time.time())

    hashed_issuer_cert = hashlib.sha256(issuer_cert_bytes).digest()[:8]
    tbs = {
        'version': 2,
        'signerInfo': ('certificateDigestSHA256', hashed_issuer_cert),
        'subjectInfo': {
            'subjectType': 'enrollment-credential',
            'subjectName': subject_name[:32]
        },
        'subjectAttributes': {
            'verificationKey': {
                'algorithm': 'ecdsa-nistp256-with-sha256',
                'key': ('uncompressed', {
                    'x': subject_pub.public_numbers().x.to_bytes(32, 'big'),
                    'y': subject_pub.public_numbers().y.to_bytes(32, 'big')
                })
            },
            'assuranceLevel': b'\x01',
            'itsList': ('its-aid-list', [36])  # CAM by default
        },
        'validityRestrictions': {
            'timeOfValidation': ('timeStartAndDuration', {
                'startValidity': now,
                # short-lived pseudonym (10 mins)
                'duration': ('seconds', 600)
            })
        }

    }

    tbs_encoded = spec.encode("ToBeSignedCertificateAlias", tbs)
    signature = issuer_priv.sign(tbs_encoded, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)
    r_bytes, s_bytes = r.to_bytes(32, 'big'), s.to_bytes(32, 'big')
    cert = {
        'tbs': tbs,
        'signature': {
            'r': ('x-coordinate-only', r_bytes),
            's': s_bytes
        }
    }

    return spec.encode("CertificateAlias", cert)


def build_pseudonym_cert(subject_pub: ec.EllipticCurvePublicKey, issuer_cert_bytes: bytes, issuer_priv: ec.EllipticCurvePrivateKey, subject_name="VEH_PSEUDONYM", linkage_value=None) -> bytes:
    """
    Builds an ETSI 103 097 pseudonym certificate.

    param
    -----
        subject_pub : Public key of the subject.
        issuer_cert_bytes : DER-encoded certificate of the issuer.
        issuer_priv : Private key of the issuer.
        subject_name : Name of the subject, truncated to 32 bytes.
        linkage_value : Optional linkage value to include in the certificate.
    return
    ------
    bytes : DER-encoded certificate.
    """
    now = int(time.time())

    hashed_issuer_cert = hashlib.sha256(issuer_cert_bytes).digest()[:8]
    tbs = {
        'version': 2,
        'signerInfo': ('certificateDigestSHA256', hashed_issuer_cert),
        'subjectInfo': {
            'subjectType': 'authorization-ticket',
            'subjectName': subject_name[:32]
        },
        'subjectAttributes': {
            'verificationKey': {
                'algorithm': 'ecdsa-nistp256-with-sha256',
                'key': ('uncompressed', {
                    'x': subject_pub.public_numbers().x.to_bytes(32, 'big'),
                    'y': subject_pub.public_numbers().y.to_bytes(32, 'big')
                })
            },
            'assuranceLevel': b'\x01',
            'itsList': ('its-aid-list', [36])  # CAM by default
        },
        'validityRestrictions': {
            'timeOfValidation': ('timeStartAndDuration', {
                'startValidity': now,
                # short-lived pseudonym (10 mins)
                'duration': ('seconds', 600)
            })
        }
    }

    # Add LV to subjectName or assuranceLevel as demo if needed
    if linkage_value is not None:
        # Truncate or encode LV into assuranceLevel (very optional/hacky)
        tbs['ld'] = linkage_value.to_bytes(32, 'big')

    # Sign
    tbs_encoded = spec.encode("ToBeSignedCertificateAlias", tbs)
    signature = issuer_priv.sign(tbs_encoded, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)

    cert = {
        'tbs': tbs,
        'signature': {
            'r': ('x-coordinate-only', r.to_bytes(32, 'big')),
            's': s.to_bytes(32, 'big')
        }
    }

    return spec.encode("CertificateAlias", cert)

def build_root_ca_cert(key: ec.EllipticCurvePrivateKey, subject_name="ROOT_CA") -> bytes:
    """
    Builds a self-signed root CA certificate.

    param
    -----
        key : Private key of the root CA.
        subject_name : Name of the root CA, truncated to 32 bytes.
    return
    ------
        bytes : DER-encoded root CA certificate.
    """
    now = int(time.time())
    tbs = {
        'version': 2,
        'signerInfo': ('self', None),
        'subjectInfo': {
            'subjectType': 'root-ca',
            'subjectName': subject_name[:32]
        },
        'subjectAttributes': {
            'verificationKey': {
                'algorithm': 'ecdsa-nistp256-with-sha256',
                'key': ('uncompressed', {
                    'x': key.public_key().public_numbers().x.to_bytes(32, 'big'),
                    'y': key.public_key().public_numbers().y.to_bytes(32, 'big')
                })
            },
            'assuranceLevel': b'\xFF',
            'itsList': ('its-aid-list', [0])
        },
        'validityRestrictions': {
            'timeOfValidation': ('timeStartAndDuration', {
                'startValidity': now,
                'duration': ('seconds', 31536000)  # 1 year
            })
        }
    }

    tbs_encoded = spec.encode("ToBeSignedCertificateAlias", tbs)
    signature = key.sign(tbs_encoded, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)
    cert = {
        'tbs': tbs,
        'signature': {
            'r': ('x-coordinate-only', r.to_bytes(32, 'big')),
            's': s.to_bytes(32, 'big')

        }
    }

    return spec.encode("CertificateAlias", cert)


def build_authority_cert(subject_pub: ec.EllipticCurvePublicKey, issuer_cert_bytes: bytes, issuer_priv: ec.EllipticCurvePrivateKey, subject_name="LTCA", authority_type='enrollment-authority') -> bytes:
    """
    Builds an ETSI 103 097 authority certificate.

    param
    -----
        subject_pub : Public key of the subject.
        issuer_cert_bytes : DER-encoded certificate of the issuer.
        issuer_priv : Private key of the issuer.
        subject_name : Name of the subject, truncated to 32 bytes.
        authority_type : Type of the authority (e.g., 'enrollment-authority').
    return
    ------
        bytes : DER-encoded authority certificate.
    """
    now = int(time.time())

    hashed_issuer_cert = hashlib.sha256(issuer_cert_bytes).digest()[:8]
    tbs = {
        'version': 2,
        # Placeholder; trust chain is out-of-band
        'signerInfo': ('certificateDigestSHA256', hashed_issuer_cert),
        'subjectInfo': {
            'subjectType': authority_type,
            'subjectName': subject_name[:32]
        },
        'subjectAttributes': {
            'verificationKey': {
                'algorithm': 'ecdsa-nistp256-with-sha256',
                'key': ('uncompressed', {
                    'x': subject_pub.public_numbers().x.to_bytes(32, 'big'),
                    'y': subject_pub.public_numbers().y.to_bytes(32, 'big')
                })
            },
            'assuranceLevel': b'\x02',
            'itsList': ('its-aid-list', [0])
        },
        'validityRestrictions': {
            'timeOfValidation': ('timeStartAndDuration', {
                'startValidity': now,
                'duration': ('seconds', 31536000)
            })

        }
    }

    tbs_encoded = spec.encode("ToBeSignedCertificateAlias", tbs)
    signature = issuer_priv.sign(tbs_encoded, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)

    cert = {
        'tbs': tbs,
        'signature': {
            'r': ('x-coordinate-only', r.to_bytes(32, 'big')),
            's': s.to_bytes(32, 'big')
        }
    }

    return spec.encode("CertificateAlias", cert)


def verify_cert_signature(cert_bytes: bytes, issuer_public_key: ec.EllipticCurvePublicKey) -> bool:
    """
    Verifies the signature of an ETSI 103 097 certificate.

    Param:
        cert_bytes (bytes): DER-encoded certificate.
        issuer_public_key: cryptography public key object of issuer.

    return:
        bool: True if signature is valid, False otherwise.
    """
    # Step 1: Decode the certificate
    cert_dict = spec.decode("CertificateAlias", cert_bytes)

    # Step 2: Extract and remove the signature field
    signature = cert_dict["signature"]

    tbs_encoded = spec.encode('ToBeSignedCertificateAlias', cert_dict['tbs'])

    # Step 3: Reconstruct the raw signature from r + s
    # 'x-coordinate-only', 'compressed-y-0', or 'compressed-y-1'
    r_bytes = signature['r'][1]
    print(r_bytes, "in len : ", len(r_bytes))
    s_bytes = signature['s']
    print(s_bytes, "in len : ", len(s_bytes))
    r = int.from_bytes(r_bytes, 'big')
    s = int.from_bytes(s_bytes, 'big')
    der_signature = encode_dss_signature(r, s)

    # Step 4: Verify the signature
    try:
        issuer_public_key.verify(
            der_signature,
            tbs_encoded,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False
