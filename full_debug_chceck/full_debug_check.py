from lxml import etree
import hashlib, base64, binascii
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.backends import default_backend
import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


fn = 'signed_xml.xml' ### !!! tutaj zmien nazwe pliku XML do sprawdzenia !!!
xml = open(fn,'rb').read()

parser = etree.XMLParser(remove_blank_text=False)
doc = etree.fromstring(xml, parser)

ns = {
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
    'xades': 'http://uri.etsi.org/01903/v1.3.2#'
}

sig = doc.find('.//ds:Signature', ns)
if sig is None:
    raise SystemExit("Signature element not found")

# 1) Reference URI="" digest (already known) - recompute
root_copy = etree.fromstring(xml)
sig_copy = root_copy.find('.//ds:Signature', ns)
sig_copy.getparent().remove(sig_copy)
can_ref = etree.tostring(root_copy, method="c14n", exclusive=True, with_comments=False)
digest_ref_b64 = base64.b64encode(hashlib.sha256(can_ref).digest()).decode()

# 2) SignedProperties extraction and digest
signed_props = sig.find('.//{http://uri.etsi.org/01903/v1.3.2#}SignedProperties')
if signed_props is None:
    # try find by id
    signed_props = doc.xpath('//*[@Id="SignedProps-1618565691"]')
    signed_props = signed_props[0] if signed_props else None

if signed_props is None:
    signed_props_can = None
    digest_signed_props_b64 = None
else:
    signed_props_can = etree.tostring(signed_props, method="c14n", exclusive=True, with_comments=False)
    digest_signed_props_b64 = base64.b64encode(hashlib.sha256(signed_props_can).digest()).decode()

# 3) SignedInfo canonicalization (what is signed)
signed_info = sig.find('./ds:SignedInfo', ns)
signed_info_can = etree.tostring(signed_info, method="c14n", exclusive=True, with_comments=False)
signed_info_b64 = base64.b64encode(hashlib.sha256(signed_info_can).digest()).decode()

# 4) SignatureValue bytes
sigvalue_elem = sig.find('./ds:SignatureValue', ns)
sigvalue_b64 = sigvalue_elem.text.strip() if sigvalue_elem is not None else None
sigvalue_bytes = base64.b64decode(sigvalue_b64) if sigvalue_b64 is not None else None

# 5) Certificate parse and digest
cert_elem = sig.find('.//ds:X509Certificate', ns)
cert_b64 = cert_elem.text.strip() if cert_elem is not None else None
cert_der = base64.b64decode(cert_b64)
cert = x509.load_der_x509_certificate(cert_der, backend=default_backend())
cert_subject = cert.subject.rfc4514_string()
cert_issuer = cert.issuer.rfc4514_string()
cert_serial = cert.serial_number
cert_pubkey = cert.public_key()
# get pubkey numbers if EC
pubkey_info = {}
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
if isinstance(cert_pubkey, EllipticCurvePublicKey):
    nums = cert_pubkey.public_numbers()
    pubkey_info['curve'] = cert_pubkey.curve.name
    pubkey_info['x'] = nums.x
    pubkey_info['y'] = nums.y

cert_sha256_b64 = base64.b64encode(hashlib.sha256(cert_der).digest()).decode()

# 6) Compare provided SigningCertificate digest
prov = sig.find('.//{http://uri.etsi.org/01903/v1.3.2#}CertDigest/{http://www.w3.org/2000/09/xmldsig#}DigestValue')
provided_cert_digest = prov.text.strip() if prov is not None else None

# 7) Try to verify signature: sign over signed_info_can using ECDSA-SHA256.
verify_result = {'verified': False, 'errors': []}
from cryptography.exceptions import InvalidSignature

# helper to try verify with given signature bytes (ASN.1 DER)
def try_verify(sig_bytes):
    try:
        cert_pubkey.verify(sig_bytes, signed_info_can, ec.ECDSA(hashes.SHA256()))
        return True, None
    except InvalidSignature as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

# First try as DER
ok, err = try_verify(sigvalue_bytes)
sig_format = None
if not ok:
    # if length matches 64 (P-256 raw r||s), convert to DER
    if sigvalue_bytes is not None and len(sigvalue_bytes) in (64, 96, 132):
        half = len(sigvalue_bytes)//2
        r = int.from_bytes(sigvalue_bytes[:half], 'big')
        s = int.from_bytes(sigvalue_bytes[half:], 'big')
        der = utils.encode_dss_signature(r, s)
        ok2, err2 = try_verify(der)
        if ok2:
            ok = True
            sig_format = 'raw-r||s converted to DER'
        else:
            sig_format = f'raw->DER failed: {err2}'
    else:
        sig_format = f'DER attempt failed: {err}'
else:
    sig_format = 'signature bytes treated as DER and verified'

if ok:
    verify_result['verified'] = True
    verify_result['format'] = sig_format
else:
    verify_result['verified'] = False
    verify_result['format'] = sig_format
    verify_result['errors'].append(err)

# prepare output
digest_ref_xml = sig.find('.*/ds:Reference/ds:DigestValue', ns)
digest_signedprops_xml = sig.find('.*/ds:Reference[@Type="http://uri.etsi.org/01903#SignedProperties"]/ds:DigestValue', ns)

#checks
digest_matches_xml1 = digest_ref_b64 == (digest_ref_xml.text.strip() if digest_ref_xml is not None else None)
digest_matches_xml2 = digest_signed_props_b64 == (digest_signedprops_xml.text.strip() if digest_signedprops_xml is not None else None)

out = {
    'file': fn,
    'reference_uri_empty': {
        'canonical_bytes_len': len(can_ref),
        'canonical_text': can_ref.decode(),
        'digest_sha256_b64': digest_ref_b64,
        'digest_matches_xml': digest_matches_xml1
    },
    'signed_properties': {
#        'found': signed_props is not None,
        'canonical_bytes_len': len(signed_props_can) if signed_props_can is not None else None,
        'canonical_text': signed_props_can.decode() if signed_props_can is not None else None,
        'digest_sha256_b64': digest_signed_props_b64,
        'digest_matches_xml': digest_matches_xml2
    },
    'signed_info': {
        'canonical_bytes_len': len(signed_info_can),
        'canonical_text': signed_info_can.decode(),
        'signature_method': signed_info.find('./ds:SignatureMethod', ns).get('Algorithm'),
        'digest_sha256_b64' : signed_info_b64
    },
    'signature_value': {
        'b64': sigvalue_b64,
        'len': len(sigvalue_bytes) if sigvalue_bytes is not None else None,
        'hex': sigvalue_bytes.hex() if sigvalue_bytes is not None else None
    },
    'certificate': {
        'subject': cert_subject,
        'issuer': cert_issuer,
        'serial': cert_serial,
        'pubkey_info': pubkey_info,
        'sha256_b64': cert_sha256_b64,
        'provided_cert_digest_b64': provided_cert_digest,
        'provided_cert_digest_matches': (provided_cert_digest == cert_sha256_b64) if provided_cert_digest is not None else None
    },
    'verification': verify_result
}

# print(out)
dump = json.dumps(out)
parsed = json.loads(dump)
print(json.dumps(parsed, indent=4))
