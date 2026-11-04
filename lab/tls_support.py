"""Small TLS context helpers using Python's normal CA and hostname checks."""
import os
import ssl


def server_context(cert_file, key_file, *, ca_file=None, require_client=False):
    if not cert_file or not key_file:
        raise RuntimeError("TLS server certificate and key are required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    if require_client:
        if not ca_file:
            raise RuntimeError("TLS CA file required for mutual TLS")
        context.load_verify_locations(cafile=ca_file)
        context.verify_mode = ssl.CERT_REQUIRED
    return context


def client_context(*, ca_file=None, cert_file=None, key_file=None):
    ca_file = ca_file or os.environ.get("APPROVAL_CA_FILE")
    if not ca_file:
        raise RuntimeError("TLS CA file required; refusing unverified service connection")
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert_file and key_file:
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    elif cert_file or key_file:
        raise RuntimeError("both client certificate and key are required")
    return context
