"""Read the certificate the server presents on the HTTPS connection the audit already uses."""

import datetime as dt
import socket
import ssl


def certificate(host, port=443):
    result = {"trusted": None, "issuer": None, "subject": None, "expires": None, "error": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        result["trusted"] = True
    except ssl.SSLCertVerificationError as exc:
        result["trusted"] = False
        result["error"] = exc.verify_message
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
            cert = _decode_der(der)
        except (OSError, ssl.SSLError):
            return result
    except OSError as exc:
        result["error"] = str(exc)
        return result
    if cert:
        result["issuer"] = _name(cert.get("issuer"))
        result["subject"] = _name(cert.get("subject"))
        if cert.get("notAfter"):
            expires = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            result["expires"] = expires.date().isoformat()
    return result


def _name(parts):
    if not parts:
        return None
    return ", ".join(f"{k}={v}" for rdn in parts for k, v in rdn)


def _decode_der(der):
    # The standard library only decodes verified certificates; for an untrusted one we
    # still want issuer and expiry, which the cryptography package can read if present.
    try:
        from cryptography import x509
    except ImportError:
        return None
    cert = x509.load_der_x509_certificate(der)
    issuer = [[(a.oid._name, a.value)] for a in cert.issuer]
    subject = [[(a.oid._name, a.value)] for a in cert.subject]
    return {
        "issuer": issuer,
        "subject": subject,
        "notAfter": cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
    }
