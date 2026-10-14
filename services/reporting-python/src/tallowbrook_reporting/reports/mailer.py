"""Report mail: signed, sealed for the customer, and sent through the mail relay."""

from __future__ import annotations

import base64
import logging
import smtplib
from functools import cache
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7

from tallowbrook_reporting import settings
from tallowbrook_reporting.transfer.tls import carrier_context

log = logging.getLogger(__name__)


class MailConfigError(RuntimeError):
    pass


@cache
def _load_mail_signer() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    signer_cert = x509.load_pem_x509_certificate(Path(settings.MAIL_SIGNER_CERT_PATH).read_bytes())
    signer_key = serialization.load_pem_private_key(
        Path(settings.MAIL_SIGNER_KEY_PATH).read_bytes(), password=None
    )
    if not isinstance(signer_key, rsa.RSAPrivateKey):
        raise MailConfigError("report mail signer key has the wrong type")
    return signer_cert, signer_key


def mime_body(text: str, attachment_name: str, attachment: bytes) -> bytes:
    boundary = "tb-report-part"
    encoded = base64.encodebytes(attachment).decode("ascii")
    return (
        f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n\r\n'
        f"--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n"
        f"--{boundary}\r\nContent-Type: application/octet-stream\r\n"
        f'Content-Disposition: attachment; filename="{attachment_name}"\r\n'
        f"Content-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")


def sign_report_mail(body: bytes) -> bytes:
    signer_cert, signer_key = _load_mail_signer()
    return (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(body)
        .add_signer(signer_cert, signer_key, hashes.SHA256())
        .sign(serialization.Encoding.SMIME, [pkcs7.PKCS7Options.DetachedSignature])
    )


def encrypt_for_customer(signed: bytes, recipient_cert: x509.Certificate) -> bytes:
    return (
        pkcs7.PKCS7EnvelopeBuilder()
        .set_data(signed)
        .add_recipient(recipient_cert)
        .encrypt(serialization.Encoding.SMIME, [])
    )


def send_report(to: str, subject: str, message: bytes) -> None:
    headers = f"From: {settings.REPORTS_FROM}\r\nTo: {to}\r\nSubject: {subject}\r\n".encode()
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30) as smtp:
        smtp.starttls(context=carrier_context())
        smtp.login(settings.SMTP_USER, settings.smtp_password())
        smtp.sendmail(settings.REPORTS_FROM, [to], headers + message)
    log.info("sent %r to %s", subject, to)


def mail_report(
    to: str, subject: str, text: str, name: str, attachment: bytes, cert: x509.Certificate
) -> None:
    signed = sign_report_mail(mime_body(text, name, attachment))
    send_report(to, subject, encrypt_for_customer(signed, cert))
