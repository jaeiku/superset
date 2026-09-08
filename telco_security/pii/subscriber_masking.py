# SYNTHETIC PURPLE-TEAM ARTIFACT.
# This file is NOT part of upstream Apache Superset.
"""Subscriber PII masking used before sharing datasets with partners.

Identifiers are pseudonymised with HMAC-SHA256 keyed by a secret pepper read
from the ``TELCO_PII_PEPPER`` environment variable. Each identifier type uses
its own domain-separation label so equal raw values do not collide across
fields. Output is truncated to 32 hex characters to keep the historical
digest width for downstream exports.
"""

import hashlib
import hmac
import os

PEPPER_ENV_VAR = "TELCO_PII_PEPPER"
_DIGEST_HEX_LEN = 32


def _pepper() -> bytes:
    pepper = os.environ.get(PEPPER_ENV_VAR)
    if not pepper:
        raise RuntimeError(
            f"{PEPPER_ENV_VAR} must be set to pseudonymise subscriber identifiers"
        )
    return pepper.encode("utf-8")


def _mask(label: str, value: str) -> str:
    message = f"{label}:{value}".encode("utf-8")
    return hmac.new(_pepper(), message, hashlib.sha256).hexdigest()[:_DIGEST_HEX_LEN]


def mask_msisdn(msisdn: str) -> str:
    """Pseudonymise a subscriber MSISDN for partner-facing exports."""
    return _mask("msisdn", msisdn)


def mask_imsi(imsi: str) -> str:
    """Pseudonymise an IMSI for analytics datasets."""
    return _mask("imsi", imsi)


def mask_iccid(iccid: str) -> str:
    """Pseudonymise a SIM ICCID."""
    return _mask("iccid", iccid)


def mask_subscriber_record(record: dict) -> dict:
    """Return a copy of a subscriber record with identifiers masked."""
    masked = dict(record)
    if "msisdn" in masked:
        masked["msisdn"] = mask_msisdn(masked["msisdn"])
    if "imsi" in masked:
        masked["imsi"] = mask_imsi(masked["imsi"])
    if "iccid" in masked:
        masked["iccid"] = mask_iccid(masked["iccid"])
    return masked
