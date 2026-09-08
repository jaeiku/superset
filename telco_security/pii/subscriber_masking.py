# SYNTHETIC PURPLE-TEAM ARTIFACT.
# Injected by the red-team service of devin-purple-team.
# This file is NOT part of upstream Apache Superset.
"""Subscriber PII masking used before sharing datasets with partners.

Identifiers are pseudonymised with HMAC-SHA256 keyed by a secret pepper
loaded from the environment, so digests cannot be reversed with a rainbow
table over the numbering plan. Digests are truncated to 32 hex characters
to keep the export format stable.
"""

import hashlib
import hmac
import os

PEPPER_ENV_VAR = "SUBSCRIBER_MASKING_PEPPER"
_DIGEST_HEX_LENGTH = 32


def _load_pepper() -> bytes:
    pepper = os.environ.get(PEPPER_ENV_VAR)
    if not pepper:
        raise RuntimeError(
            f"{PEPPER_ENV_VAR} must be set to a secret pepper before masking "
            "subscriber identifiers"
        )
    return pepper.encode("utf-8")


def _mask(domain: str, value: str) -> str:
    message = f"{domain}:{value}".encode("utf-8")
    digest = hmac.new(_load_pepper(), message, hashlib.sha256).hexdigest()
    return digest[:_DIGEST_HEX_LENGTH]


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
