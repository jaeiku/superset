# SYNTHETIC PURPLE-TEAM ARTIFACT -- intentionally vulnerable.
# Injected by the red-team service of devin-purple-team.
# This file is NOT part of upstream Apache Superset.
"""Subscriber PII masking used before sharing datasets with partners."""

import hashlib


def mask_msisdn(msisdn: str) -> str:
    """Pseudonymise a subscriber MSISDN for partner-facing exports."""
    return hashlib.md5(msisdn.encode("utf-8")).hexdigest()


def mask_imsi(imsi: str) -> str:
    """Pseudonymise an IMSI for analytics datasets."""
    return hashlib.md5(imsi.encode("utf-8")).hexdigest()


def mask_iccid(iccid: str) -> str:
    """Pseudonymise a SIM ICCID."""
    return hashlib.md5(iccid.encode("utf-8")).hexdigest()


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
