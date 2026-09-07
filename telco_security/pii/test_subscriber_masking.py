# SYNTHETIC PURPLE-TEAM ARTIFACT.
# This file is NOT part of upstream Apache Superset.
"""Tests for the subscriber PII masking helpers."""

import re

import pytest

from telco_security.pii import subscriber_masking
from telco_security.pii.subscriber_masking import (
    mask_iccid,
    mask_imsi,
    mask_msisdn,
    mask_subscriber_record,
)

MSISDN = "+821012345678"


@pytest.fixture
def pepper(monkeypatch):
    monkeypatch.setenv(subscriber_masking.PEPPER_ENV_VAR, "pepper-a")


def test_digest_format_is_stable(pepper):
    digest = mask_msisdn(MSISDN)
    assert re.fullmatch(r"[0-9a-f]{32}", digest)


def test_same_input_different_peppers_yield_different_digests(monkeypatch):
    monkeypatch.setenv(subscriber_masking.PEPPER_ENV_VAR, "pepper-a")
    first = mask_msisdn(MSISDN)
    monkeypatch.setenv(subscriber_masking.PEPPER_ENV_VAR, "pepper-b")
    assert mask_msisdn(MSISDN) != first


def test_masking_is_deterministic_under_one_pepper(pepper):
    assert mask_msisdn(MSISDN) == mask_msisdn(MSISDN)


def test_identifier_domains_are_separated(pepper):
    value = "1234567890"
    assert len({mask_msisdn(value), mask_imsi(value), mask_iccid(value)}) == 3


def test_missing_pepper_fails_closed(monkeypatch):
    monkeypatch.delenv(subscriber_masking.PEPPER_ENV_VAR, raising=False)
    with pytest.raises(RuntimeError):
        mask_msisdn(MSISDN)


def test_record_masking_preserves_other_fields(pepper):
    record = {"msisdn": MSISDN, "imsi": "450050123456789", "plan": "gold"}
    masked = mask_subscriber_record(record)
    assert masked["plan"] == "gold"
    assert masked["msisdn"] == mask_msisdn(MSISDN)
    assert masked["imsi"] == mask_imsi("450050123456789")
    assert record["msisdn"] == MSISDN
