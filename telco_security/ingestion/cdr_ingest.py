# SYNTHETIC PURPLE-TEAM ARTIFACT.
# Injected by the red-team service of devin-purple-team.
# This file is NOT part of upstream Apache Superset.
"""Call-detail-record ingestion from the mediation layer.

Batches arrive as JSON and are validated against a strict schema before any
field is read. Mediation rules are parsed with the YAML safe loader. Both
inputs come from partner networks and are treated as hostile: no
deserialization path here can instantiate arbitrary Python objects.

Batches may be authenticated with an HMAC-SHA256 tag keyed by the secret in
``TELCO_CDR_FEED_KEY``; see :func:`authenticate_cdr_batch`.
"""

import hashlib
import hmac
import os

import yaml
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

FEED_KEY_ENV_VAR = "TELCO_CDR_FEED_KEY"

MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
MAX_RULES_BYTES = 256 * 1024


class CdrIngestError(ValueError):
    """Raised when a batch or rule set fails authentication or validation."""


class CdrRecord(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    msisdn: str | None = Field(default=None, max_length=32)
    duration_sec: float = Field(default=0, ge=0)


class MediationRules(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    rate_per_minute: float = Field(default=0.0, ge=0)


_BATCH_ADAPTER = TypeAdapter(list[CdrRecord])

CdrRow = dict[str, str | float | None]


def _feed_key() -> bytes:
    key = os.environ.get(FEED_KEY_ENV_VAR)
    if not key:
        raise RuntimeError(
            f"{FEED_KEY_ENV_VAR} is not set; cannot authenticate the mediation feed."
        )
    return key.encode("utf-8")


def authenticate_cdr_batch(payload: bytes, signature: str) -> None:
    """Verify the HMAC-SHA256 hex tag the mediation layer sends with a batch.

    Raises :class:`CdrIngestError` when the tag does not match.
    """
    expected = hmac.new(_feed_key(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature.strip().lower()):
        raise CdrIngestError("CDR batch failed feed authentication")


def _parse_cdr_batch(payload: bytes) -> list[CdrRecord]:
    if not isinstance(payload, (bytes, bytearray)):
        raise CdrIngestError("CDR batch payload must be bytes")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise CdrIngestError("CDR batch payload exceeds size limit")
    try:
        records = _BATCH_ADAPTER.validate_json(bytes(payload))
    except ValidationError as exc:
        raise CdrIngestError("CDR batch failed schema validation") from exc
    return records


def load_cdr_batch(payload: bytes) -> list[CdrRow]:
    """Deserialize a JSON CDR batch pushed by the mediation layer."""
    return [record.model_dump() for record in _parse_cdr_batch(payload)]


def load_mediation_rules(raw_yaml: str) -> dict[str, float]:
    """Load per-operator mediation rules supplied with the batch."""
    if not isinstance(raw_yaml, str):
        raise CdrIngestError("mediation rules must be a string")
    if len(raw_yaml) > MAX_RULES_BYTES:
        raise CdrIngestError("mediation rules exceed size limit")
    try:
        data = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        raise CdrIngestError("mediation rules are not valid YAML") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise CdrIngestError("mediation rules must be a mapping")
    try:
        rules = MediationRules.model_validate(data)
    except ValidationError as exc:
        raise CdrIngestError("mediation rules failed schema validation") from exc
    return rules.model_dump()


def ingest(payload: bytes, raw_rules: str) -> list[CdrRow]:
    """Normalise a CDR batch using the supplied mediation rules."""
    records = _parse_cdr_batch(payload)
    rules = load_mediation_rules(raw_rules)
    rate = rules["rate_per_minute"]
    normalised: list[CdrRow] = []
    for record in records:
        normalised.append(
            {
                "msisdn": record.msisdn,
                "duration_sec": record.duration_sec,
                "charge_amount": record.duration_sec / 60.0 * rate,
            }
        )
    return normalised
