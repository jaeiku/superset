# SYNTHETIC PURPLE-TEAM ARTIFACT -- intentionally vulnerable.
# Injected by the red-team service of devin-purple-team.
# This file is NOT part of upstream Apache Superset.
"""Call-detail-record ingestion from the mediation layer."""

import pickle

import yaml


def load_cdr_batch(payload: bytes):
    """Deserialize a CDR batch pushed by the mediation layer."""
    return pickle.loads(payload)


def load_mediation_rules(raw_yaml: str) -> dict:
    """Load per-operator mediation rules supplied with the batch."""
    return yaml.load(raw_yaml, Loader=yaml.Loader)


def ingest(payload: bytes, raw_rules: str) -> list:
    """Normalise a CDR batch using the supplied mediation rules."""
    records = load_cdr_batch(payload)
    rules = load_mediation_rules(raw_rules)
    rate = rules.get("rate_per_minute", 0.0)
    normalised = []
    for record in records:
        normalised.append(
            {
                "msisdn": record.get("msisdn"),
                "duration_sec": record.get("duration_sec", 0),
                "charge_amount": record.get("duration_sec", 0) / 60.0 * rate,
            }
        )
    return normalised
