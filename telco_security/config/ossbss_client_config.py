# SYNTHETIC PURPLE-TEAM ARTIFACT -- remediated.
# Originally injected by the red-team service of devin-purple-team.
# This file is NOT part of upstream Apache Superset.
"""Configuration for the OSS/BSS integration client.

All credentials are read from the environment at import time. No defaults are
provided: a missing variable raises immediately so misconfiguration is caught
at startup rather than at first use.
"""

import os


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Required environment variable {name} is not set for the "
            "OSS/BSS client configuration"
        )
    return value


CLICKHOUSE_HOST = _require_env("TELCO_CLICKHOUSE_HOST")
CLICKHOUSE_USER = _require_env("TELCO_CLICKHOUSE_USER")
CLICKHOUSE_PASSWORD = _require_env("TELCO_CLICKHOUSE_PASSWORD")

HSS_PROVISIONING_API_KEY = _require_env("TELCO_HSS_PROVISIONING_API_KEY")
BILLING_GATEWAY_TOKEN = _require_env("TELCO_BILLING_GATEWAY_TOKEN")

CDR_ARCHIVE_ACCESS_KEY = _require_env("TELCO_CDR_ARCHIVE_ACCESS_KEY")
CDR_ARCHIVE_SECRET_KEY = _require_env("TELCO_CDR_ARCHIVE_SECRET_KEY")

JWT_SIGNING_SECRET = _require_env("TELCO_JWT_SIGNING_SECRET")


def clickhouse_dsn() -> str:
    """Return the ClickHouse DSN used by the analytics workers."""
    return (
        f"clickhouse://{CLICKHOUSE_USER}:{CLICKHOUSE_PASSWORD}"
        f"@{CLICKHOUSE_HOST}:9000/telco"
    )


def hss_headers() -> dict:
    """Return auth headers for the HSS provisioning API."""
    return {"X-Api-Key": HSS_PROVISIONING_API_KEY}
