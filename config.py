"""Central configuration and .env loading.

Every other module imports paths and settings from here so there is exactly
one place that knows where data lives and where secrets come from.

Secrets are read with python-dotenv and only ever held inside ``Settings``.
They are never logged, rendered, or written to a report.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Paths (absolute, so the app works no matter which directory it is started from)
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SAMPLES_DIR = DATA_DIR / "samples"
CACHE_DIR = DATA_DIR / "cache"
HISTORY_PATH = DATA_DIR / "history.jsonl"
ENV_PATH = BASE_DIR / ".env"

# ---------------------------------------------------------------------------
# App-wide constants
# ---------------------------------------------------------------------------
APP_NAME = "AI-Assisted Phishing Analysis Tool"
APP_VERSION = "1.0.0"

# Refuse to analyse anything larger than this (protects the UI from huge files).
MAX_INPUT_BYTES = 2 * 1024 * 1024  # 2 MB

# VirusTotal
VT_CACHE_TTL_HOURS = 24
VT_REQUEST_TIMEOUT = 15
DEFAULT_MAX_LOOKUPS = 4

# OpenAI
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
OPENAI_TIMEOUT = 20.0

# Populate os.environ from .env at import time. Changing .env needs a reload
# (Settings page has a "Reload .env" button) or an app restart.
load_dotenv(ENV_PATH)


@dataclass(frozen=True)
class Settings:
    """A snapshot of runtime configuration. Safe to pass around the app."""

    vt_api_key: str = ""
    openai_api_key: str = ""
    openai_model: str = DEFAULT_OPENAI_MODEL
    default_max_lookups: int = DEFAULT_MAX_LOOKUPS

    @property
    def has_vt(self) -> bool:
        return bool(self.vt_api_key)

    @property
    def has_openai(self) -> bool:
        return bool(self.openai_api_key)


def _bounded_int(raw: str | None, default: int, low: int = 1, high: int = 10) -> int:
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def get_settings() -> Settings:
    """Read current environment values (never cached, so reloads work)."""
    return Settings(
        vt_api_key=os.getenv("VT_API_KEY", "").strip(),
        openai_api_key=os.getenv("OPENAI_API_KEY", "").strip(),
        openai_model=os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL).strip()
        or DEFAULT_OPENAI_MODEL,
        default_max_lookups=_bounded_int(
            os.getenv("MAX_VT_LOOKUPS"), DEFAULT_MAX_LOOKUPS
        ),
    )


def reload_env() -> Settings:
    """Re-read .env with override=True. Used by the Settings page."""
    load_dotenv(ENV_PATH, override=True)
    return get_settings()


def ensure_dirs() -> None:
    """Create runtime directories if they are missing."""
    for path in (DATA_DIR, SAMPLES_DIR, CACHE_DIR):
        path.mkdir(parents=True, exist_ok=True)
