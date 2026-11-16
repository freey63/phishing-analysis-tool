"""VirusTotal API v3 client with caching and defensive error handling.

Design notes
------------
* Lookups are opt-in and only accept URLs/domains/IPs.
* Results are cached for 24 hours to stay inside the free-tier quota.
* HTTP 429 is retried once with backoff, then reported as an error.
* A "clean" verdict is explicitly described as *not proof of safety*.
* API keys are only ever sent in the ``x-apikey`` header.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from pathlib import Path
from typing import Callable
from urllib.parse import quote

import requests

from config import (
    CACHE_DIR,
    VT_CACHE_TTL_HOURS,
    VT_REQUEST_TIMEOUT,
)
from core.brands import is_public_ip
from core.models import IOC, Reputation, ReputationVerdict, utc_now_iso

BASE_URL = "https://www.virustotal.com/api/v3"
_CACHE_FILENAME = "vt_cache.json"
_MAX_CACHE_ENTRIES = 500
_MAX_RETRY_WAIT = 20


class VTError(Exception):
    """Generic VirusTotal failure."""


class VTAuthError(VTError):
    """The API key is missing or rejected."""


class VTRateLimitError(VTError):
    """The API quota was exhausted."""


def url_to_vt_id(url: str) -> str:
    """VirusTotal identifies URLs by unpadded base64 of the URL."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def cache_path() -> Path:
    return CACHE_DIR / _CACHE_FILENAME


def cache_info() -> dict[str, object]:
    """Summarise the on-disk cache for the Settings page."""
    path = cache_path()
    if not path.exists():
        return {"entries": 0, "size_bytes": 0, "exists": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = len(data) if isinstance(data, dict) else 0
    except (json.JSONDecodeError, OSError):
        entries = 0
    return {"entries": entries, "size_bytes": path.stat().st_size, "exists": True}


def clear_cache() -> None:
    path = cache_path()
    try:
        path.unlink()
    except FileNotFoundError:
        pass


class VTClient:
    def __init__(
        self,
        api_key: str,
        *,
        cache_dir: Path | None = None,
        ttl_hours: int = VT_CACHE_TTL_HOURS,
        timeout: int = VT_REQUEST_TIMEOUT,
        session: requests.Session | None = None,
        min_interval_seconds: float = 0.0,
    ) -> None:
        if not api_key:
            raise VTAuthError("No VirusTotal API key configured.")
        self._api_key = api_key
        self._ttl_seconds = max(1, ttl_hours) * 3600
        self._timeout = timeout
        self._session = session or requests.Session()
        self._min_interval = max(0.0, min_interval_seconds)
        self._last_request = 0.0
        self._lock = threading.Lock()
        self._cache_file = (cache_dir or CACHE_DIR) / _CACHE_FILENAME
        self._cache = self._load_cache()

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------
    def _load_cache(self) -> dict[str, dict]:
        try:
            raw = json.loads(self._cache_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}
        if not isinstance(raw, dict):
            return {}
        now = time.time()
        return {
            key: value
            for key, value in raw.items()
            if isinstance(value, dict)
            and now - float(value.get("ts", 0)) <= self._ttl_seconds
        }

    def _save_cache(self) -> None:
        try:
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            if len(self._cache) > _MAX_CACHE_ENTRIES:
                newest = sorted(
                    self._cache.items(),
                    key=lambda item: item[1].get("ts", 0),
                    reverse=True,
                )[:_MAX_CACHE_ENTRIES]
                self._cache = dict(newest)
            temporary = self._cache_file.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(self._cache, ensure_ascii=False), encoding="utf-8"
            )
            temporary.replace(self._cache_file)
        except OSError:
            # Caching is an optimisation; never fail an analysis over it.
            pass

    def _cache_get(self, kind: str, value: str) -> tuple[bool, dict | None]:
        key = f"{kind}:{value.lower()}"
        entry = self._cache.get(key)
        if not entry:
            return False, None
        if time.time() - float(entry.get("ts", 0)) > self._ttl_seconds:
            self._cache.pop(key, None)
            return False, None
        return True, entry.get("payload")

    def _cache_set(self, kind: str, value: str, payload: dict | None) -> None:
        self._cache[f"{kind}:{value.lower()}"] = {
            "ts": time.time(),
            "payload": payload,
        }
        self._save_cache()

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------
    def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last_request
        wait = self._min_interval - elapsed
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def _request(self, path: str) -> dict | None:
        url = f"{BASE_URL}{path}"
        headers = {"x-apikey": self._api_key, "accept": "application/json"}

        response: requests.Response | None = None
        for attempt in range(2):
            self._throttle()
            try:
                response = self._session.get(
                    url, headers=headers, timeout=self._timeout
                )
            except requests.RequestException as exc:
                raise VTError("Network error while contacting VirusTotal.") from exc

            if response.status_code == 429 and attempt == 0:
                retry_after = response.headers.get("Retry-After", "10")
                try:
                    wait = int(float(retry_after))
                except (TypeError, ValueError):
                    wait = 10
                time.sleep(max(1, min(wait, _MAX_RETRY_WAIT)))
                continue
            break

        assert response is not None
        if response.status_code == 401 or response.status_code == 403:
            raise VTAuthError("VirusTotal rejected the API key.")
        if response.status_code == 429:
            raise VTRateLimitError(
                "VirusTotal rate limit reached. Wait a minute or reduce lookups."
            )
        if response.status_code == 404:
            return None  # unknown indicator, not an error
        if response.status_code >= 500:
            raise VTError(f"VirusTotal server error (HTTP {response.status_code}).")
        if response.status_code != 200:
            raise VTError(f"Unexpected VirusTotal response (HTTP {response.status_code}).")

        try:
            payload = response.json()
        except ValueError as exc:
            raise VTError("VirusTotal returned malformed JSON.") from exc
        return payload if isinstance(payload, dict) else None

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------
    @staticmethod
    def _endpoint(kind: str, value: str) -> str:
        if kind == "url":
            return f"/urls/{url_to_vt_id(value)}"
        if kind == "domain":
            return f"/domains/{quote(value, safe='')}"
        if kind == "ip":
            return f"/ip_addresses/{quote(value, safe='')}"
        raise VTError(f"Unsupported IOC type: {kind}")

    @staticmethod
    def _parse_reputation(kind: str, value: str, payload: dict | None) -> Reputation:
        if not payload:
            return Reputation(
                ioc_kind=kind,
                value=value,
                verdict=ReputationVerdict.UNKNOWN,
                note="Not found in VirusTotal (no vendor has reported this indicator).",
            )

        attributes = (payload.get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total = sum(
            int(value)
            for value in stats.values()
            if isinstance(value, (int, float))
        )

        detections: list[str] = []
        results = attributes.get("last_analysis_results") or {}
        if isinstance(results, dict):
            for engine, detail in results.items():
                if not isinstance(detail, dict):
                    continue
                if detail.get("category") in {"malicious", "suspicious"}:
                    label = str(detail.get("result") or detail.get("category"))
                    detections.append(f"{engine}: {label}")
                if len(detections) >= 5:
                    break

        if malicious >= 2 or (malicious >= 1 and suspicious >= 1):
            verdict = ReputationVerdict.MALICIOUS
            note = f"{malicious} of {total} security vendors flagged this as malicious."
        elif malicious == 1 or suspicious >= 3:
            verdict = ReputationVerdict.SUSPICIOUS
            note = (
                f"{malicious + suspicious} of {total} security vendors flagged this "
                "as malicious or suspicious."
            )
        elif harmless + undetected > 0:
            verdict = ReputationVerdict.CLEAN
            note = (
                f"No security vendors flagged this indicator "
                f"({harmless + undetected}/{total} clean). "
                "Clean reputation is not proof of safety."
            )
        else:
            verdict = ReputationVerdict.UNKNOWN
            note = "VirusTotal has no analysis data for this indicator yet."

        return Reputation(
            ioc_kind=kind,
            value=value,
            verdict=verdict,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            total_engines=total,
            detections=detections,
            note=note,
            checked_at=utc_now_iso(),
        )

    def lookup(self, kind: str, value: str) -> Reputation:
        """Look up one indicator (cache first, then the API)."""
        cached, payload = self._cache_get(kind, value)
        if not cached:
            payload = self._request(self._endpoint(kind, value))
            self._cache_set(kind, value, payload)
        return self._parse_reputation(kind, value, payload)

    # ------------------------------------------------------------------
    # Batch
    # ------------------------------------------------------------------
    def lookup_many(
        self,
        iocs: list[IOC],
        *,
        max_lookups: int = 4,
        on_progress: Callable[[str], None] | None = None,
    ) -> list[Reputation]:
        priority = {"url": 0, "domain": 1, "ip": 2}
        candidates: list[IOC] = []
        seen: set[tuple[str, str]] = set()
        for ioc in iocs:
            if ioc.kind not in priority:
                continue
            key = (ioc.kind, ioc.value.lower())
            if key in seen:
                continue
            seen.add(key)
            candidates.append(ioc)
        candidates.sort(key=lambda item: priority[item.kind])

        results: list[Reputation] = []
        performed = 0

        for ioc in candidates:
            if performed >= max(1, max_lookups):
                break

            if ioc.kind == "ip" and not is_public_ip(ioc.value):
                results.append(
                    Reputation(
                        ioc_kind="ip",
                        value=ioc.value,
                        verdict=ReputationVerdict.UNKNOWN,
                        note="Private or reserved IP address — not sent to VirusTotal.",
                    )
                )
                continue

            if on_progress:
                on_progress(f"VirusTotal: checking {ioc.kind} {ioc.value}")

            try:
                results.append(self.lookup(ioc.kind, ioc.value))
                performed += 1
            except VTAuthError as exc:
                results.append(
                    Reputation(
                        ioc_kind=ioc.kind,
                        value=ioc.value,
                        verdict=ReputationVerdict.ERROR,
                        note="VirusTotal rejected the API key. Check VT_API_KEY in .env.",
                    )
                )
                break
            except VTRateLimitError as exc:
                results.append(
                    Reputation(
                        ioc_kind=ioc.kind,
                        value=ioc.value,
                        verdict=ReputationVerdict.ERROR,
                        note=str(exc),
                    )
                )
                break
            except VTError as exc:
                results.append(
                    Reputation(
                        ioc_kind=ioc.kind,
                        value=ioc.value,
                        verdict=ReputationVerdict.ERROR,
                        note=str(exc),
                    )
                )

        return results
