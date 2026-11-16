"""Append-only local history stored as JSON Lines.

Why JSONL? It is human-readable, append-safe, and needs no database. The file
is git-ignored and stays on the analyst's machine. Only the structured result
is stored - never the raw email body.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pandas as pd

from config import HISTORY_PATH
from core.models import AnalysisResult

_LOCK = threading.Lock()
_COLUMNS = [
    "id",
    "created_at",
    "source",
    "subject",
    "sender",
    "risk_level",
    "risk_score",
    "findings",
    "iocs",
    "reputation_checked",
    "ai_used",
]


def save_result(result: AnalysisResult) -> str:
    """Append one analysis to history and return its id."""
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "id": result.id,
        "created_at": result.created_at,
        "result": result.to_dict(),
    }
    line = json.dumps(record, ensure_ascii=False)
    with _LOCK:
        with open(HISTORY_PATH, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    return result.id


def load_records() -> list[dict]:
    """Read all valid records, newest first. Corrupt lines are skipped."""
    if not HISTORY_PATH.exists():
        return []
    try:
        lines = HISTORY_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    records: list[dict] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and isinstance(record.get("result"), dict):
            records.append(record)

    records.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return records


def records_to_frame(records: list[dict]) -> pd.DataFrame:
    """Flatten records into a DataFrame for the dashboard."""
    rows = []
    for record in records:
        result = record.get("result", {})
        risk = result.get("risk", {})
        rows.append(
            {
                "id": record.get("id", result.get("id", "")),
                "created_at": record.get("created_at", result.get("created_at", "")),
                "source": result.get("source", ""),
                "subject": result.get("subject", "") or "(no subject)",
                "sender": result.get("sender", ""),
                "risk_level": risk.get("level", "Low"),
                "risk_score": int(risk.get("score", 0) or 0),
                "findings": len(result.get("findings", [])),
                "iocs": len(result.get("iocs", [])),
                "reputation_checked": bool(result.get("reputation_checked", False)),
                "ai_used": bool(result.get("ai_used", False)),
            }
        )

    frame = pd.DataFrame(rows, columns=_COLUMNS)
    if not frame.empty:
        frame["created_at"] = pd.to_datetime(
            frame["created_at"], utc=True, errors="coerce"
        )
    return frame


def delete_record(record_id: str) -> bool:
    """Remove one record, rewriting the file atomically."""
    records = load_records()
    remaining = [record for record in records if record.get("id") != record_id]
    if len(remaining) == len(records):
        return False
    _rewrite(remaining)
    return True


def clear_history() -> None:
    """Delete all saved analyses."""
    with _LOCK:
        try:
            HISTORY_PATH.unlink()
        except FileNotFoundError:
            pass


def _rewrite(records: list[dict]) -> None:
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = HISTORY_PATH.with_suffix(".tmp")
    with _LOCK:
        with open(temporary, "w", encoding="utf-8") as handle:
            for record in reversed(records):  # keep chronological append order
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        temporary.replace(HISTORY_PATH)


def history_stats(frame: pd.DataFrame) -> dict[str, object]:
    if frame.empty:
        return {
            "total": 0,
            "high_risk": 0,
            "average_score": 0,
            "iocs": 0,
            "last_seen": "—",
        }
    high_risk = int(frame["risk_level"].isin(["High", "Critical"]).sum())
    last_seen = frame["created_at"].max()
    return {
        "total": int(len(frame)),
        "high_risk": high_risk,
        "average_score": int(round(frame["risk_score"].mean())),
        "iocs": int(frame["iocs"].sum()),
        "last_seen": (
            last_seen.strftime("%Y-%m-%d %H:%M UTC")
            if pd.notna(last_seen)
            else "—"
        ),
    }
