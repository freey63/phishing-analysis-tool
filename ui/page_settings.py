"""Settings page: integration status, defaults, caches and safety notes."""

from __future__ import annotations

import streamlit as st

from config import (
    APP_VERSION,
    MAX_INPUT_BYTES,
    get_settings,
    reload_env,
)
from core.models import RiskLevel
from core.samples import list_samples
from core.vt_client import cache_info, clear_cache
from storage.history import clear_history, load_records


def _integration_status(name: str, configured: bool, env_var: str) -> None:
    st.subheader(name)
    if configured:
        st.success(f"{env_var} detected (value hidden)")
    else:
        st.warning(f"{env_var} not set")
    st.caption("Keys are read from `.env` and never displayed in the UI or reports.")


def render() -> None:
    st.title("⚙️ Settings")
    st.caption(
        "All configuration lives in `.env`. Changing the file requires "
        "**Reload .env** (or an app restart)."
    )

    settings = get_settings()

    status_a, status_b = st.columns(2)
    with status_a:
        _integration_status("VirusTotal", settings.has_vt, "VT_API_KEY")
        st.caption(
            "Free tier: about 4 requests/minute. Lookups are cached for 24 hours, "
            "and only indicators are sent - never the email body."
        )
    with status_b:
        _integration_status("OpenAI", settings.has_openai, "OPENAI_API_KEY")
        st.caption(
            f"Model: `{settings.openai_model}`. The email body is sent only when "
            "you tick **Let AI read the body** for that analysis."
        )

    st.markdown("#### `.env` template")
    st.code(
        "VT_API_KEY=your_virustotal_key\n"
        "OPENAI_API_KEY=your_openai_key\n"
        "OPENAI_MODEL=gpt-4o-mini\n"
        "MAX_VT_LOOKUPS=4",
        language="bash",
    )
    st.caption("Copy `.env.example` to `.env` and fill in only the keys you have.")

    if st.button("Reload .env"):
        reload_env()
        st.success("Environment reloaded.")
        st.rerun()

    st.divider()
    st.subheader("Defaults for new analyses")

    st.session_state.setdefault("opt_vt", False)
    st.session_state.setdefault("opt_ai", False)
    st.session_state.setdefault("opt_body", False)

    pref_a, pref_b = st.columns(2)
    pref_a.checkbox(
        "Enable VirusTotal by default",
        key="opt_vt",
        disabled=not settings.has_vt,
        help="Ignored while no VT_API_KEY is configured.",
    )
    pref_b.checkbox(
        "Enable AI explanation by default",
        key="opt_ai",
        disabled=not settings.has_openai,
        help="Ignored while no OPENAI_API_KEY is configured.",
    )
    st.checkbox(
        "Let AI read the email body by default (privacy-sensitive)",
        key="opt_body",
        disabled=not (settings.has_openai and st.session_state.get("opt_ai")),
    )
    st.slider(
        "Default maximum VirusTotal lookups",
        min_value=1,
        max_value=10,
        value=int(st.session_state.get("opt_max", settings.default_max_lookups)),
        key="opt_max",
        disabled=not settings.has_vt,
        help="Free keys allow about 4 lookups per minute. Cached lookups still count.",
    )

    st.divider()
    st.subheader("Caches and data")

    info = cache_info()
    size_kb = float(info["size_bytes"]) / 1024  # type: ignore[arg-type]
    st.write(
        f"**VirusTotal cache:** {info['entries']} entries · {size_kb:.1f} KB · "
        "24-hour TTL"
    )
    if st.button("Clear VirusTotal cache", disabled=not bool(info["entries"])):
        clear_cache()
        st.success("VirusTotal cache cleared.")
        st.rerun()

    records = load_records()
    st.write(f"**Analysis history:** {len(records)} saved analyses")
    confirm_clear = st.checkbox(
        "I understand clearing history cannot be undone.",
        key="confirm_clear_history",
    )
    if st.button(
        "Clear all history",
        disabled=not confirm_clear or not records,
        key="clear_history_button",
    ):
        clear_history()
        st.success("History cleared.")
        st.rerun()

    st.divider()
    st.subheader("Built-in samples")
    st.dataframe(
        [
            {
                "Sample": sample.title,
                "Expected": sample.expected,
                "What it tests": sample.description,
            }
            for sample in list_samples()
        ],
        hide_index=True,
        width="stretch",
    )

    st.divider()
    st.subheader("Safety rules this tool follows")
    st.markdown(
        """
- No URL, domain or IP in an email is ever contacted - analysis is static.
- Attachments are never opened, decoded for viewing, or executed. Only metadata is read.
- No email is sent, replied to, or forwarded; mailboxes are never contacted.
- Links in the UI and reports are defanged and inert.
- API keys are never rendered, logged, or written into reports.
- **Unknown reputation is never treated as safe.**
        """
    )
    st.caption(
        f"AI-Assisted Phishing Analysis Tool v{APP_VERSION} · maximum input "
        f"{MAX_INPUT_BYTES // (1024 * 1024)} MB · risk bands: "
        f"{RiskLevel.LOW.value} 0-24, {RiskLevel.MEDIUM.value} 25-49, "
        f"{RiskLevel.HIGH.value} 50-74, {RiskLevel.CRITICAL.value} 75-100."
    )
