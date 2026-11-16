"""Streamlit entry point.

Run with:  streamlit run app.py
"""

from __future__ import annotations

import streamlit as st

from config import APP_NAME, APP_VERSION, ensure_dirs, get_settings
from ui import page_analyze, page_history, page_settings
from ui.components import inject_css


def _init_state() -> None:
    defaults = {
        "input_mode": "Paste email",
        "opt_vt": False,
        "opt_ai": False,
        "opt_body": False,
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def main() -> None:
    st.set_page_config(
        page_title=APP_NAME,
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    ensure_dirs()
    _init_state()
    inject_css()

    settings = get_settings()

    with st.sidebar:
        st.markdown("## 🛡️ Phishing Analyst")
        st.caption(APP_NAME)
        page = st.radio(
            "Navigation",
            options=["🔎 Analyze", "📊 History", "⚙️ Settings"],
            label_visibility="collapsed",
        )
        st.divider()
        st.caption("Integrations")
        st.markdown(
            f"{'🟢' if settings.has_vt else '⚪'} VirusTotal "
            f"· {'ready' if settings.has_vt else 'not configured'}"
        )
        st.markdown(
            f"{'🟢' if settings.has_openai else '⚪'} OpenAI "
            f"· {'ready' if settings.has_openai else 'not configured'}"
        )
        st.divider()
        st.caption(
            "No links are opened. No attachments are executed. No email is sent."
        )
        st.caption(f"v{APP_VERSION} · local-first")

    if page == "🔎 Analyze":
        page_analyze.render()
    elif page == "📊 History":
        page_history.render()
    else:
        page_settings.render()


if __name__ == "__main__":
    main()
