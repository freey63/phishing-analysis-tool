"""Analyze page: input, options, results, and report downloads."""

from __future__ import annotations

import html

import streamlit as st

from config import MAX_INPUT_BYTES, get_settings
from core.models import (
    AnalysisResult,
    SEVERITY_ORDER,
    ReputationVerdict,
    Severity,
)
from core.pipeline import analyze_email_text
from core.report_builder import (
    build_ioc_blocklist,
    build_json,
    build_markdown,
    build_soc_ticket,
    json_filename,
    report_filename,
)
from core.samples import list_samples, load_sample_text
from storage.history import save_result
from ui.components import (
    finding_card,
    findings_by_category,
    format_timestamp,
    iocs_dataframe,
    message_details_dataframe,
    reputations_dataframe,
    risk_badge,
    risk_breakdown_dataframe,
)


def _load_sample_cb(sample_text: str) -> None:
    st.session_state["email_input"] = sample_text
    st.session_state["input_mode"] = "Paste email"


def _queue_sample_cb(sample_text: str) -> None:
    st.session_state["pending_text"] = sample_text


def _render_sample_panel() -> None:
    samples = list_samples()
    if not samples:
        return

    has_text = bool(st.session_state.get("email_input", "").strip())
    with st.expander("🧪 Try a sample email", expanded=not has_text):
        st.caption(
            "Synthetic samples covering credential phishing, BEC, malware delivery "
            "and a legitimate control email. All links are defanged."
        )
        selected_key = st.selectbox(
            "Sample",
            options=[sample.key for sample in samples],
            format_func=lambda key: next(
                sample.title for sample in samples if sample.key == key
            ),
        )
        sample = next(item for item in samples if item.key == selected_key)
        sample_text = load_sample_text(sample.key)

        st.markdown(f"**{sample.title}** — expected: `{sample.expected}`")
        st.caption(sample.description)
        st.code(sample_text[:1500], language="text")

        left, right = st.columns(2)
        left.button(
            "Load into editor",
            on_click=_load_sample_cb,
            args=(sample_text,),
            width="stretch",
        )
        right.button(
            "Analyze this sample now",
            on_click=_queue_sample_cb,
            args=(sample_text,),
            type="primary",
            width="stretch",
        )


def _render_options(settings) -> tuple[bool, bool, bool, int]:
    st.session_state.setdefault("opt_vt", False)
    st.session_state.setdefault("opt_ai", False)
    st.session_state.setdefault("opt_body", False)

    with st.expander("⚙️ Analysis options", expanded=True):
        column_a, column_b, column_c = st.columns(3)

        do_vt = column_a.checkbox(
            "VirusTotal reputation lookup",
            key="opt_vt",
            disabled=not settings.has_vt,
            help="Sends only URLs/domains/IPs to VirusTotal. Nothing is opened.",
        )
        do_ai = column_b.checkbox(
            "AI explanation",
            key="opt_ai",
            disabled=not settings.has_openai,
            help="Uses OpenAI to rewrite the findings in plain English.",
        )
        include_body = column_c.checkbox(
            "Let AI read the body",
            key="opt_body",
            disabled=not (do_ai and settings.has_openai),
            help=(
                "Off by default. When on, the first 1,500 characters of the body "
                "are sent to OpenAI in addition to the findings."
            ),
        )

        max_lookups = st.slider(
            "Maximum VirusTotal lookups per analysis",
            min_value=1,
            max_value=10,
            value=settings.default_max_lookups,
            key="opt_max",
            disabled=not (do_vt and settings.has_vt),
            help="The free VirusTotal tier allows about 4 requests per minute.",
        )

        if not settings.has_vt:
            st.caption(
                "VirusTotal is off: add `VT_API_KEY` to `.env` to enable it."
            )
        if not settings.has_openai:
            st.caption(
                "AI is off: add `OPENAI_API_KEY` to `.env` to enable it. "
                "The built-in explanation is always available."
            )

    return (
        bool(do_vt and settings.has_vt),
        bool(do_ai and settings.has_openai),
        bool(include_body and do_ai and settings.has_openai),
        int(max_lookups),
    )


def _read_input() -> tuple[str, str]:
    mode = st.radio(
        "Input method",
        options=["Paste email", "Upload .eml / .txt"],
        horizontal=True,
        key="input_mode",
    )

    if mode == "Paste email":
        text = st.text_area(
            "Raw email source (headers + body)",
            key="email_input",
            height=320,
            placeholder=(
                "Paste the full email source here, including From/Reply-To/"
                "Authentication-Results headers. A body-only paste also works."
            ),
        )
        return text or "", "Pasted email"

    uploaded = st.file_uploader(
        "Choose an .eml or .txt file",
        type=["eml", "txt", "email"],
        key="email_file",
        help="The file is read locally and never uploaded by this tool.",
    )
    if uploaded is None:
        return "", uploaded.name if uploaded else "Uploaded file"

    data = uploaded.getvalue()
    if len(data) > MAX_INPUT_BYTES:
        st.error("File is larger than the 2 MB limit.")
        return "", f"Uploaded file: {uploaded.name}"

    text = data.decode("utf-8", errors="replace")
    st.caption(f"Loaded `{uploaded.name}` · {len(data):,} bytes")
    with st.expander("Preview uploaded content", expanded=False):
        st.code(text[:3000], language="text")
    return text, f"Uploaded file: {uploaded.name}"


def render() -> None:
    st.title("🔎 Analyze an email")
    st.caption(
        "Offline parsing and heuristics first. VirusTotal and AI are optional, "
        "opt-in enhancements."
    )

    settings = get_settings()
    _render_sample_panel()
    text, source = _read_input()
    do_vt, do_ai, include_body, max_lookups = _render_options(settings)

    pending_text = st.session_state.pop("pending_text", None)
    effective_text = pending_text if pending_text is not None else text

    st.write("")
    run_clicked = st.button(
        "Run analysis", type="primary", width="stretch", key="run_analysis"
    )
    st.caption(
        "Nothing is sent by email, no link is opened, and no attachment is executed."
    )

    if run_clicked or pending_text is not None:
        if not effective_text.strip():
            st.warning("Paste an email, upload a file, or choose a sample first.")
            return

        byte_length = len(effective_text.encode("utf-8"))
        if byte_length > MAX_INPUT_BYTES:
            st.error("Input is larger than the 2 MB limit. Trim it and try again.")
            return

        result: AnalysisResult | None = None
        try:
            with st.status("Running analysis...", expanded=True) as status:
                result = analyze_email_text(
                    effective_text,
                    source=(
                        source
                        if pending_text is None
                        else "Built-in sample"
                    ),
                    do_reputation=do_vt,
                    do_ai=do_ai,
                    include_body_in_ai=include_body,
                    max_lookups=max_lookups,
                    settings=settings,
                    on_stage=status.write,
                )
                status.update(
                    label="Analysis complete",
                    state="complete",
                    expanded=False,
                )
        except Exception as error:  # noqa: BLE001 - show a friendly failure
            st.error(
                f"Analysis failed ({type(error).__name__}). "
                "Check the input format and try again."
            )
            with st.expander("Technical details"):
                st.exception(error)
            return

        if result is not None:
            try:
                save_result(result)
            except OSError:
                st.warning(
                    "Analysis completed, but it could not be saved to history "
                    "(check folder permissions)."
                )
            st.session_state["last_result"] = result
            st.session_state["last_result_saved_at"] = format_timestamp(
                result.created_at
            )
            st.toast("Analysis saved to history", icon="💾")

    result = st.session_state.get("last_result")
    if isinstance(result, AnalysisResult):
        _render_result(result)


def _render_result(result: AnalysisResult) -> None:
    st.divider()
    st.markdown(f"### {html.escape(result.subject or '(no subject)')}")
    st.caption(
        f"From {result.sender or 'unknown'} · {format_timestamp(result.created_at)} "
        f"· {result.source} · Report `{result.id}`"
    )

    st.markdown(
        risk_badge(result.risk.level, result.risk.score), unsafe_allow_html=True
    )

    metric_a, metric_b, metric_c, metric_d = st.columns(4)
    metric_a.metric("Risk score", f"{result.risk.score}/100")
    metric_b.metric("Findings", len(result.findings))
    metric_c.metric("IOCs", len(result.iocs))
    metric_d.metric(
        "Reputation",
        "Checked" if result.reputation_checked else "Not checked",
    )

    if result.risk.unknown_reputation:
        st.warning(
            "Reputation is **unknown / unverified**, not safe. "
            "Enable VirusTotal or inspect the indicators manually."
        )

    tab_overview, tab_findings, tab_iocs, tab_ai, tab_ticket, tab_report = st.tabs(
        [
            "Overview",
            f"Findings ({len(result.findings)})",
            f"IOCs & reputation ({len(result.iocs)})",
            "Explanation",
            "🛡️ SOC Action & Ticket",
            "Report",
        ]
    )

    with tab_overview:
        left, right = st.columns([3, 2])
        with left:
            st.markdown("**Message details**")
            st.dataframe(
                message_details_dataframe(result),
                hide_index=True,
                width="stretch",
            )
        with right:
            st.markdown("**Score breakdown**")
            breakdown = risk_breakdown_dataframe(result.risk)
            if breakdown.empty:
                st.caption("No scoring findings were produced.")
            else:
                st.dataframe(breakdown, hide_index=True, width="stretch")
            st.progress(min(1.0, result.risk.score / 100))

        st.markdown("**Top indicators**")
        top = [
            item
            for item in result.findings_sorted
            if item.severity != Severity.INFO
        ][:5]
        if top:
            for finding in top:
                st.markdown(finding_card(finding), unsafe_allow_html=True)
        else:
            st.success(
                "No strong phishing indicators were detected. This is not a "
                "guarantee that the email is safe."
            )

        if result.attachments:
            st.markdown("**Attachments (metadata only, never opened)**")
            st.dataframe(
                [
                    {
                        "Filename": item.filename,
                        "Type": item.content_type,
                        "Size (bytes)": item.size_bytes,
                    }
                    for item in result.attachments
                ],
                hide_index=True,
                width="stretch",
            )

    with tab_findings:
        severities = st.multiselect(
            "Filter by severity",
            options=[severity.value for severity in SEVERITY_ORDER],
            default=[severity.value for severity in SEVERITY_ORDER],
        )
        visible = [
            item
            for item in result.findings_sorted
            if item.severity.value in severities
        ]
        if not visible:
            st.info("No findings match the selected severities.")
        for category, group in findings_by_category(visible).items():
            st.markdown(f"#### {category} ({len(group)})")
            for finding in group:
                st.markdown(finding_card(finding), unsafe_allow_html=True)

    with tab_iocs:
        st.caption(
            "Indicators are defanged (`hxxps://bad[.]example`) and shown as text. "
            "This tool never opens them."
        )
        frame = iocs_dataframe(result.iocs)
        if frame.empty:
            st.info("No indicators were extracted.")
        else:
            st.dataframe(frame, hide_index=True, width="stretch")
            st.download_button(
                "Download indicators (CSV)",
                data=frame.to_csv(index=False),
                file_name=f"iocs-{result.id}.csv",
                mime="text/csv",
                key=f"csv_{result.id}",
            )

        st.markdown("**Reputation**")
        if result.reputations:
            st.dataframe(
                reputations_dataframe(result.reputations),
                hide_index=True,
                width="stretch",
            )
            if any(
                item.verdict == ReputationVerdict.MALICIOUS
                for item in result.reputations
            ):
                st.error("At least one indicator is flagged as malicious.")
            if any(
                item.verdict in {ReputationVerdict.UNKNOWN, ReputationVerdict.ERROR}
                for item in result.reputations
            ):
                st.warning(
                    "Some indicators are **unknown or failed to check**. "
                    "Unknown reputation is not the same as clean."
                )
            with st.expander("Vendor detections"):
                for item in result.reputations:
                    if item.detections:
                        st.markdown(
                            f"**{item.ioc_kind}: {html.escape(item.value)}**"
                        )
                        for detection in item.detections:
                            st.markdown(f"- {html.escape(detection)}")
        else:
            st.info(
                "No reputation lookup was performed. Every indicator remains "
                "**unknown / unverified**, which is not the same as safe."
            )

    with tab_ai:
        if result.ai_used:
            st.success("AI-generated explanation")
        else:
            st.info(result.ai_note or "Showing the built-in explanation.")
        st.markdown(result.ai_explanation)
        if result.ai_note:
            st.caption(result.ai_note)

    with tab_ticket:
        st.caption(
            "Ready-to-copy SOC incident note formatted for Jira Service Desk, "
            "TheHive, or ServiceNow, with containment playbook steps."
        )
        soc_ticket = build_soc_ticket(result)
        st.code(soc_ticket, language="text")

        st.markdown("**Perimeter Containment Exports**")
        blocklist_plain = build_ioc_blocklist(result, format_type="plain")
        blocklist_csv = build_ioc_blocklist(result, format_type="csv")

        col_bl1, col_bl2 = st.columns(2)
        col_bl1.download_button(
            "Download Firewall/DNS Blocklist (Text)",
            data=blocklist_plain,
            file_name=f"blocklist-{result.id}.txt",
            mime="text/plain",
            key=f"bl_txt_{result.id}",
            width="stretch",
        )
        col_bl2.download_button(
            "Download Blocklist (CSV)",
            data=blocklist_csv,
            file_name=f"blocklist-{result.id}.csv",
            mime="text/csv",
            key=f"bl_csv_{result.id}",
            width="stretch",
        )

    with tab_report:
        report = build_markdown(result)
        report_json = build_json(result)
        download_a, download_b = st.columns(2)
        download_a.download_button(
            "Download Markdown report",
            data=report,
            file_name=report_filename(result),
            mime="text/markdown",
            key=f"md_{result.id}",
            width="stretch",
        )
        download_b.download_button(
            "Download JSON result",
            data=report_json,
            file_name=json_filename(result),
            mime="application/json",
            key=f"json_{result.id}",
            width="stretch",
        )
        with st.expander("Preview report", expanded=False):
            st.markdown(report)
