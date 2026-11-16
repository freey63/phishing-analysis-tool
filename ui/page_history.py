"""History dashboard: metrics, trends, saved reports and deletion."""

from __future__ import annotations

import html

import streamlit as st

from core.models import AnalysisResult, SEVERITY_ICONS, SEVERITY_ORDER
from core.report_builder import (
    build_json,
    build_markdown,
    json_filename,
    report_filename,
)
from storage.history import (
    delete_record,
    history_stats,
    load_records,
    records_to_frame,
)
from ui.components import (
    format_timestamp,
    risk_badge,
)

_RISK_ORDER = ["Low", "Medium", "High", "Critical"]


def _label(row) -> str:
    timestamp = row["created_at"]
    formatted = (
        timestamp.strftime("%Y-%m-%d %H:%M") if hasattr(timestamp, "strftime") else "—"
    )
    subject = str(row["subject"])[:70]
    return f"{formatted} · {row['risk_level']} ({row['risk_score']}) · {subject}"


def render() -> None:
    st.title("📊 Analysis history")
    st.caption(
        "Stored locally in `data/history.jsonl`. Only structured results are "
        "saved - never the raw email body."
    )

    records = load_records()
    if not records:
        st.info(
            "No analyses yet. Open **Analyze**, try one of the sample emails, and "
            "your results will appear here."
        )
        return

    frame = records_to_frame(records)
    stats = history_stats(frame)

    metric_a, metric_b, metric_c, metric_d = st.columns(4)
    metric_a.metric("Analyses", stats["total"])
    metric_b.metric("High / Critical", stats["high_risk"])
    metric_c.metric("Average score", f"{stats['average_score']}/100")
    metric_d.metric("Indicators seen", stats["iocs"])

    with st.expander("Filters", expanded=True):
        filter_a, filter_b = st.columns([2, 3])
        selected_risks = filter_a.multiselect(
            "Risk level",
            options=_RISK_ORDER,
            default=_RISK_ORDER,
        )
        query = filter_b.text_input(
            "Search subject, sender or ID",
            placeholder="e.g. invoice, microsoft, a1b2c3d4",
        ).strip()

    filtered = frame[frame["risk_level"].isin(selected_risks)]
    if query:
        mask = (
            filtered["subject"].str.contains(query, case=False, na=False)
            | filtered["sender"].str.contains(query, case=False, na=False)
            | filtered["id"].str.contains(query, case=False, na=False)
        )
        filtered = filtered[mask]

    if filtered.empty:
        st.warning("No analyses match the current filters.")
        return

    chart_a, chart_b = st.columns([2, 3])
    with chart_a:
        st.markdown("**Risk distribution**")
        counts = filtered["risk_level"].value_counts().reindex(
            _RISK_ORDER, fill_value=0
        )
        st.bar_chart(counts.rename("Analyses"))
    with chart_b:
        st.markdown("**Score over time**")
        trend = (
            filtered.dropna(subset=["created_at"])
            .sort_values("created_at")
            .set_index("created_at")["risk_score"]
        )
        if trend.empty:
            st.caption("No valid timestamps to plot.")
        else:
            st.line_chart(trend.rename("Risk score"))

    st.markdown("**Saved analyses**")
    display = filtered.assign(
        created_at=filtered["created_at"].dt.strftime("%Y-%m-%d %H:%M")
    )[
        [
            "created_at",
            "subject",
            "sender",
            "risk_level",
            "risk_score",
            "findings",
            "iocs",
        ]
    ].rename(
        columns={
            "created_at": "When (UTC)",
            "subject": "Subject",
            "sender": "From",
            "risk_level": "Risk",
            "risk_score": "Score",
            "findings": "Findings",
            "iocs": "IOCs",
        }
    )
    st.dataframe(display, hide_index=True, width="stretch")

    st.divider()
    st.subheader("Open a saved analysis")

    by_id = {record["id"]: record for record in records}
    all_rows = {row["id"]: row for _, row in frame.iterrows()}
    visible_ids = set(filtered["id"])
    options = [record_id for record_id in all_rows if record_id in visible_ids]

    selected_id = st.selectbox(
        "Analysis",
        options=options,
        format_func=lambda record_id: _label(all_rows[record_id]),
    )

    record = by_id[selected_id]
    result = AnalysisResult.from_dict(record["result"])
    report = build_markdown(result)

    st.markdown(f"#### {html.escape(result.subject or '(no subject)')}")
    st.caption(
        f"From {result.sender or 'unknown'} · "
        f"{format_timestamp(result.created_at)} · ID `{result.id}`"
    )
    st.markdown(
        risk_badge(result.risk.level, result.risk.score), unsafe_allow_html=True
    )

    detail_a, detail_b, detail_c = st.columns(3)
    detail_a.metric("Findings", len(result.findings))
    detail_b.metric("IOCs", len(result.iocs))
    detail_c.metric(
        "Reputation", "Checked" if result.reputation_checked else "Not checked"
    )

    with st.expander("Findings summary", expanded=False):
        for severity in SEVERITY_ORDER:
            group = result.findings_by_severity(severity)
            if not group:
                continue
            st.markdown(
                f"**{SEVERITY_ICONS[severity]} {severity.value} ({len(group)})**"
            )
            for finding in group:
                st.markdown(f"- {finding.title} — {finding.detail}")

    with st.expander("Report preview", expanded=False):
        st.markdown(report)

    download_a, download_b = st.columns(2)
    download_a.download_button(
        "Download Markdown",
        data=report,
        file_name=report_filename(result),
        mime="text/markdown",
        key=f"history_md_{result.id}",
        width="stretch",
    )
    download_b.download_button(
        "Download JSON",
        data=build_json(result),
        file_name=json_filename(result),
        mime="application/json",
        key=f"history_json_{result.id}",
        width="stretch",
    )

    st.divider()
    confirm = st.checkbox(
        "I understand deleting this analysis cannot be undone.",
        key=f"confirm_delete_{result.id}",
    )
    if st.button(
        "Delete this analysis",
        disabled=not confirm,
        key=f"delete_{result.id}",
    ):
        if delete_record(result.id):
            st.success("Analysis deleted.")
            st.rerun()
        else:
            st.error("That analysis could not be found.")
