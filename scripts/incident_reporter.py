#!/usr/bin/env python3
"""
Incident Report Generator
==========================

Produces professional Markdown and PDF incident reports from MariTime alert data.

The PDF is generated with fpdf2.  If fpdf2 is unavailable a graceful fallback
produces the Markdown report and logs a warning.

Usage::

    reporter = IncidentReporter()
    paths = reporter.generate_report(
        alerts=rule_engine.alerts,
        assets=inventory.get_assets(),
        stats=rule_engine.get_stats(),
        output_dir='reports',
    )
    print(paths['markdown_path'])
    print(paths['pdf_path'])   # None when fpdf2 is missing
"""

import json
import logging
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("incident_reporter")

# ---------------------------------------------------------------------------
# Optional fpdf2 import
# ---------------------------------------------------------------------------

try:
    from fpdf import FPDF  # type: ignore

    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False
    logger.warning(
        "fpdf2 is not installed — PDF generation is disabled.  "
        "Install with: pip install fpdf2"
    )

# ---------------------------------------------------------------------------
# Color / style constants
# ---------------------------------------------------------------------------

_ACCENT_R, _ACCENT_G, _ACCENT_B = 139, 92, 246  # #8b5cf6 — violet
_DARK_R, _DARK_G, _DARK_B = 30, 30, 46          # near-black body
_LIGHT_R, _LIGHT_G, _LIGHT_B = 240, 240, 248    # near-white page
_SEV_COLORS = {
    "critical": (220, 38, 38),
    "high": (234, 88, 12),
    "warning": (202, 138, 4),
    "info": (37, 99, 235),
}

# ---------------------------------------------------------------------------
# Recommendation mappings
# ---------------------------------------------------------------------------

_RECOMMENDATIONS: Dict[str, str] = {
    "function_code_anomaly": (
        "Enforce a strict Modbus function-code allowlist on all PLC-facing firewalls. "
        "Only permit function codes 0x03 (Read Holding Registers) during normal "
        "operations and 0x06 (Write Single Register) within approved maintenance windows."
    ),
    "value_anomaly": (
        "Deploy real-time value monitoring on all safety-critical and operational "
        "registers.  Configure hardware interlocks to reject out-of-range values "
        "at the field-device level."
    ),
    "source_ip_anomaly": (
        "Implement network segmentation (IEC 62443 zones and conduits) with strict "
        "allow-list firewall rules.  Unknown source IPs should be blocked at the "
        "perimeter and trigger immediate SOC notification."
    ),
    "flooding_attack": (
        "Rate-limit Modbus requests per source IP at the network layer. "
        "Consider deploying a purpose-built OT/ICS firewall or data diode for "
        "unidirectional enforcement."
    ),
    "safety_critical_violation": (
        "Immediately audit all writes to safety-critical registers (40006).  "
        "Enable Safety Instrumented System (SIS) lockout procedures and review "
        "Safety Integrity Level (SIL) compliance."
    ),
    "register_write_anomaly": (
        "Enforce write protection on read-only registers at both the firmware "
        "and network levels.  Review PLC access control lists."
    ),
    "timing_anomaly": (
        "Enforce time-based access controls so Modbus write operations are only "
        "permitted during approved maintenance windows.  Alert on-call engineers "
        "for any out-of-hours activity."
    ),
    "unauthorized_write": (
        "Mandate HMAC-SHA256 pre-authorization tokens for all Modbus write "
        "operations.  Rotate HMAC keys regularly and enforce short token TTLs "
        "(≤ 30 seconds)."
    ),
    "firmware_tampering": (
        "Engage incident response immediately.  Verify PLC firmware checksums "
        "against known-good backups.  Isolate affected devices and restore from "
        "a trusted backup.  Review physical and logical access logs."
    ),
    "recon_then_strike": (
        "Implement correlation rules to detect read-scan → write sequences.  "
        "Consider deploying honeypot registers to detect reconnaissance activity."
    ),
    "register_sweep": (
        "Detect and block sequential multi-register read bursts.  Whitelist only "
        "the specific registers each client legitimately requires (least privilege)."
    ),
    "pattern_anomaly": (
        "Refine the baseline model by collecting at least 72 hours of representative "
        "traffic before enabling anomaly detection in production mode."
    ),
    "new_device_discovered": (
        "Audit all newly discovered devices against the approved asset inventory. "
        "Disconnect unauthorised devices immediately and investigate their origin."
    ),
    "device_behavioral_drift": (
        "Review recent firmware or configuration updates to the affected device. "
        "Compare current operational profile against baseline and investigate "
        "discrepancies."
    ),
    "slow_burn": (
        "Tune detection thresholds for slow, low-volume attack patterns.  "
        "Increase baseline window to capture diurnal cycles."
    ),
    "safety_bypass_sequence": (
        "Immediately invoke safety shutdown procedures.  Investigate whether "
        "Safety Instrumented System (SIS) controls have been bypassed."
    ),
    "confidence_anomaly": (
        "Review ML model drift and retrain on recent traffic.  Validate that "
        "sensor readings are accurate and not being spoofed."
    ),
}


# ===========================================================================
# IncidentReporter
# ===========================================================================


class IncidentReporter:
    """Generate Markdown and PDF security incident reports.

    Reports are self-contained documents covering:

    * Executive summary
    * MITRE ATT&CK ICS coverage
    * Critical/high event timeline
    * Asset inventory snapshot
    * Auto-generated recommendations

    Example output filenames::

        incident_report_20260705_182215.md
        incident_report_20260705_182215.pdf
    """

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def generate_report(
        self,
        alerts: List[Dict],
        assets: List[Dict],
        stats: Dict,
        output_dir: str = ".",
    ) -> Dict[str, Optional[str]]:
        """Generate Markdown and optionally PDF reports.

        Args:
            alerts:     List of alert dicts from the rule engine.
            assets:     List of asset dicts from asset_inventory.get_assets().
            stats:      Dict with keys: packets_processed, alerts_generated,
                        rules_triggered, uptime (seconds, optional).
            output_dir: Directory where report files are written
                        (created if it does not exist).

        Returns:
            ::

                {
                    "markdown_path": "/abs/path/incident_report_YYYYMMDD_HHMMSS.md",
                    "pdf_path":      "/abs/path/incident_report_YYYYMMDD_HHMMSS.pdf",
                                    # or None if fpdf2 unavailable
                }
        """
        os.makedirs(output_dir, exist_ok=True)

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"incident_report_{timestamp_str}"
        md_path = os.path.join(output_dir, base_name + ".md")
        pdf_path = os.path.join(output_dir, base_name + ".pdf")

        # Pre-compute shared analysis data
        analysis = self._analyse(alerts, assets, stats)

        # Write Markdown
        md_content = self._build_markdown(analysis, timestamp_str)
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(md_content)
        logger.info("Markdown report written: %s", md_path)

        # Write PDF
        pdf_out: Optional[str] = None
        if FPDF_AVAILABLE:
            try:
                self._build_pdf(analysis, timestamp_str, pdf_path)
                pdf_out = os.path.abspath(pdf_path)
                logger.info("PDF report written: %s", pdf_path)
            except Exception as exc:
                logger.error("PDF generation failed: %s", exc, exc_info=True)
        else:
            logger.warning(
                "fpdf2 not installed — PDF report skipped.  "
                "Markdown report is at %s",
                md_path,
            )

        return {
            "markdown_path": os.path.abspath(md_path),
            "pdf_path": pdf_out,
        }

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def _analyse(
        self,
        alerts: List[Dict],
        assets: List[Dict],
        stats: Dict,
    ) -> Dict[str, Any]:
        """Compute all derived data required for both Markdown and PDF reports."""
        total_alerts = len(alerts)

        # Severity counts
        sev_counts: Counter = Counter(a.get("severity", "unknown") for a in alerts)

        # Top threat type
        type_counts: Counter = Counter(a.get("alert_type", "unknown") for a in alerts)
        top_threat = type_counts.most_common(1)[0][0] if type_counts else "None"

        # MITRE coverage
        mitre_counter: Counter = Counter()
        mitre_names: Dict[str, str] = {}
        for a in alerts:
            mid = a.get("mitre_id") or a.get("analysis_details", {}).get("mitre_id")
            mname = a.get("mitre_name") or a.get("analysis_details", {}).get("mitre_name", "")
            if mid:
                mitre_counter[mid] += 1
                mitre_names[mid] = mname

        # Critical/high timeline (last 50)
        severe_alerts = [
            a for a in alerts
            if a.get("severity") in ("critical", "high")
        ][-50:]

        # Asset summary
        total_assets = len(assets)
        unknown_assets = sum(1 for a in assets if a.get("status") == "unknown" or a.get("is_unknown", False))
        attacker_assets = sum(1 for a in assets if a.get("is_attacker") or a.get("flagged_attacker", False))

        # Which alert types fired?
        fired_types = set(a.get("alert_type", "") for a in alerts)

        # Uptime string
        uptime_secs = stats.get("uptime", 0)
        if uptime_secs:
            h, rem = divmod(int(uptime_secs), 3600)
            m, s = divmod(rem, 60)
            uptime_str = f"{h}h {m}m {s}s"
        else:
            uptime_str = "N/A"

        # Recommendations (only for fired types)
        recommendations: List[Tuple[str, str]] = [
            (alert_type, _RECOMMENDATIONS[alert_type])
            for alert_type in sorted(fired_types)
            if alert_type in _RECOMMENDATIONS
        ]

        return {
            "total_alerts": total_alerts,
            "sev_counts": dict(sev_counts),
            "top_threat": top_threat,
            "type_counts": dict(type_counts.most_common(20)),
            "mitre_counter": dict(mitre_counter),
            "mitre_names": mitre_names,
            "severe_alerts": severe_alerts,
            "total_assets": total_assets,
            "unknown_assets": unknown_assets,
            "attacker_assets": attacker_assets,
            "fired_types": fired_types,
            "recommendations": recommendations,
            "packets_processed": stats.get("packets_processed", 0),
            "rules_triggered": stats.get("rules_triggered", {}),
            "uptime_str": uptime_str,
        }

    # ------------------------------------------------------------------
    # Markdown builder
    # ------------------------------------------------------------------

    def _build_markdown(self, a: Dict[str, Any], ts: str) -> str:
        """Render the full Markdown report string."""
        lines: List[str] = []

        # ── Header ──────────────────────────────────────────────────────
        lines.append("# MARI TIME — Security Incident Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"**Report ID:** `{ts}`")
        lines.append("")
        lines.append("---")
        lines.append("")

        # ── Executive Summary ───────────────────────────────────────────
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Alerts | **{a['total_alerts']}** |")
        lines.append(f"| Critical Alerts | {a['sev_counts'].get('critical', 0)} |")
        lines.append(f"| High Alerts | {a['sev_counts'].get('high', 0)} |")
        lines.append(f"| Warning Alerts | {a['sev_counts'].get('warning', 0)} |")
        lines.append(f"| Info Alerts | {a['sev_counts'].get('info', 0)} |")
        lines.append(f"| Top Threat Type | `{a['top_threat']}` |")
        lines.append(f"| Packets Processed | {a['packets_processed']:,} |")
        lines.append(f"| Monitoring Uptime | {a['uptime_str']} |")
        lines.append("")

        # ── MITRE Coverage ──────────────────────────────────────────────
        lines.append("## 2. MITRE ATT&CK for ICS Coverage")
        lines.append("")
        if a["mitre_counter"]:
            lines.append("| Technique ID | Name | Alert Count |")
            lines.append("|-------------|------|-------------|")
            sorted_mitre = sorted(
                a["mitre_counter"].items(), key=lambda x: x[1], reverse=True
            )
            for mid, count in sorted_mitre:
                name = a["mitre_names"].get(mid, "")
                lines.append(f"| `{mid}` | {name} | {count} |")
        else:
            lines.append("*No MITRE techniques mapped in this reporting period.*")
        lines.append("")

        # ── Critical Events Timeline ────────────────────────────────────
        lines.append("## 3. Critical / High Events Timeline (Last 50)")
        lines.append("")
        if a["severe_alerts"]:
            lines.append("| Time | Severity | Source IP | Alert Type | MITRE ID |")
            lines.append("|------|----------|-----------|------------|----------|")
            for alert in a["severe_alerts"]:
                ts_fmt = alert.get("timestamp", "")[:19].replace("T", " ")
                sev = alert.get("severity", "").upper()
                src = alert.get(
                    "source_ip",
                    alert.get("packet_details", {}).get("source_ip", "—"),
                )
                atype = alert.get("alert_type", "—")
                mid = alert.get("mitre_id", "—")
                lines.append(f"| {ts_fmt} | {sev} | {src} | `{atype}` | `{mid}` |")
        else:
            lines.append("*No critical or high alerts recorded.*")
        lines.append("")

        # ── Asset Inventory ─────────────────────────────────────────────
        lines.append("## 4. Asset Inventory Snapshot")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Devices | {a['total_assets']} |")
        lines.append(f"| Unknown Devices | {a['unknown_assets']} |")
        lines.append(f"| Flagged as Attacker | {a['attacker_assets']} |")
        lines.append("")

        # ── Recommendations ─────────────────────────────────────────────
        lines.append("## 5. Recommendations")
        lines.append("")
        if a["recommendations"]:
            for idx, (alert_type, rec_text) in enumerate(a["recommendations"], 1):
                lines.append(f"### 5.{idx} {alert_type.replace('_', ' ').title()}")
                lines.append("")
                lines.append(rec_text)
                lines.append("")
        else:
            lines.append("*No specific recommendations — system appears healthy.*")
            lines.append("")

        # ── Footer ───────────────────────────────────────────────────────
        lines.append("---")
        lines.append("")
        lines.append(
            "*This report was automatically generated by the MariTime Modbus "
            "OT/ICS Security Monitor.  Treat the contents as CONFIDENTIAL.*"
        )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # PDF builder
    # ------------------------------------------------------------------

    def _build_pdf(
        self,
        a: Dict[str, Any],
        ts: str,
        output_path: str,
    ) -> None:
        """Render the full PDF report using fpdf2."""

        class _PDF(FPDF):  # type: ignore
            def header(self) -> None:
                # Company name as logo
                self.set_font("Helvetica", "B", 22)
                self.set_text_color(_ACCENT_R, _ACCENT_G, _ACCENT_B)
                self.cell(0, 12, "MARI TIME", align="L", new_x="LMARGIN", new_y="NEXT")
                self.set_font("Helvetica", "", 9)
                self.set_text_color(120, 120, 140)
                self.cell(
                    0, 5,
                    "Modbus OT/ICS Security Monitor — Incident Report",
                    align="L",
                    new_x="LMARGIN",
                    new_y="NEXT",
                )
                self.ln(2)
                # Violet rule
                self.set_draw_color(_ACCENT_R, _ACCENT_G, _ACCENT_B)
                self.set_line_width(0.8)
                self.line(
                    self.l_margin,
                    self.get_y(),
                    self.w - self.r_margin,
                    self.get_y(),
                )
                self.ln(4)

            def footer(self) -> None:
                self.set_y(-15)
                self.set_font("Helvetica", "I", 8)
                self.set_text_color(150, 150, 160)
                self.cell(
                    0, 10,
                    f"Page {self.page_no()} — CONFIDENTIAL — MariTime Security Monitor",
                    align="C",
                )

        pdf = _PDF()
        pdf.set_margins(left=18, top=20, right=18)
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()

        def section_title(title: str) -> None:
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(_ACCENT_R, _ACCENT_G, _ACCENT_B)
            pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
            pdf.set_draw_color(_ACCENT_R, _ACCENT_G, _ACCENT_B)
            pdf.set_line_width(0.3)
            pdf.line(
                pdf.l_margin,
                pdf.get_y(),
                pdf.w - pdf.r_margin,
                pdf.get_y(),
            )
            pdf.ln(3)
            pdf.set_text_color(_DARK_R, _DARK_G, _DARK_B)

        def body_text(text: str) -> None:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(_DARK_R, _DARK_G, _DARK_B)
            pdf.multi_cell(0, 5, text)
            pdf.ln(2)

        def kv_row(label: str, value: str, accent: bool = False) -> None:
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(80, 80, 100)
            pdf.cell(65, 6, label, border="B")
            if accent:
                pdf.set_text_color(_ACCENT_R, _ACCENT_G, _ACCENT_B)
            else:
                pdf.set_text_color(_DARK_R, _DARK_G, _DARK_B)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 6, value, border="B", new_x="LMARGIN", new_y="NEXT")

        def table_header(*cols: Tuple[str, int]) -> None:
            pdf.set_fill_color(_ACCENT_R, _ACCENT_G, _ACCENT_B)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 8)
            for label, width in cols:
                pdf.cell(width, 6, label, border=1, fill=True)
            pdf.ln()
            pdf.set_text_color(_DARK_R, _DARK_G, _DARK_B)

        # ── Report metadata ─────────────────────────────────────────────
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(100, 100, 120)
        pdf.cell(
            0, 6,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}   "
            f"Report ID: {ts}",
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.ln(2)

        # ── 1. Executive Summary ────────────────────────────────────────
        section_title("1. Executive Summary")
        kv_row("Total Alerts", str(a["total_alerts"]), accent=True)
        kv_row("Critical Alerts", str(a["sev_counts"].get("critical", 0)))
        kv_row("High Alerts", str(a["sev_counts"].get("high", 0)))
        kv_row("Warning Alerts", str(a["sev_counts"].get("warning", 0)))
        kv_row("Top Threat Type", a["top_threat"])
        kv_row("Packets Processed", f"{a['packets_processed']:,}")
        kv_row("Monitoring Uptime", a["uptime_str"])
        pdf.ln(4)

        # ── 2. MITRE ATT&CK Coverage ────────────────────────────────────
        section_title("2. MITRE ATT&CK for ICS Coverage")
        if a["mitre_counter"]:
            col_widths = (30, 110, 34)
            table_header(
                ("Technique ID", col_widths[0]),
                ("Name", col_widths[1]),
                ("Alert Count", col_widths[2]),
            )
            sorted_mitre = sorted(
                a["mitre_counter"].items(), key=lambda x: x[1], reverse=True
            )
            for i, (mid, count) in enumerate(sorted_mitre):
                fill = i % 2 == 0
                pdf.set_fill_color(240, 238, 252) if fill else pdf.set_fill_color(255, 255, 255)
                pdf.set_font("Helvetica", "B", 8)
                pdf.cell(col_widths[0], 5, mid, border=1, fill=fill)
                pdf.set_font("Helvetica", "", 8)
                pdf.cell(col_widths[1], 5, a["mitre_names"].get(mid, ""), border=1, fill=fill)
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(_ACCENT_R, _ACCENT_G, _ACCENT_B)
                pdf.cell(col_widths[2], 5, str(count), border=1, fill=fill, align="C")
                pdf.set_text_color(_DARK_R, _DARK_G, _DARK_B)
                pdf.ln()
        else:
            body_text("No MITRE techniques mapped in this reporting period.")
        pdf.ln(4)

        # ── 3. Critical Events Timeline ─────────────────────────────────
        section_title("3. Critical / High Events Timeline (Last 50)")
        if a["severe_alerts"]:
            cw = (32, 18, 30, 50, 22, 22)
            table_header(
                ("Time", cw[0]),
                ("Severity", cw[1]),
                ("Source IP", cw[2]),
                ("Alert Type", cw[3]),
                ("MITRE", cw[4]),
            )
            for i, alert in enumerate(a["severe_alerts"]):
                fill = i % 2 == 0
                pdf.set_fill_color(240, 238, 252) if fill else pdf.set_fill_color(255, 255, 255)
                ts_fmt = alert.get("timestamp", "")[:19].replace("T", " ")
                sev = alert.get("severity", "").upper()
                src_ip = alert.get(
                    "source_ip",
                    alert.get("packet_details", {}).get("source_ip", "—"),
                )
                atype = alert.get("alert_type", "—")
                mid = alert.get("mitre_id", "—")

                # Severity colour
                sev_rgb = _SEV_COLORS.get(alert.get("severity", ""), (60, 60, 60))
                pdf.set_font("Helvetica", "", 7)
                pdf.cell(cw[0], 5, ts_fmt, border=1, fill=fill)
                pdf.set_text_color(*sev_rgb)
                pdf.set_font("Helvetica", "B", 7)
                pdf.cell(cw[1], 5, sev, border=1, fill=fill, align="C")
                pdf.set_text_color(_DARK_R, _DARK_G, _DARK_B)
                pdf.set_font("Helvetica", "", 7)
                pdf.cell(cw[2], 5, str(src_ip)[:18], border=1, fill=fill)
                pdf.cell(cw[3], 5, str(atype)[:35], border=1, fill=fill)
                pdf.set_text_color(_ACCENT_R, _ACCENT_G, _ACCENT_B)
                pdf.cell(cw[4], 5, str(mid), border=1, fill=fill)
                pdf.set_text_color(_DARK_R, _DARK_G, _DARK_B)
                pdf.ln()
        else:
            body_text("No critical or high alerts recorded.")
        pdf.ln(4)

        # ── 4. Asset Inventory ─────────────────────────────────────────
        section_title("4. Asset Inventory Snapshot")
        kv_row("Total Devices", str(a["total_assets"]))
        kv_row("Unknown Devices", str(a["unknown_assets"]))
        kv_row("Flagged as Attacker", str(a["attacker_assets"]))
        pdf.ln(4)

        # ── 5. Recommendations ─────────────────────────────────────────
        section_title("5. Recommendations")
        if a["recommendations"]:
            for idx, (alert_type, rec_text) in enumerate(a["recommendations"], 1):
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(_ACCENT_R, _ACCENT_G, _ACCENT_B)
                label = f"5.{idx}  {alert_type.replace('_', ' ').title()}"
                pdf.cell(0, 6, label, new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(_DARK_R, _DARK_G, _DARK_B)
                pdf.set_font("Helvetica", "", 9)
                pdf.multi_cell(0, 5, rec_text)
                pdf.ln(2)
        else:
            body_text("No specific recommendations — system appears healthy.")

        # Footer note
        pdf.ln(6)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(140, 140, 160)
        pdf.multi_cell(
            0, 5,
            "This report was automatically generated by the MariTime Modbus "
            "OT/ICS Security Monitor. Treat the contents as CONFIDENTIAL.",
        )

        pdf.output(output_path)
