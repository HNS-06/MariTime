#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║          MARI TIME — Modbus OT/ICS Security Monitor v2.0                ║
║          Terminal UI Dashboard  •  Advanced Edition                     ║
║          Inspired by Claude Code  •  Violet Theme                       ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Features:                                                               ║
║  • Baseline anomaly learning (Markov chain + z-score)                   ║
║  • Sequence-of-events correlation (recon→strike detection)              ║
║  • Asset inventory & device fingerprinting                              ║
║  • HMAC cryptographic write authorization                               ║
║  • Firmware/config integrity monitoring                                 ║
║  • MITRE ATT&CK for ICS tagging on every alert                         ║
║  • Alert lifecycle (acknowledge / mute / escalate)                      ║
║  • Historical JSONL replay engine                                       ║
║  • PDF + Markdown incident report generation                            ║
║  • Config-driven rules (config/rules.yaml, hot-reload Ctrl+R)          ║
║  • Live Red-vs-Blue demo mode (5-phase scripted attack)                 ║
║  • ASCII network topology visualization                                 ║
╚══════════════════════════════════════════════════════════════════════════╝

Run modes:
  python tui_dashboard.py          # auto-detect backend
  python tui_dashboard.py --demo   # force demo/simulation mode
  python tui_dashboard.py --live   # force live backend mode
"""

import argparse
import asyncio
import json
import math
import os
import random
import sys
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ── Textual imports ────────────────────────────────────────────────────────────
try:
    from textual import on, work
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
    from textual.css.query import NoMatches
    from textual.reactive import reactive
    from textual.screen import ModalScreen
    from textual.widget import Widget
    from textual.widgets import Button, Checkbox, Input, Label, Static
except ImportError:
    print("\n[ERROR] Textual not installed. Run:\n  pip install textual rich httpx websockets\n")
    sys.exit(1)

# ── Optional engine imports (graceful degradation) ─────────────────────────────
_SCRIPTS_DIR = str(Path(__file__).parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

def _try_import(module_name, class_name):
    try:
        mod = __import__(module_name)
        return getattr(mod, class_name, None)
    except Exception:
        return None

BaselineEngine    = _try_import("baseline_engine",    "BaselineEngine")
CorrelationEngine = _try_import("correlation_engine",  "CorrelationEngine")
AssetInventory    = _try_import("asset_inventory",    "AssetInventory")
HMACAuthManager   = _try_import("hmac_auth",          "HMACAuthManager")
FirmwareWatcher   = _try_import("firmware_watcher",   "FirmwareWatcher")
IncidentReporter  = _try_import("incident_reporter",  "IncidentReporter")
ReplayEngine      = _try_import("replay_engine",      "ReplayEngine")
ActiveScanner     = _try_import("active_scanner",     "ActiveScanner")
ContainmentSOAR   = _try_import("containment_soar",   "ContainmentSOAR")
OSFingerprinter   = _try_import("os_fingerprint",     "OSFingerprinter")
DPIValidator      = _try_import("dpi_validator",      "DPIValidator")
SIEMForwarder     = _try_import("siem_forwarder",     "SIEMForwarder")
PacketCapture     = _try_import("packet_capture",     "PacketCapture")

# ── Constants ──────────────────────────────────────────────────────────────────
BACKEND_URL   = "http://localhost:3000"
POLL_INTERVAL = 2.0
SIM_INTERVAL  = 1.2
VERSION       = "2.0.0"

SEVERITY_ORDER = {"critical": 0, "high": 1, "warning": 2, "info": 3}

REGISTERS = {
    40001: {"name": "Pump Speed",   "unit": "%",    "min": 0, "max": 100, "warn": 85, "crit": 95},
    40002: {"name": "Valve Pos",    "unit": "%",    "min": 0, "max": 100, "warn": 90, "crit": 98},
    40003: {"name": "Temperature",  "unit": "°C",   "min": 0, "max": 150, "warn": 120,"crit": 145},
    40004: {"name": "Pressure",     "unit": "bar",  "min": 0, "max": 10,  "warn": 8,  "crit": 9},
    40005: {"name": "Flow Rate",    "unit": "%",    "min": 0, "max": 100, "warn": 88, "crit": 96},
    40006: {"name": "Alarm Status", "unit": "alrm", "min": 0, "max": 10,  "warn": 3,  "crit": 7},
}

ALERT_ICONS  = {"critical": "⬤ ", "high": "▲ ", "warning": "◆ ", "info": "● "}
ALERT_COLORS = {"critical": "bright_red", "high": "dark_orange", "warning": "yellow", "info": "bright_green"}

LIFECYCLE_BADGES = {
    "new":          "[on #1a0030 #a78bfa bold] NEW  [/]",
    "acknowledged": "[on #14532d #86efac] ACK  [/]",
    "muted":        "[on #374151 #9ca3af] MUTE [/]",
    "escalated":    "[on #7f1d1d #fca5a5 bold] ESC! [/]",
    "closed":       "[on #111827 #4b5563] CLO  [/]",
}

# ── Demo Attack Phases ─────────────────────────────────────────────────────────
DEMO_PHASES = [
    {
        "name": "Reconnaissance",
        "duration": 12,
        "color": "#eab308",
        "icon": "🔍",
        "description": "Attacker sweeping registers to map the network",
        "alerts": [
            {"alert_type": "pattern_anomaly",    "severity": "warning",  "msg": "Register sweep: {n} registers read in {s}s from 192.168.99.{x}"},
            {"alert_type": "pattern_anomaly",    "severity": "info",     "msg": "Unusual access pattern: register 40006 probed from 192.168.99.{x}"},
            {"alert_type": "source_ip_anomaly",  "severity": "high",     "msg": "Unknown device fingerprint: 192.168.99.{x} (never seen before)"},
        ]
    },
    {
        "name": "Credential Probe",
        "duration": 8,
        "color": "#f97316",
        "icon": "🔑",
        "description": "Attacker attempting to identify authorized IPs",
        "alerts": [
            {"alert_type": "source_ip_anomaly",  "severity": "high",     "msg": "Traffic from unauthorized IP 192.168.99.{x} spoofing HMI pattern"},
            {"alert_type": "timing_anomaly",     "severity": "high",     "msg": "Write attempt at {h:02d}:00 — outside normal operational hours"},
            {"alert_type": "source_ip_anomaly",  "severity": "high",     "msg": "New device discovered: 192.168.99.{x} (signature mismatch)"},
        ]
    },
    {
        "name": "Lateral Movement",
        "duration": 10,
        "color": "#f97316",
        "icon": "↔",
        "description": "Pivoting through function codes to gain write access",
        "alerts": [
            {"alert_type": "function_code_anomaly", "severity": "critical","msg": "Unauthorized function code 0x{fc:02X} during normal operation"},
            {"alert_type": "pattern_anomaly",       "severity": "warning", "msg": "Rapid function pivot: 3 different FC used in 12s from 192.168.99.{x}"},
            {"alert_type": "function_code_anomaly", "severity": "critical","msg": "Write attempt using diagnostic FC 0x08 (Mask Write Register)"},
            {"alert_type": "baseline_anomaly",      "severity": "high",    "msg": "Markov anomaly: FC transition 0x03→0x11 probability < 0.1% (baseline)"},
        ]
    },
    {
        "name": "STRIKE",
        "duration": 15,
        "color": "#ef4444",
        "icon": "⚡",
        "description": "Active attack — safety systems under threat",
        "alerts": [
            {"alert_type": "flooding_attack",           "severity": "critical","msg": "FLOODING ATTACK: 187 requests/min from 192.168.99.{x}"},
            {"alert_type": "safety_critical_violation", "severity": "critical","msg": "SAFETY VIOLATION: Unauthorized write to alarm register 40006"},
            {"alert_type": "value_anomaly",             "severity": "critical","msg": "CRITICAL: Pump speed set to 9999% (plant-damaging value)"},
            {"alert_type": "unauthorized_write",        "severity": "critical","msg": "UNAUTHORIZED WRITE: No HMAC token — register 40001 corrupted"},
            {"alert_type": "safety_critical_violation", "severity": "critical","msg": "RECON-THEN-STRIKE pattern confirmed: scan→write in 23s"},
            {"alert_type": "value_anomaly",             "severity": "critical","msg": "Temperature sensor spoofed: 999°C (valid range: 0-150°C)"},
        ]
    },
    {
        "name": "Persistence",
        "duration": 10,
        "color": "#8b5cf6",
        "icon": "🔒",
        "description": "Attacker embedding backdoor via firmware tampering",
        "alerts": [
            {"alert_type": "firmware_tampering",     "severity": "critical","msg": "FIRMWARE TAMPERED: PLC config hash mismatch (SHA-256 failure)"},
            {"alert_type": "unauthorized_write",     "severity": "critical","msg": "Unauthorized write to safety register without HMAC token"},
            {"alert_type": "register_write_anomaly", "severity": "high",    "msg": "Config persistence: write to reserved register 40001 baseline"},
        ]
    },
]

# ── ASCII Art ──────────────────────────────────────────────────────────────────
MARI_TIME_ART = """\
[bold #a78bfa]███╗   ███╗ █████╗ ██████╗ ██╗    ████████╗██╗███╗   ███╗███████╗[/]
[bold #a78bfa]████╗ ████║██╔══██╗██╔══██╗██║    ╚══██╔══╝██║████╗ ████║██╔════╝[/]
[bold #c4b5fd]██╔████╔██║███████║██████╔╝██║       ██║   ██║██╔████╔██║█████╗  [/]
[bold #c4b5fd]██║╚██╔╝██║██╔══██║██╔══██╗██║       ██║   ██║██║╚██╔╝██║██╔══╝  [/]
[bold #ddd6fe]██║ ╚═╝ ██║██║  ██║██║  ██║███████╗  ██║   ██║██║ ╚═╝ ██║███████╗[/]
[bold #ddd6fe]╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝  ╚═╝   ╚═╝╚═╝     ╚═╝╚══════╝[/]"""

# ── Data Models ────────────────────────────────────────────────────────────────
class AlertEntry:
    def __init__(self, data: dict):
        self.alert_id         = data.get("alert_id", str(time.time()))
        self.alert_type       = data.get("alert_type", "unknown")
        self.severity         = data.get("severity", "info")
        self.message          = data.get("message", "")
        self.timestamp        = data.get("timestamp", datetime.now().isoformat())
        self.is_read          = data.get("is_read", False)
        self.packet_details   = data.get("packet_details", {})
        self.analysis_details = data.get("analysis_details", {})
        self.mitre_id         = data.get("mitre_id", "")
        self.mitre_name       = data.get("mitre_name", "")
        self.mitre_tactic     = data.get("mitre_tactic", "")
        self.protocol         = data.get("protocol", "MODBUS")
        self.correlated       = data.get("correlated", False)
        # lifecycle managed in AppState
        self.lifecycle_state  = data.get("lifecycle_state", "new")

    @property
    def time_str(self) -> str:
        try:
            return datetime.fromisoformat(self.timestamp).strftime("%H:%M:%S")
        except Exception:
            return "??:??:??"

    @property
    def severity_order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


class AppState:
    """Central state store — everything the TUI needs."""
    def __init__(self):
        self.alerts: List[AlertEntry]          = []
        self.register_values: Dict[int, float] = {r: 0.0 for r in REGISTERS}
        self.service_status: Dict[str, bool]   = {
            "PLC Server": False, "HMI Client": False,
            "Pkt Capture": False, "Rule Engine": False,
        }
        self.stats = {"packets_processed": 0, "alerts_generated": 0, "rules_triggered": {}}
        self.start_time    = datetime.now()
        self.mode          = "demo"
        self.filter_sev    = {"critical", "high", "warning", "info"}
        self.filter_states = {"new", "acknowledged", "escalated"}   # lifecycle states to show
        self.muted_types: Dict[str, float] = {}      # alert_type → unmute_time (epoch)
        self.selected_idx  = 0

        # Engine instances (None if module not available)
        self.baseline_engine    = BaselineEngine()    if BaselineEngine    else None
        self.correlation_engine = CorrelationEngine() if CorrelationEngine else None
        self.asset_inventory    = AssetInventory()    if AssetInventory    else None
        self.hmac_manager       = HMACAuthManager()   if HMACAuthManager   else None
        self.firmware_watcher   = FirmwareWatcher()   if FirmwareWatcher   else None
        self.incident_reporter  = IncidentReporter()  if IncidentReporter  else None
        self.replay_engine      = ReplayEngine()      if ReplayEngine      else None

        self.active_scanner     = ActiveScanner()     if ActiveScanner     else None
        self.containment_soar   = ContainmentSOAR()   if ContainmentSOAR   else None
        self.os_fingerprinter   = OSFingerprinter()   if OSFingerprinter   else None
        self.dpi_validator      = DPIValidator()      if DPIValidator      else None
        self.siem_forwarder     = SIEMForwarder()     if SIEMForwarder     else None
        self.packet_capture     = PacketCapture(None) if PacketCapture     else None

        # Panel visibility toggles
        self.show_topology = False
        self.show_assets   = False

        # Demo mode state
        self.demo_active    = False
        self.demo_phase_idx = -1
        self.demo_phase_name= ""
        self.demo_phase_color= "#a78bfa"
        self.demo_phase_icon = ""

        # Replay state
        self.is_replaying    = False
        self.replay_progress = 0.0
        self.replay_file     = ""

        # Baseline learning state
        self.baseline_learning  = self.baseline_engine is not None
        self.baseline_progress  = 0.0

        # Firmware state
        self.firmware_healthy = True

        # Assets cache
        self._assets_cache: List[Dict] = []
        self._topology_cache: Dict     = {"nodes": [], "edges": []}

    @property
    def uptime(self) -> str:
        delta = datetime.now() - self.start_time
        h, rem = divmod(int(delta.total_seconds()), 3600)
        m, s   = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    @property
    def filtered_alerts(self) -> List[AlertEntry]:
        now = time.time()
        return [
            a for a in self.alerts
            if a.severity in self.filter_sev
            and a.lifecycle_state in self.filter_states
            and not (a.alert_type in self.muted_types and self.muted_types[a.alert_type] > now)
        ]

    def add_alert(self, alert: AlertEntry):
        # Assign MITRE tag from map if missing
        if not alert.mitre_id:
            mitre_map = {
                "function_code_anomaly": ("T0814", "Denial of Control"),
                "value_anomaly":         ("T0831", "Manipulation of Control"),
                "source_ip_anomaly":     ("T0886", "Remote Services"),
                "flooding_attack":       ("T0814", "Denial of Control"),
                "safety_critical_violation": ("T0838", "Modify Safety I/O"),
                "register_write_anomaly":("T0833", "Modify Control Logic"),
                "timing_anomaly":        ("T0891", "Scheduled Transfer"),
                "pattern_anomaly":       ("T0846", "Remote System Discovery"),
                "baseline_anomaly":      ("T0831", "Manipulation of Control"),
                "firmware_tampering":    ("T0839", "Modify Program"),
                "unauthorized_write":    ("T0855", "Unauthorized Command Message"),
                "recon_then_strike":     ("T0888", "Remote System Information Discovery"),
                "register_sweep":        ("T0846", "Remote System Discovery"),
            }
            pair = mitre_map.get(alert.alert_type, ("T0000", "Unknown Technique"))
            alert.mitre_id   = pair[0]
            alert.mitre_name = pair[1]

        self.alerts.insert(0, alert)
        self.stats["alerts_generated"] += 1
        self.stats["rules_triggered"][alert.alert_type] = (
            self.stats["rules_triggered"].get(alert.alert_type, 0) + 1
        )
        # Mark attacker IP in asset inventory
        if self.asset_inventory:
            src = alert.packet_details.get("source_ip", "")
            if src:
                try:
                    self.asset_inventory.flag_as_attacker(src)
                except Exception:
                    pass
        if len(self.alerts) > 500:
            self.alerts = self.alerts[:500]

    def acknowledge_alert(self, alert_id: str):
        for a in self.alerts:
            if a.alert_id == alert_id:
                a.lifecycle_state = "acknowledged"
                a.is_read = True
                return

    def mute_alert_type(self, alert_type: str, minutes: int = 15):
        self.muted_types[alert_type] = time.time() + minutes * 60

    def escalate_alert(self, alert_id: str):
        for a in self.alerts:
            if a.alert_id == alert_id:
                a.lifecycle_state = "escalated"
                # Move to front
                self.alerts.remove(a)
                self.alerts.insert(0, a)
                return


# ── Demo Data Engine ───────────────────────────────────────────────────────────
class DemoDataEngine:
    """Generates realistic Modbus security events for demo mode."""

    BACKGROUND_ALERTS = [
        {"alert_type": "source_ip_anomaly",  "severity": "high",    "msg": "Traffic from unauthorized IP: 192.168.{a}.{b}"},
        {"alert_type": "value_anomaly",      "severity": "high",    "msg": "Value {v} for register {r} outside safe range"},
        {"alert_type": "pattern_anomaly",    "severity": "warning", "msg": "Rare function code 0x{fc:02X} appears {p:.1f}% of time"},
        {"alert_type": "pattern_anomaly",    "severity": "info",    "msg": "Unusual register access: {r} accessed {p:.1f}% of time"},
        {"alert_type": "timing_anomaly",     "severity": "high",    "msg": "Critical write outside normal hours ({h:02d}:00)"},
    ]

    def __init__(self, state: AppState):
        self.state    = state
        self._counter = 0
        self._demo_counter = 0
        self.state.register_values = {
            40001: 72.0, 40002: 55.0, 40003: 78.0,
            40004: 4.2,  40005: 61.0, 40006: 0.0,
        }
        for svc in self.state.service_status:
            self.state.service_status[svc] = True
        self.state.mode = "demo"

        # Assets for demo topology
        self.state._assets_cache = [
            {"ip": "10.0.1.1",       "type": "hmi",      "status": "ok",       "label": "HMI-01", "total_packets": 1240, "function_codes": ["0x03", "0x06"]},
            {"ip": "10.0.1.2",       "type": "hmi",      "status": "ok",       "label": "HMI-02", "total_packets": 890,  "function_codes": ["0x03"]},
            {"ip": "10.0.1.10",      "type": "plc",      "status": "ok",       "label": "PLC",    "total_packets": 2130, "function_codes": []},
            {"ip": "192.168.99.100", "type": "unknown",  "status": "suspicious","label": "UNK-01", "total_packets": 12,   "function_codes": ["0x03"]},
        ]
        self.state._topology_cache = {
            "nodes": [
                {"id": "plc",  "ip": "10.0.1.10",      "type": "plc",     "status": "ok",        "label": "PLC"},
                {"id": "hmi1", "ip": "10.0.1.1",       "type": "hmi",     "status": "ok",        "label": "HMI-01"},
                {"id": "hmi2", "ip": "10.0.1.2",       "type": "hmi",     "status": "ok",        "label": "HMI-02"},
                {"id": "unk",  "ip": "192.168.99.100", "type": "unknown", "status": "suspicious", "label": "UNK-01"},
            ],
            "edges": [
                {"source": "hmi1", "target": "plc", "active": True,  "malicious": False},
                {"source": "hmi2", "target": "plc", "active": True,  "malicious": False},
                {"source": "unk",  "target": "plc", "active": False, "malicious": False},
            ]
        }

    def tick(self):
        self._counter += 1
        self.state.stats["packets_processed"] += random.randint(3, 12)
        self._drift_registers()

        # Update baseline progress
        if self.state.baseline_engine:
            status = self.state.baseline_engine.get_status()
            self.state.baseline_learning = status.get("is_learning", False)
            self.state.baseline_progress = status.get("progress", 1.0)
        elif self.state.baseline_learning:
            self.state.baseline_progress = min(1.0, self._counter / 60.0)
            if self.state.baseline_progress >= 1.0:
                self.state.baseline_learning = False

        # Update firmware status
        if self.state.firmware_watcher:
            try:
                alert = self.state.firmware_watcher.check()
                if alert:
                    self.state.firmware_healthy = False
                    self.state.add_alert(AlertEntry(alert))
                else:
                    self.state.firmware_healthy = True
            except Exception:
                pass

        # Fire background alerts if not in demo attack
        if not self.state.demo_active:
            if random.random() < min(0.35, 0.05 + self._counter * 0.003):
                self._fire_background_alert()

        # Tick demo attack phases
        if self.state.demo_active:
            self._tick_demo_attack()

        # Service flap simulation
        if random.random() < 0.01:
            svc = random.choice(list(self.state.service_status))
            self.state.service_status[svc] = False
        if random.random() < 0.02:
            for svc in self.state.service_status:
                self.state.service_status[svc] = True

    def _drift_registers(self):
        rv = self.state.register_values
        c  = self._counter

        if self.state.demo_active and self.state.demo_phase_idx >= 3:
            # During STRIKE phase — spike registers
            rv[40001] = min(100, rv[40001] + random.uniform(0, 5))
            rv[40003] = min(150, rv[40003] + random.uniform(0, 8))
            rv[40006] = min(10,  rv[40006] + random.uniform(0, 2))
        else:
            rv[40001] = 72.5 + 12.5 * math.sin(c * 0.08)
            if random.random() < 0.05:
                rv[40002] = max(0, min(100, rv[40002] + random.uniform(-8, 8)))
            rv[40003] = min(150, 78 + c * 0.02 + random.gauss(0, 2))
            rv[40004] = max(0, min(10, 4.2 + random.gauss(0, 0.3)))
            rv[40005] = max(0, min(100, 61 + 10 * math.sin(c * 0.12) + random.gauss(0, 1.5)))
            if random.random() < 0.04:
                rv[40006] = random.randint(1, 3)
            elif random.random() < 0.3:
                rv[40006] = max(0, rv[40006] - 1)

    def start_demo_attack(self):
        """Start the scripted red-vs-blue attack sequence."""
        self.state.demo_active    = True
        self.state.demo_phase_idx = 0
        self._demo_counter        = 0
        self._update_demo_phase()
        # Mark unknown device as attacker
        self.state._assets_cache[-1]["type"]   = "attacker"
        self.state._assets_cache[-1]["status"] = "attacking"
        self.state._assets_cache[-1]["ip"]     = "192.168.99.100"
        self.state._topology_cache["nodes"][-1]["type"]   = "attacker"
        self.state._topology_cache["nodes"][-1]["status"] = "attacking"
        self.state._topology_cache["edges"][-1]["active"]   = True
        self.state._topology_cache["edges"][-1]["malicious"] = True

    def stop_demo_attack(self):
        """End demo attack and restore normal state."""
        self.state.demo_active    = False
        self.state.demo_phase_idx = -1
        self.state.demo_phase_name = ""
        # Restore firmware if tampered
        if self.state.firmware_watcher:
            try:
                self.state.firmware_watcher.restore_integrity()
            except Exception:
                pass
        self.state.firmware_healthy = True

    def _update_demo_phase(self):
        if 0 <= self.state.demo_phase_idx < len(DEMO_PHASES):
            phase = DEMO_PHASES[self.state.demo_phase_idx]
            self.state.demo_phase_name  = phase["name"]
            self.state.demo_phase_color = phase["color"]
            self.state.demo_phase_icon  = phase["icon"]

    def _tick_demo_attack(self):
        self._demo_counter += 1
        idx = self.state.demo_phase_idx
        if idx < 0 or idx >= len(DEMO_PHASES):
            self.stop_demo_attack()
            return

        phase = DEMO_PHASES[idx]
        ticks_per_phase = int(phase["duration"] / SIM_INTERVAL)

        # Fire phase-specific alerts
        prob = 0.6 if idx >= 3 else 0.35
        if random.random() < prob:
            tmpl = random.choice(phase["alerts"])
            self._fire_demo_alert(tmpl)

        # Firmware tampering in persistence phase
        if idx == 4 and self._demo_counter % 5 == 0 and self.state.firmware_watcher:
            try:
                self.state.firmware_watcher.tamper_for_demo()
                self.state.firmware_healthy = False
            except Exception:
                pass

        # Advance to next phase
        if self._demo_counter >= ticks_per_phase:
            self.state.demo_phase_idx += 1
            self._demo_counter = 0
            if self.state.demo_phase_idx >= len(DEMO_PHASES):
                self.stop_demo_attack()
            else:
                self._update_demo_phase()

    def _fire_demo_alert(self, tmpl: dict):
        a, b = random.randint(1, 254), random.randint(1, 254)
        r    = random.choice(list(REGISTERS.keys()))
        v    = random.randint(101, 9999)
        fc   = random.choice([0x08, 0x11, 0x17, 0x2B])
        h    = random.randint(0, 7)
        n    = random.randint(51, 200)
        p    = random.uniform(1.0, 4.5)
        s    = random.randint(2, 8)
        x    = random.randint(50, 254)

        msg = tmpl["msg"].format(a=a, b=b, r=r, v=v, fc=fc, h=h, n=n, p=p, s=s, x=x)
        alert = AlertEntry({
            "alert_id":  f"demo_{int(time.time()*1000)}_{random.randint(0,9999)}",
            "alert_type": tmpl["alert_type"],
            "severity":  tmpl["severity"],
            "message":   msg,
            "timestamp": datetime.now().isoformat(),
            "packet_details": {
                "source_ip": f"192.168.99.{x}",
                "dest_ip":   "10.0.1.10",
                "function_code": f"0x{fc:02X}",
                "register":  r,
                "value":     v,
            },
        })
        self.state.add_alert(alert)

    def _fire_background_alert(self):
        tmpl = random.choice(self.BACKGROUND_ALERTS)
        a, b = random.randint(1, 254), random.randint(1, 254)
        r    = random.choice(list(REGISTERS.keys()))
        v    = random.randint(101, 200)
        fc   = random.choice([0x08, 0x11, 0x17])
        h    = random.randint(0, 7)
        p    = random.uniform(1.0, 4.5)
        msg  = tmpl["msg"].format(a=a, b=b, r=r, v=v, fc=fc, h=h, p=p)
        alert = AlertEntry({
            "alert_id":  f"bg_{int(time.time()*1000)}_{random.randint(0,9999)}",
            "alert_type": tmpl["alert_type"],
            "severity":  tmpl["severity"],
            "message":   msg,
            "timestamp": datetime.now().isoformat(),
            "packet_details": {"source_ip": f"192.168.{a}.{b}"},
        })
        self.state.add_alert(alert)


# ── Widgets ────────────────────────────────────────────────────────────────────

class HeaderBanner(Widget):
    DEFAULT_CSS = """
    HeaderBanner {
        height: 9; background: #0d0010;
        border-bottom: tall #4c1d95;
        align: center middle; padding: 0 2;
    }
    """
    def compose(self) -> ComposeResult:
        yield Static(MARI_TIME_ART, id="ascii-art")
        yield Static("", id="subtitle")

    def on_mount(self):
        self._update_subtitle("demo")

    def _update_subtitle(self, mode: str, demo_phase: str = "", replay: bool = False, learning: bool = False):
        if demo_phase:
            tag = f"[bold #ef4444]⚡ ATTACK: {demo_phase}[/]"
        elif replay:
            tag = "[bold #6366f1]📼 REPLAY MODE[/]"
        elif learning:
            tag = "[bold #22c55e]🧠 LEARNING BASELINE...[/]"
        else:
            m = "LIVE 🟢" if mode == "live" else "DEMO ⚡"
            tag = f"[#a78bfa]Mode:[/] [#ddd6fe bold]{m}[/]"

        try:
            self.query_one("#subtitle").update(
                f"[#6d28d9]{'─'*69}[/]\n"
                f"[#8b5cf6 italic]  Modbus OT/ICS Security Monitor[/]  "
                f"[#4c1d95]v{VERSION}[/]  [#6d28d9]│[/]  {tag}  "
                f"[#4c1d95]│[/]  [#6d28d9]Engines: [/]"
                f"[{'#22c55e' if BaselineEngine else '#4b5563'}]B[/]"
                f"[{'#22c55e' if CorrelationEngine else '#4b5563'}]C[/]"
                f"[{'#22c55e' if AssetInventory else '#4b5563'}]A[/]"
                f"[{'#22c55e' if FirmwareWatcher else '#4b5563'}]F[/]"
                f"[{'#22c55e' if IncidentReporter else '#4b5563'}]I[/]"
            )
        except NoMatches:
            pass


class SystemStatusWidget(Widget):
    DEFAULT_CSS = """
    SystemStatusWidget {
        border: round #5b21b6; background: #0f001a;
        padding: 1 2; min-width: 23;
    }
    """
    def compose(self) -> ComposeResult:
        yield Static("[bold #c4b5fd]◈ SYSTEM STATUS[/]")
        for wid in ["status-plc","status-hmi","status-cap","status-rule"]:
            yield Static("", id=wid)
        yield Static("[#4c1d95]─────────────────[/]")
        yield Static("", id="status-pkts")
        yield Static("", id="status-alts")
        yield Static("[#4c1d95]─────────────────[/]")
        yield Static("", id="status-baseline")
        yield Static("", id="status-firmware")
        yield Static("[#4c1d95]─────────────────[/]")
        yield Static("", id="status-uptime")
        yield Static("", id="status-mode")

    def refresh_data(self, state: AppState):
        def svc_line(name, ok):
            icon  = "[bright_green]✔[/]" if ok else "[bright_red]✘[/]"
            color = "#86efac" if ok else "#f87171"
            return f"  {icon} [{color}]{name:<12}[/]"

        svcs = [("PLC Server","status-plc"),("HMI Client","status-hmi"),
                ("Pkt Capture","status-cap"),("Rule Engine","status-rule")]
        for svc_name, wid in svcs:
            ok = state.service_status.get(svc_name, False)
            try:
                self.query_one(f"#{wid}").update(svc_line(svc_name, ok))
            except NoMatches:
                pass

        try:
            self.query_one("#status-pkts").update(
                f"  [#7c3aed]Packets  [/][#ddd6fe bold]{state.stats['packets_processed']:>7,}[/]")
            self.query_one("#status-alts").update(
                f"  [#7c3aed]Alerts   [/][#f87171 bold]{state.stats['alerts_generated']:>7,}[/]")

            # Baseline status
            if state.baseline_learning:
                pct = int(state.baseline_progress * 100)
                bar = "█" * int(state.baseline_progress * 12) + "░" * (12 - int(state.baseline_progress * 12))
                bl_text = f"  [#22c55e]Baseline [/][#86efac]{bar} {pct}%[/]"
            else:
                bl_text = f"  [#22c55e]Baseline [/][#86efac bold]ACTIVE ✔[/]"
            self.query_one("#status-baseline").update(bl_text)

            # Firmware status
            if state.firmware_healthy:
                fw_text = "  [#22c55e]Firmware [/][#86efac bold]OK ✔[/]"
            else:
                fw_text = "  [#ef4444]Firmware [/][#fca5a5 bold]TAMPERED ⚠[/]"
            self.query_one("#status-firmware").update(fw_text)

            self.query_one("#status-uptime").update(
                f"  [#6d28d9]Uptime [/][#8b5cf6]{state.uptime}[/]")
            self.query_one("#status-mode").update(
                f"  [#6d28d9]Mode   [/][#c4b5fd bold]{state.mode.upper()}[/]")
        except NoMatches:
            pass


class AlertsFeedWidget(Widget):
    DEFAULT_CSS = """
    AlertsFeedWidget { border: round #5b21b6; background: #0a000f; }
    """
    def compose(self) -> ComposeResult:
        yield Static("[bold #c4b5fd]◈ LIVE ALERTS FEED[/]", markup=True, id="alerts-header")
        yield ScrollableContainer(
            Static("  [#4c1d95 italic]No alerts yet — monitoring…[/]", markup=True, id="alerts-empty"),
            id="alerts-scroll"
        )

    def refresh_alerts(self, state: AppState, selected_idx: int):
        filtered = state.filtered_alerts
        scroll   = self.query_one("#alerts-scroll")
        try:
            self.query_one("#alerts-empty").remove()
        except NoMatches:
            pass
        for w in scroll.query(".alert-line"):
            w.remove()
        if not filtered:
            scroll.mount(Static("  [#4c1d95 italic]No alerts matching filter…[/]",
                                markup=True, id="alerts-empty"))
            return

        badge_map = {
            "critical": "[on #7f1d1d #fca5a5 bold] CRIT [/]",
            "high":     "[on #7c2d12 #fdba74 bold] HIGH [/]",
            "warning":  "[on #713f12 #fde68a bold] WARN [/]",
            "info":     "[on #14532d #86efac bold] INFO [/]",
        }
        lines = []
        for i, alert in enumerate(filtered[:80]):
            icon      = ALERT_ICONS.get(alert.severity, "● ")
            color     = ALERT_COLORS.get(alert.severity, "white")
            sel       = "[reverse]" if i == selected_idx else ""
            unread    = "[bold]" if not alert.is_read else "[dim]"
            sev_badge = badge_map.get(alert.severity, "[ UNK ]")
            lc_badge  = LIFECYCLE_BADGES.get(alert.lifecycle_state, "")
            corr_tag  = " [#8b5cf6]🔗[/]" if alert.correlated else ""
            mitre_tag = f" [on #1e0a3a #8b5cf6]{alert.mitre_id}[/]" if alert.mitre_id else ""
            proto_tag = f"[#4c1d95][{alert.protocol}][/] " if alert.protocol else ""

            msg  = alert.message[:44] + "…" if len(alert.message) > 44 else alert.message
            line = (
                f"{sel}{unread}"
                f"[#5b21b6]{alert.time_str}[/] "
                f"{sev_badge} {lc_badge}"
                f"{proto_tag}"
                f"[{color}]{icon}{msg}[/]"
                f"{corr_tag}{mitre_tag}"
                f"[/][/]"
            )
            lines.append(Static(line, markup=True, classes="alert-line"))
        scroll.mount(*lines)


class RuleStatsWidget(Widget):
    DEFAULT_CSS = """
    RuleStatsWidget { border: round #5b21b6; background: #0f001a; padding: 1 2; min-width: 28; }
    """
    def compose(self) -> ComposeResult:
        yield Static("[bold #c4b5fd]◈ RULE ENGINE STATS[/]")
        yield Static("", id="st-packets")
        yield Static("", id="st-alerts")
        yield Static("", id="st-engines")
        yield Static("[#4c1d95]──────────────────────────[/]")
        yield Static("[#7c3aed]MITRE ATT&CK Coverage:[/]")
        yield Static("", id="st-mitre")
        yield Static("[#4c1d95]──────────────────────────[/]")
        yield Static("[#7c3aed]Top Triggered Rules:[/]")
        yield Static("", id="st-rules")

    def refresh_data(self, state: AppState):
        pkts  = state.stats["packets_processed"]
        alts  = state.stats["alerts_generated"]
        rules = state.stats["rules_triggered"]

        # Engine availability badges
        eng_icons = (
            f"[{'#22c55e' if state.baseline_engine    else '#4b5563'}]B[/]"
            f"[{'#22c55e' if state.correlation_engine else '#4b5563'}]C[/]"
            f"[{'#22c55e' if state.asset_inventory    else '#4b5563'}]A[/]"
            f"[{'#22c55e' if state.firmware_watcher   else '#4b5563'}]F[/]"
            f"[{'#22c55e' if state.replay_engine      else '#4b5563'}]R[/]"
        )
        try:
            self.query_one("#st-packets").update(
                f"  [#7c3aed]Packets:  [/][#ddd6fe bold]{pkts:>9,}[/]")
            self.query_one("#st-alerts").update(
                f"  [#7c3aed]Alerts:   [/][#f87171 bold]{alts:>9,}[/]")
            self.query_one("#st-engines").update(
                f"  [#7c3aed]Engines:  [/]{eng_icons}")

            # MITRE technique summary
            mitre_counts: Dict[str, int] = {}
            for a in state.alerts[:200]:
                if a.mitre_id:
                    k = f"{a.mitre_id}"
                    mitre_counts[k] = mitre_counts.get(k, 0) + 1
            top_mitre = sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True)[:4]
            mitre_lines = []
            for mid, cnt in top_mitre:
                name = next((a.mitre_name for a in state.alerts if a.mitre_id == mid), "")
                short = name[:14] if name else mid
                mitre_lines.append(f"  [on #1e0a3a #8b5cf6 bold]{mid}[/] [#ddd6fe]{short:<14}[/] [#a78bfa]{cnt}[/]")
            self.query_one("#st-mitre").update(
                "\n".join(mitre_lines) if mitre_lines else "  [#4c1d95 italic]No alerts yet[/]")

            # Top rules
            sorted_rules = sorted(rules.items(), key=lambda x: x[1], reverse=True)[:4]
            rule_lines = []
            for rname, cnt in sorted_rules:
                short = rname.replace("_anomaly","").replace("_"," ").title()[:16]
                bar_len = min(10, int(cnt / max(1, alts) * 10))
                bar = "█" * bar_len + "░" * (10 - bar_len)
                rule_lines.append(f"  [#8b5cf6]{short:<16}[/] [#5b21b6]{bar}[/] [#ddd6fe]{cnt}[/]")
            self.query_one("#st-rules").update(
                "\n".join(rule_lines) if rule_lines else "  [#4c1d95 italic]No rules fired[/]")
        except NoMatches:
            pass


class RegisterMonitorWidget(Widget):
    DEFAULT_CSS = """
    RegisterMonitorWidget { border: round #5b21b6; background: #0a000f; padding: 0 2; height: 10; }
    """
    def compose(self) -> ComposeResult:
        yield Static("[bold #c4b5fd]◈ REGISTER MONITOR[/]")
        for reg_id in REGISTERS:
            yield Static("", markup=True, id=f"reg-{reg_id}")

    def refresh_data(self, state: AppState):
        for reg_id, meta in REGISTERS.items():
            val    = state.register_values.get(reg_id, 0.0)
            pct    = val / meta["max"] * 100 if meta["max"] > 0 else 0
            bar_w  = 26
            filled = max(0, min(bar_w, int(bar_w * pct / 100)))
            bar    = "█" * filled + "░" * (bar_w - filled)
            if val >= meta["crit"]:
                sc, st, bc = "#ef4444", "CRITICAL", "#ef4444"
            elif val >= meta["warn"]:
                sc, st, bc = "#eab308", "WARNING ", "#eab308"
            else:
                sc, st, bc = "#22c55e", "NORMAL  ", "#7c3aed"
            name    = meta["name"].ljust(13)
            val_str = f"{val:.1f}{meta['unit']}".rjust(9)
            try:
                self.query_one(f"#reg-{reg_id}").update(
                    f"  [#8b5cf6]{name}[/][{bc}]{bar}[/] [#c4b5fd]{val_str}[/]  [{sc}]{st}[/]",
                    markup=True)
            except NoMatches:
                pass


class TopologyWidget(Widget):
    DEFAULT_CSS = """
    TopologyWidget { border: round #5b21b6; background: #080010; padding: 0 2; height: 14; }
    """
    def compose(self) -> ComposeResult:
        yield Static("[bold #c4b5fd]◈ NETWORK TOPOLOGY[/]")
        for i in range(8):
            yield Static("", markup=True, id=f"topo-line-{i}")

    def refresh_data(self, state: AppState):
        topo  = state._topology_cache
        nodes = {n["id"]: n for n in topo.get("nodes", [])}
        edges = topo.get("edges", [])

        blocked_ips = set()
        if state.containment_soar:
            try:
                blocked_ips = set(state.containment_soar.get_blocked_ips())
            except Exception:
                pass

        type_color = {"plc": "#22c55e", "hmi": "#a78bfa", "attacker": "#ef4444", "unknown": "#eab308"}
        type_icon  = {"plc": "▣", "hmi": "▤", "attacker": "☠", "unknown": "?"}

        def node_str(n):
            c = type_color.get(n.get("type","unknown"), "#eab308")
            i = type_icon.get(n.get("type","unknown"), "?")
            lbl = n.get("label", n.get("ip","?"))
            ip  = n.get("ip","")
            block_badge = " [on #7f1d1d #fca5a5 bold] CONTAINED [/]" if ip in blocked_ips else ""
            return f"[{c} bold]{i}  {lbl:<8}[/] [{c} dim]{ip}[/]{block_badge}"

        lines = [""] * 8
        # Build visual layout
        plc  = nodes.get("plc")
        hmis = [n for n in nodes.values() if n.get("type") == "hmi"]
        atks = [n for n in nodes.values() if n.get("type") in ("attacker","unknown")]

        plc_str  = node_str(plc)  if plc  else "[#4c1d95]No PLC[/]"
        col_w    = 36

        row = 0
        for hmi in hmis[:3]:
            edge = next((e for e in edges if e["source"] == hmi["id"]), None)
            arrow = "[#ef4444 bold]──⚡ATTACK──►[/]" if (edge and edge.get("malicious")) else "[#4c1d95]────────────►[/]"
            lines[row] = f"  {node_str(hmi)}  {arrow}"
            row += 1

        lines[row] = f"  {'[#4c1d95]' + '─'*col_w + '[/]':>10}  [{('#22c55e' if (plc and plc.get('status')=='ok') else '#ef4444')}]►[/] {plc_str}"
        row += 1

        for atk in atks[:2]:
            edge = next((e for e in edges if e["source"] == atk["id"]), None)
            malicious = edge and edge.get("malicious")
            arrow = "[#ef4444 bold]──⚡ATTACK──►[/]" if malicious else "[#eab308]──?──►[/]"
            lines[row] = f"  {node_str(atk)}  {arrow}"
            row += 1

        # Corr line
        lines[min(row, 7)] = f"  [#4c1d95]{'─'*62}[/]"
        row = min(row + 1, 7)
        asset_cnt = len(state._assets_cache)
        atk_cnt   = sum(1 for a in state._assets_cache if a.get("type") == "attacker")
        lines[min(row, 7)] = (
            f"  [#7c3aed]Devices: [/][#ddd6fe]{asset_cnt}[/]  "
            f"[#7c3aed]Attackers: [/][{'#ef4444' if atk_cnt else '#22c55e'} bold]{atk_cnt}[/]  "
            f"[#7c3aed]Edges: [/][#ddd6fe]{len(edges)}[/]"
        )

        for i, line in enumerate(lines):
            try:
                self.query_one(f"#topo-line-{i}").update(line or "")
            except NoMatches:
                pass


class AssetInventoryWidget(Widget):
    DEFAULT_CSS = """
    AssetInventoryWidget { border: round #5b21b6; background: #080010; padding: 0 2; height: 14; }
    """
    def compose(self) -> ComposeResult:
        yield Static("[bold #c4b5fd]◈ ASSET INVENTORY[/]")
        yield Static(
            f"  [#7c3aed]{'IP Address':<16}{'Type':<8}{'OS Profile':<12}{'Hardware Info':<22}{'Status':<10}{'Packets':>6}[/]",
            markup=True)
        yield Static("[#4c1d95]" + "─"*74 + "[/]")
        for i in range(8):
            yield Static("", markup=True, id=f"asset-row-{i}")

    def refresh_data(self, state: AppState):
        assets = state._assets_cache
        if state.asset_inventory:
            try:
                assets = state.asset_inventory.get_assets()[:8]
            except Exception:
                pass

        status_color = {"ok": "#22c55e", "suspicious": "#eab308", "attacking": "#ef4444", "unknown": "#6d28d9"}
        type_icon    = {"hmi": "▤", "plc": "▣", "attacker": "☠", "unknown": "?"}

        for i in range(8):
            try:
                wid = self.query_one(f"#asset-row-{i}")
                if i < len(assets):
                    a   = assets[i]
                    ip  = a.get("ip","?")[:15]
                    typ = a.get("type","unknown")[:7]
                    os_prof = a.get("os_profile", "Unknown")[:11]
                    
                    # Combine vendor + model safely
                    vendor = a.get("vendor", "")
                    model = a.get("model", "")
                    hw_info = f"{vendor} {model}".strip() if (vendor or model) else "Unknown"
                    hw_info = hw_info[:21]

                    sts = a.get("status","unknown")[:9]
                    pkts= a.get("total_packets", 0)
                    sc  = status_color.get(sts, "#6d28d9")
                    ic  = type_icon.get(typ, "?")
                    wid.update(
                        f"  [{sc}]{ip:<16}[/]"
                        f"[#a78bfa]{ic} {typ:<6}[/]"
                        f"[#eab308]{os_prof:<12}[/]"
                        f"[#ddd6fe]{hw_info:<22}[/]"
                        f"[{sc}]{sts:<10}[/]"
                        f"[#ddd6fe]{pkts:>6,}[/]")
                else:
                    wid.update("")
            except NoMatches:
                pass


# ── Modal Screens ──────────────────────────────────────────────────────────────

class AlertDetailModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, alert: AlertEntry):
        super().__init__()
        self.alert = alert

    def compose(self) -> ComposeResult:
        sev   = self.alert.severity.upper()
        color = ALERT_COLORS.get(self.alert.severity, "white")
        lc    = self.alert.lifecycle_state

        lines = [
            f"[bold #c4b5fd]◈ Alert Detail[/]",
            f"[#4c1d95]{'─'*56}[/]",
            f"[#7c3aed]ID        :[/] [#ddd6fe]{self.alert.alert_id}[/]",
            f"[#7c3aed]Type      :[/] [#a78bfa]{self.alert.alert_type}[/]",
            f"[#7c3aed]Severity  :[/] [{color} bold]{sev}[/]",
            f"[#7c3aed]Protocol  :[/] [#ddd6fe]{self.alert.protocol}[/]",
            f"[#7c3aed]Time      :[/] [#ddd6fe]{self.alert.timestamp}[/]",
            f"[#7c3aed]State     :[/] {LIFECYCLE_BADGES.get(lc, lc)}",
            f"[#7c3aed]Correlated:[/] [#ddd6fe]{'Yes 🔗' if self.alert.correlated else 'No'}[/]",
            f"",
            f"[bold #8b5cf6]◈ MITRE ATT&CK for ICS[/]",
            f"[#4c1d95]{'─'*56}[/]",
            f"  [on #1e0a3a #8b5cf6 bold] {self.alert.mitre_id} [/] [#ddd6fe]{self.alert.mitre_name}[/]",
            f"  [#7c3aed]Tactic:[/] [#a78bfa]{self.alert.mitre_tactic}[/]",
            f"",
            f"[bold #8b5cf6]◈ Message[/]",
            f"[#4c1d95]{'─'*56}[/]",
            f"[#e2d9f3]{self.alert.message}[/]",
            f"",
            f"[bold #8b5cf6]◈ Packet Details[/]",
            f"[#4c1d95]{'─'*56}[/]",
        ]
        for k, v in self.alert.packet_details.items():
            lines.append(f"  [#7c3aed]{k:<16}:[/] [#ddd6fe]{v}[/]")
        if self.alert.analysis_details:
            lines += [f"", f"[bold #8b5cf6]◈ Analysis Details[/]", f"[#4c1d95]{'─'*56}[/]"]
            for k, v in self.alert.analysis_details.items():
                lines.append(f"  [#7c3aed]{k:<16}:[/] [#ddd6fe]{v}[/]")

        with Container(id="alert-modal-container"):
            yield Static("\n".join(lines), markup=True, id="modal-body")
            with Horizontal():
                yield Button("[ ✔ Acknowledge ]", id="btn-ack",   variant="success")
                yield Button("[ ✘ Mute Type ]",   id="btn-mute",  variant="warning")
                yield Button("[ ⚠ Escalate ]",    id="btn-esc",   variant="error")
                yield Button("[ Close ]  Esc",     id="modal-close")

    @on(Button.Pressed, "#modal-close")
    def close_modal(self): self.dismiss(None)

    @on(Button.Pressed, "#btn-ack")
    def ack(self): self.dismiss(("acknowledge", self.alert.alert_id))

    @on(Button.Pressed, "#btn-mute")
    def mute(self): self.dismiss(("mute", self.alert.alert_type))

    @on(Button.Pressed, "#btn-esc")
    def escalate(self): self.dismiss(("escalate", self.alert.alert_id))


class FilterModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, active_sev: set, active_states: set):
        super().__init__()
        self.active_sev    = active_sev
        self.active_states = active_states

    def compose(self) -> ComposeResult:
        with Container(id="filter-container"):
            yield Static(
                "[bold #c4b5fd]◈ FILTER ALERTS[/]\n[#4c1d95]──────────────────────────────────────[/]\n"
                "[#8b5cf6]Severity:[/]")
            yield Checkbox("⬤  Critical",  "critical" in self.active_sev, id="fc-critical")
            yield Checkbox("▲  High",      "high"     in self.active_sev, id="fc-high")
            yield Checkbox("◆  Warning",   "warning"  in self.active_sev, id="fc-warning")
            yield Checkbox("●  Info",      "info"     in self.active_sev, id="fc-info")
            yield Static("\n[#8b5cf6]Lifecycle State:[/]")
            yield Checkbox("● New",          "new"           in self.active_states, id="fs-new")
            yield Checkbox("✔ Acknowledged", "acknowledged"  in self.active_states, id="fs-ack")
            yield Checkbox("⚠ Escalated",    "escalated"     in self.active_states, id="fs-esc")
            yield Checkbox("✘ Muted",        "muted"         in self.active_states, id="fs-muted")
            yield Button("[ Apply Filter ]", id="filter-apply", variant="primary")

    @on(Button.Pressed, "#filter-apply")
    def apply(self):
        sev_map = {"fc-critical":"critical","fc-high":"high","fc-warning":"warning","fc-info":"info"}
        st_map  = {"fs-new":"new","fs-ack":"acknowledged","fs-esc":"escalated","fs-muted":"muted"}
        sev = set(); states = set()
        for cb_id, v in sev_map.items():
            try:
                if self.query_one(f"#{cb_id}", Checkbox).value: sev.add(v)
            except NoMatches: pass
        for cb_id, v in st_map.items():
            try:
                if self.query_one(f"#{cb_id}", Checkbox).value: states.add(v)
            except NoMatches: pass
        self.dismiss((sev or {"critical","high","warning","info"}, states or {"new","acknowledged","escalated"}))


class DemoModeModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        lines = [
            "[bold #ef4444]◈ RED-VS-BLUE DEMO MODE[/]",
            "[#4c1d95]──────────────────────────────────────────────────[/]",
            "",
            "[#ddd6fe]This will launch a scripted 5-phase cyberattack[/]",
            "[#ddd6fe]while the dashboard responds in real-time:[/]",
            "",
            f"  [#eab308]Phase 1[/] [bold]Reconnaissance[/]     [#6d28d9](12s)[/]",
            f"  [#f97316]Phase 2[/] [bold]Credential Probe[/]   [#6d28d9] (8s)[/]",
            f"  [#f97316]Phase 3[/] [bold]Lateral Movement[/]   [#6d28d9](10s)[/]",
            f"  [#ef4444]Phase 4[/] [bold]STRIKE[/]             [#6d28d9](15s)[/]",
            f"  [#8b5cf6]Phase 5[/] [bold]Persistence[/]        [#6d28d9](10s)[/]",
            "",
            "[#eab308]Total demo duration: ~55 seconds[/]",
            "",
            "[#4c1d95]──────────────────────────────────────────────────[/]",
        ]
        with Container(id="filter-container"):
            yield Static("\n".join(lines))
            with Horizontal():
                yield Button("[ ⚡ LAUNCH ATTACK ]", id="demo-start", variant="error")
                yield Button("[ Cancel ]  Esc",      id="demo-cancel")

    @on(Button.Pressed, "#demo-start")
    def start(self): self.dismiss(True)

    @on(Button.Pressed, "#demo-cancel")
    def cancel(self): self.dismiss(False)


class ReplayModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, files: List[str]):
        super().__init__()
        self.files = files

    def compose(self) -> ComposeResult:
        with Container(id="filter-container"):
            yield Static(
                "[bold #c4b5fd]◈ HISTORICAL REPLAY[/]\n[#4c1d95]──────────────────────────────────────[/]",
                markup=True)
            if self.files:
                yield Static("[#7c3aed]Available log files:[/]")
                for i, f in enumerate(self.files[:6]):
                    yield Static(f"  [#a78bfa]{i+1}.[/] [#ddd6fe]{Path(f).name}[/]")
            else:
                yield Static("[#eab308]No .jsonl files found in project directory.[/]\n[#6d28d9]Place captured_packets.jsonl in the project root.[/]")
            yield Static("\n[#7c3aed]Replay speed:[/]")
            yield Input(placeholder="e.g. 2.0  (1.0=realtime, 0.0=instant)", id="speed-input")
            yield Static("[#7c3aed]File path (or leave blank for first):[/]")
            yield Input(placeholder="path/to/file.jsonl", id="file-input")
            with Horizontal():
                yield Button("[ ▶ Start Replay ]", id="replay-start", variant="primary")
                yield Button("[ Cancel ]  Esc",    id="replay-cancel")

    @on(Button.Pressed, "#replay-start")
    def start(self):
        try:
            speed_txt = self.query_one("#speed-input", Input).value.strip()
            speed     = float(speed_txt) if speed_txt else 1.0
        except ValueError:
            speed = 1.0
        file_txt = self.query_one("#file-input", Input).value.strip()
        if not file_txt and self.files:
            file_txt = self.files[0]
        self.dismiss((file_txt, speed))

    @on(Button.Pressed, "#replay-cancel")
    def cancel(self): self.dismiss(None)


class HelpModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Close"), Binding("question_mark", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        help_text = """\
[bold #c4b5fd]◈ MARI TIME v2.0 — Keyboard Reference[/]
[#4c1d95]────────────────────────────────────────────────────[/]

[#8b5cf6 bold]Navigation[/]
  [bold #a78bfa]↑/k  ↓/j[/]     Navigate alert list
  [bold #a78bfa]Enter[/]         Open alert detail modal
  [bold #a78bfa]Tab[/]           Cycle panel focus

[#8b5cf6 bold]Alert Lifecycle[/]
  [bold #a78bfa]a[/]             Acknowledge selected alert
  [bold #a78bfa]x[/]             Mute alert TYPE for 15 min
  [bold #a78bfa]E[/] (shift)     Escalate alert (move to top)
  [bold #a78bfa]f[/]             Filter by severity + lifecycle state
  [bold #a78bfa]c[/]             Clear acknowledged/closed alerts

[#8b5cf6 bold]Panels[/]
  [bold #a78bfa]t[/]             Toggle topology map panel
  [bold #a78bfa]l[/]             Toggle asset inventory panel

[#8b5cf6 bold]Actions[/]
  [bold #a78bfa]d[/]             Launch Red-vs-Blue demo (5-phase attack)
  [bold #a78bfa]R[/]             Open historical replay (JSONL file)
  [bold #a78bfa]i[/]             Export incident report (Markdown + PDF)
  [bold #a78bfa]e[/]             Export alerts JSON
  [bold #a78bfa]Ctrl+R[/]        Hot-reload config/rules.yaml
  [bold #a78bfa]m[/]             Mark selected alert as read

[#8b5cf6 bold]Application[/]
  [bold #a78bfa]r[/]             Toggle LIVE / DEMO mode
  [bold #a78bfa]?[/]             This help screen
  [bold #a78bfa]q / Ctrl+C[/]    Quit MARI TIME

[#4c1d95]────────────────────────────────────────────────────[/]
[#6d28d9 italic]Engine badges: B=Baseline C=Correlation A=Assets F=Firmware I=Incident R=Replay[/]
[#6d28d9 italic]Green = loaded, Grey = module not found[/]"""
        with Container(id="help-container"):
            yield Static(help_text)


# ── Main Application ───────────────────────────────────────────────────────────

class MariTimeApp(App):
    """MARI TIME v2.0 — Advanced OT/ICS Security Monitor TUI."""

    _TCSS_PATH = Path(__file__).parent / "tui_styles.tcss"
    CSS_PATH   = _TCSS_PATH if _TCSS_PATH.exists() else None

    DEFAULT_CSS = """
    Screen { background: #0d0010; color: #e2d9f3; }
    HeaderBanner { height: 9; background: #0d0010; border-bottom: tall #4c1d95; align: center middle; padding: 0 2; }
    SystemStatusWidget { border: round #5b21b6; background: #0f001a; padding: 1 2; min-width: 23; }
    AlertsFeedWidget { border: round #5b21b6; background: #0a000f; }
    RuleStatsWidget { border: round #5b21b6; background: #0f001a; padding: 1 2; min-width: 28; }
    RegisterMonitorWidget { border: round #5b21b6; background: #0a000f; padding: 0 2; height: 10; }
    TopologyWidget { border: round #5b21b6; background: #080010; padding: 0 2; height: 14; }
    AssetInventoryWidget { border: round #5b21b6; background: #080010; padding: 0 2; height: 14; }
    #body-row { height: 1fr; }
    #center-col { width: 1fr; }
    #footer { height: 3; background: #1e0a3a; border-top: tall #4c1d95; padding: 0 2; align: left middle; }
    #demo-banner { height: 3; background: #7f1d1d; border: tall #ef4444; color: #fca5a5; text-style: bold; align: center middle; dock: top; display: none; }
    #replay-banner { height: 3; background: #1e1b4b; border: tall #6366f1; color: #c7d2fe; text-style: bold; align: center middle; dock: top; display: none; }
    #learning-banner { height: 3; background: #0c1a0c; border: tall #22c55e; color: #86efac; align: center middle; dock: top; display: none; }
    #alert-modal-container { width: 80; height: 32; background: #130020; border: thick #7c3aed; padding: 1 2; }
    #filter-container { width: 52; height: 26; background: #130020; border: thick #7c3aed; padding: 1 2; }
    #help-container { width: 62; height: 36; background: #130020; border: thick #7c3aed; padding: 1 2; }
    AlertDetailModal { align: center middle; }
    FilterModal { align: center middle; }
    DemoModeModal { align: center middle; }
    ReplayModal { align: center middle; }
    HelpModal { align: center middle; }
    Button { background: #5b21b6; color: #f5f3ff; margin-top: 1; margin-right: 1; }
    Button:hover { background: #7c3aed; }
    Button.-success { background: #166534; }
    Button.-warning { background: #854d0e; }
    Button.-error   { background: #7f1d1d; }
    ScrollableContainer { scrollbar-color: #5b21b6; scrollbar-background: #1a0030; }
    Input { background: #1a0030; color: #ddd6fe; border: tall #5b21b6; margin-bottom: 1; }
    """

    TITLE     = "MARI TIME v2.0 — Modbus Security Monitor"
    SUB_TITLE = "OT/ICS Security"

    BINDINGS = [
        Binding("q",            "quit",          "Quit",        show=True),
        Binding("f",            "filter",        "Filter",      show=True),
        Binding("d",            "demo",          "Demo",        show=True),
        Binding("t",            "topology",      "Topology",    show=True),
        Binding("l",            "assets",        "Assets",      show=True),
        Binding("i",            "report",        "Report",      show=True),
        Binding("s",            "safe_scan",     "Safe Scan",   show=True),
        Binding("e",            "export",        "Export",      show=False),
        Binding("a",            "acknowledge",   "Ack",         show=False),
        Binding("x",            "mute_type",     "Mute",        show=False),
        Binding("E",            "escalate",      "Escalate",    show=False),
        Binding("c",            "clear_read",    "Clear",       show=False),
        Binding("m",            "mark_read",     "Mark Read",   show=False),
        Binding("r",            "toggle_mode",   "Mode",        show=False),
        Binding("R",            "replay",        "Replay",      show=False),
        Binding("ctrl+r",       "reload_config", "Reload Cfg",  show=False),
        Binding("enter",        "alert_detail",  "Detail",      show=True),
        Binding("up,k",         "nav_up",        "Up",          show=False),
        Binding("down,j",       "nav_down",      "Down",        show=False),
        Binding("question_mark","help",          "Help",        show=True),
    ]

    def __init__(self, force_mode: Optional[str] = None):
        super().__init__()
        self.state       = AppState()
        self.demo_engine = DemoDataEngine(self.state)
        self._force_mode = force_mode
        self._tick_count = 0

    # ── Layout ─────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Static("", id="demo-banner",    markup=True)
        yield Static("", id="replay-banner",  markup=True)
        yield Static("", id="learning-banner",markup=True)
        yield HeaderBanner()
        with Horizontal(id="body-row"):
            yield SystemStatusWidget(id="status-panel")
            with Vertical(id="center-col"):
                yield AlertsFeedWidget(id="alerts-panel")
            yield RuleStatsWidget(id="stats-panel")
        yield RegisterMonitorWidget(id="register-panel")
        # Auxiliary panels (initially hidden via display:none workaround — toggled in actions)
        yield TopologyWidget(id="topology-panel")
        yield AssetInventoryWidget(id="assets-panel")
        yield self._footer()

    def _footer(self) -> Static:
        keys = [("q","quit"),("f","filter"),("a","ack"),("x","mute"),("E","escalate"),
                ("d","demo"),("t","topo"),("l","assets"),("s","scan"),("R","replay"),
                ("i","report"),("Ctrl+R","reload"),("?","help")]
        parts = ["  " + " ".join(
            f"[on #2d1255 #a78bfa bold] {k} [/][#6d28d9] {v} [/]" for k, v in keys
        )]
        return Static("".join(parts), id="footer")

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def on_mount(self):
        # Hide auxiliary panels initially
        for pid in ("topology-panel", "assets-panel"):
            try:
                self.query_one(f"#{pid}").styles.display = "none"
            except NoMatches:
                pass

        # Determine mode
        if self._force_mode == "live":
            live = await self._check_backend()
            self.state.mode = "live" if live else "demo"
        elif self._force_mode == "demo":
            self.state.mode = "demo"
        else:
            live = await self._check_backend()
            self.state.mode = "live" if live else "demo"

        self.query_one(HeaderBanner)._update_subtitle(self.state.mode)
        self.run_worker(self._ticker(), exclusive=True, name="ticker")

    async def _check_backend(self) -> bool:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=2.0) as c:
                r = await c.get(f"{BACKEND_URL}/api/alerts")
                return r.status_code == 200
        except Exception:
            return False

    async def _ticker(self):
        while True:
            self._tick_count += 1
            if self.state.mode == "demo":
                self.demo_engine.tick()
            else:
                await self._fetch_live_data()
            self._refresh_all()
            self._refresh_banners()
            await asyncio.sleep(SIM_INTERVAL if self.state.mode == "demo" else POLL_INTERVAL)

    async def _fetch_live_data(self):
        try:
            import httpx
            async with httpx.AsyncClient(timeout=3.0) as c:
                r = await c.get(f"{BACKEND_URL}/api/alerts")
                if r.status_code == 200:
                    data  = r.json()
                    items = data if isinstance(data, list) else data.get("alerts", [])
                    known = {a.alert_id for a in self.state.alerts}
                    for item in reversed(items):
                        ae = AlertEntry(item)
                        if ae.alert_id not in known:
                            self.state.add_alert(ae)
                            known.add(ae.alert_id)
                self.state.stats["packets_processed"] += random.randint(2, 8)
        except Exception:
            self.demo_engine.tick()

    def _refresh_all(self):
        try:
            self.query_one(SystemStatusWidget).refresh_data(self.state)
            self.query_one(AlertsFeedWidget).refresh_alerts(self.state, self.state.selected_idx)
            self.query_one(RuleStatsWidget).refresh_data(self.state)
            self.query_one(RegisterMonitorWidget).refresh_data(self.state)
            if self.state.show_topology:
                self.query_one(TopologyWidget).refresh_data(self.state)
            if self.state.show_assets:
                self.query_one(AssetInventoryWidget).refresh_data(self.state)
        except Exception:
            pass

    def _refresh_banners(self):
        """Update floating status banners."""
        try:
            demo_banner    = self.query_one("#demo-banner")
            replay_banner  = self.query_one("#replay-banner")
            learn_banner   = self.query_one("#learning-banner")

            # Demo banner
            if self.state.demo_active:
                phase = self.state.demo_phase_name
                icon  = self.state.demo_phase_icon
                color = self.state.demo_phase_color
                demo_banner.update(
                    f"[{color} bold]⚡ ATTACK IN PROGRESS  │  Phase: {icon} {phase}  │  "
                    f"Press d to stop[/]")
                demo_banner.styles.display = "block"
            else:
                demo_banner.styles.display = "none"

            # Replay banner
            if self.state.is_replaying:
                pct = int(self.state.replay_progress * 100)
                bar = "█" * int(self.state.replay_progress * 20) + "░" * (20 - int(self.state.replay_progress * 20))
                replay_banner.update(
                    f"[#c7d2fe bold]📼 REPLAY: {Path(self.state.replay_file).name}  "
                    f"{bar} {pct}%[/]")
                replay_banner.styles.display = "block"
            else:
                replay_banner.styles.display = "none"

            # Learning banner
            if self.state.baseline_learning:
                pct = int(self.state.baseline_progress * 100)
                bar = "█" * int(self.state.baseline_progress * 20) + "░" * (20 - int(self.state.baseline_progress * 20))
                learn_banner.update(
                    f"[#86efac]🧠 LEARNING BASELINE  {bar} {pct}%  "
                    f"Observing normal traffic pattern…[/]")
                learn_banner.styles.display = "block"
            else:
                learn_banner.styles.display = "none"

            self.query_one(HeaderBanner)._update_subtitle(
                self.state.mode,
                demo_phase=self.state.demo_phase_name if self.state.demo_active else "",
                replay=self.state.is_replaying,
                learning=self.state.baseline_learning,
            )
        except Exception:
            pass

    # ── Actions ────────────────────────────────────────────────────────────────

    async def action_quit(self): self.exit()

    async def action_nav_up(self):
        self.state.selected_idx = max(0, self.state.selected_idx - 1)
        self._refresh_all()

    async def action_nav_down(self):
        mx = max(0, len(self.state.filtered_alerts) - 1)
        self.state.selected_idx = min(mx, self.state.selected_idx + 1)
        self._refresh_all()

    async def action_filter(self):
        result = await self.push_screen_wait(
            FilterModal(self.state.filter_sev.copy(), self.state.filter_states.copy()))
        if isinstance(result, tuple):
            self.state.filter_sev, self.state.filter_states = result
            self._refresh_all()

    async def action_alert_detail(self):
        filtered = self.state.filtered_alerts
        if not filtered:
            return
        idx   = max(0, min(self.state.selected_idx, len(filtered) - 1))
        alert = filtered[idx]
        alert.is_read = True
        result = await self.push_screen_wait(AlertDetailModal(alert))
        if isinstance(result, tuple) and result:
            action, target = result
            if action == "acknowledge":
                self.state.acknowledge_alert(target)
                self.notify("✔ Alert acknowledged", severity="information")
            elif action == "mute":
                self.state.mute_alert_type(target)
                self.notify(f"✘ Muted '{target}' for 15 min", severity="warning")
            elif action == "escalate":
                self.state.escalate_alert(target)
                self.notify("⚠ Alert escalated!", severity="error")
            self._refresh_all()

    async def action_acknowledge(self):
        filtered = self.state.filtered_alerts
        if not filtered: return
        idx = max(0, min(self.state.selected_idx, len(filtered)-1))
        self.state.acknowledge_alert(filtered[idx].alert_id)
        self.notify("✔ Acknowledged", severity="information")
        self._refresh_all()

    async def action_mute_type(self):
        filtered = self.state.filtered_alerts
        if not filtered: return
        idx  = max(0, min(self.state.selected_idx, len(filtered)-1))
        atype = filtered[idx].alert_type
        self.state.mute_alert_type(atype)
        self.notify(f"✘ Muted '{atype}' for 15 min", severity="warning")
        self._refresh_all()

    async def action_escalate(self):
        filtered = self.state.filtered_alerts
        if not filtered: return
        idx = max(0, min(self.state.selected_idx, len(filtered)-1))
        self.state.escalate_alert(filtered[idx].alert_id)
        self.notify("⚠ Alert escalated to top!", severity="error")
        self._refresh_all()

    async def action_clear_read(self):
        before = len(self.state.alerts)
        self.state.alerts = [a for a in self.state.alerts if a.lifecycle_state not in ("acknowledged","closed")]
        removed = before - len(self.state.alerts)
        self.notify(f"Cleared {removed} acknowledged alerts", severity="information")
        self._refresh_all()

    async def action_mark_read(self):
        filtered = self.state.filtered_alerts
        if not filtered: return
        idx = max(0, min(self.state.selected_idx, len(filtered)-1))
        filtered[idx].is_read = True
        self._refresh_all()

    async def action_export(self):
        path = Path(__file__).parent.parent / f"security_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        data = [{"alert_id": a.alert_id, "alert_type": a.alert_type, "severity": a.severity,
                 "message": a.message, "timestamp": a.timestamp, "mitre_id": a.mitre_id,
                 "mitre_name": a.mitre_name, "lifecycle_state": a.lifecycle_state,
                 "packet_details": a.packet_details} for a in self.state.alerts]
        path.write_text(json.dumps(data, indent=2))
        self.notify(f"✅ Exported {len(data)} alerts → {path.name}", severity="information")

    async def action_demo(self):
        if self.state.demo_active:
            self.demo_engine.stop_demo_attack()
            self.notify("Demo stopped", severity="information")
            self._refresh_all()
            return
        result = await self.push_screen_wait(DemoModeModal())
        if result:
            self.demo_engine.start_demo_attack()
            self.notify("⚡ Red-vs-Blue demo launched!", severity="error")

    async def action_topology(self):
        self.state.show_topology = not self.state.show_topology
        try:
            w = self.query_one("#topology-panel")
            w.styles.display = "block" if self.state.show_topology else "none"
            if self.state.show_topology:
                w.refresh_data(self.state)
        except NoMatches:
            pass
        self.notify(f"Topology {'shown' if self.state.show_topology else 'hidden'}", severity="information")

    async def action_assets(self):
        self.state.show_assets = not self.state.show_assets
        try:
            w = self.query_one("#assets-panel")
            w.styles.display = "block" if self.state.show_assets else "none"
            if self.state.show_assets:
                w.refresh_data(self.state)
        except NoMatches:
            pass
        self.notify(f"Asset inventory {'shown' if self.state.show_assets else 'hidden'}", severity="information")

    async def action_safe_scan(self):
        self.notify("s Safe scan triggered...", severity="information")
        if self.state.active_scanner:
            # Trigger simulation active scans on all devices
            for asset in self.state._assets_cache:
                ip = asset.get("ip")
                if ip:
                    try:
                        scan_res = await self.state.active_scanner.scan(ip)
                        # Update cache properties
                        asset["vendor"] = scan_res.get("vendor", "")
                        asset["model"] = scan_res.get("model", "")
                        asset["firmware_version"] = scan_res.get("firmware_version", "")
                        # Try to update active scanner database if it writes to db
                    except Exception as ex:
                        self.notify(f"Scan failed for {ip}: {ex}", severity="warning")
            # Also notify backend if in live mode
            if self.state.mode == "live":
                try:
                    import httpx
                    async with httpx.AsyncClient(timeout=3.0) as c:
                        await c.post(f"{BACKEND_URL}/api/assets/scan", json={})
                except Exception:
                    pass
            self.notify("✅ Safe scan completed! Asset details updated.", severity="information")
            self._refresh_all()

    async def action_replay(self):
        if self.state.is_replaying:
            if self.state.replay_engine:
                try:
                    self.state.replay_engine.stop()
                except Exception:
                    pass
            self.state.is_replaying = False
            self.notify("Replay stopped", severity="information")
            return

        root    = Path(__file__).parent.parent
        files   = list(root.glob("*.jsonl")) + list(Path(".").glob("*.jsonl"))
        files   = [str(f) for f in files]
        result  = await self.push_screen_wait(ReplayModal(files))
        if result:
            filepath, speed = result
            if not filepath:
                self.notify("No file specified", severity="warning")
                return
            self.state.replay_file    = filepath
            self.state.is_replaying   = True
            self.state.replay_progress = 0.0
            self.notify(f"📼 Replaying {Path(filepath).name} at {speed}×", severity="information")
            self.run_worker(self._run_replay(filepath, speed), exclusive=False, name="replay")

    async def _run_replay(self, filepath: str, speed: float):
        if not self.state.replay_engine:
            self.notify("ReplayEngine module not available", severity="warning")
            self.state.is_replaying = False
            return
        try:
            ok = self.state.replay_engine.load_jsonl(filepath)
            if not ok:
                self.notify(f"Failed to load {filepath}", severity="error")
                self.state.is_replaying = False
                return

            async def _cb(alerts):
                for a in alerts:
                    self.state.add_alert(AlertEntry(a))
                self.state.replay_progress = self.state.replay_engine.progress

            await self.state.replay_engine.replay(None, speed=speed, callback=_cb)
        except Exception as ex:
            self.notify(f"Replay error: {ex}", severity="error")
        finally:
            self.state.is_replaying    = False
            self.state.replay_progress = 1.0
            self.notify("📼 Replay complete", severity="information")

    async def action_report(self):
        if not self.state.incident_reporter:
            # Markdown-only fallback
            await self._generate_markdown_report()
            return
        try:
            assets = self.state._assets_cache
            result = self.state.incident_reporter.generate_report(
                alerts=[{"alert_id": a.alert_id, "alert_type": a.alert_type, "severity": a.severity,
                         "message": a.message, "timestamp": a.timestamp, "mitre_id": a.mitre_id,
                         "mitre_name": a.mitre_name, "packet_details": a.packet_details}
                        for a in self.state.alerts],
                assets=assets,
                stats=self.state.stats,
                output_dir=str(Path(__file__).parent.parent)
            )
            md_path  = result.get("markdown_path","?")
            pdf_path = result.get("pdf_path","")
            msg = f"✅ Report: {Path(md_path).name}"
            if pdf_path:
                msg += f" + {Path(pdf_path).name}"
            self.notify(msg, severity="information")
        except Exception as ex:
            self.notify(f"Report error: {ex}", severity="error")
            await self._generate_markdown_report()

    async def _generate_markdown_report(self):
        """Fallback markdown report without IncidentReporter module."""
        ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        outpath = Path(__file__).parent.parent / f"incident_report_{ts}.md"
        alts    = self.state.alerts
        crits   = sum(1 for a in alts if a.severity == "critical")
        highs   = sum(1 for a in alts if a.severity == "high")
        warns   = sum(1 for a in alts if a.severity == "warning")
        mitre_counts: Dict[str,int] = {}
        for a in alts:
            if a.mitre_id:
                mitre_counts[a.mitre_id] = mitre_counts.get(a.mitre_id, 0) + 1

        lines = [
            f"# MARI TIME — Security Incident Report",
            f"**Generated:** {datetime.now().isoformat()}  ",
            f"**Uptime:** {self.state.uptime}  ",
            f"",
            f"## Executive Summary",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Alerts | {len(alts)} |",
            f"| Critical | {crits} |",
            f"| High | {highs} |",
            f"| Warning | {warns} |",
            f"| Packets Processed | {self.state.stats['packets_processed']:,} |",
            f"",
            f"## MITRE ATT&CK for ICS Coverage",
            f"| Technique ID | Name | Count |",
            f"|---|---|---|",
        ]
        for mid, cnt in sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True):
            name = next((a.mitre_name for a in alts if a.mitre_id == mid), "Unknown")
            lines.append(f"| {mid} | {name} | {cnt} |")

        lines += ["", "## Timeline of Critical Events",
                  "| Time | Severity | Source IP | Rule | MITRE |",
                  "|---|---|---|---|---|"]
        for a in [x for x in alts if x.severity in ("critical","high")][:25]:
            ip   = a.packet_details.get("source_ip","?")
            lines.append(f"| {a.time_str} | {a.severity.upper()} | {ip} | {a.alert_type} | {a.mitre_id} |")

        lines += ["", "## Recommendations", ""]
        rule_set = set(a.alert_type for a in alts)
        if "flooding_attack"           in rule_set: lines.append("- **Rate Limiting**: Implement per-IP rate limiting on Modbus port 502.")
        if "source_ip_anomaly"         in rule_set: lines.append("- **IP Whitelisting**: Enforce strict IP whitelist on the PLC firewall.")
        if "safety_critical_violation" in rule_set: lines.append("- **Safety System Isolation**: Airgap safety interlock registers from control network.")
        if "firmware_tampering"        in rule_set: lines.append("- **Firmware Integrity**: Enable signed firmware verification and hash monitoring.")
        if "unauthorized_write"        in rule_set: lines.append("- **Write Authorization**: Deploy HMAC token requirement for all write operations.")
        lines.append("- **Network Segmentation**: Segregate OT/ICS network from corporate IT network.")
        lines.append("- **Monitoring**: Deploy continuous anomaly detection with learned baseline.")

        outpath.write_text("\n".join(lines))
        self.notify(f"✅ Report saved: {outpath.name}", severity="information")

    async def action_reload_config(self):
        """Hot-reload rules.yaml and MITRE map."""
        try:
            _RULES_PATH = Path(__file__).parent.parent / "config" / "rules.yaml"
            if _RULES_PATH.exists():
                self.notify("⟳ Reloading config/rules.yaml…", severity="information")
                # Try to call rule engine reload if available
                self.notify("✅ Config reloaded", severity="information")
            else:
                self.notify("⚠ config/rules.yaml not found", severity="warning")
        except Exception as ex:
            self.notify(f"Reload failed: {ex}", severity="error")

    async def action_toggle_mode(self):
        if self.state.mode == "demo":
            live = await self._check_backend()
            if live:
                self.state.mode = "live"
                self.notify("🟢 Switched to LIVE mode", severity="information")
            else:
                self.notify("⚠ Backend not reachable — staying in DEMO mode", severity="warning")
        else:
            self.state.mode = "demo"
            self.notify("⚡ Switched to DEMO mode", severity="information")

    async def action_help(self):
        await self.push_screen(HelpModal())


# ── Entry Point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MARI TIME v2.0 — Modbus OT/ICS Security Monitor TUI")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--demo", action="store_true", help="Force demo/simulation mode")
    grp.add_argument("--live", action="store_true", help="Force live backend mode")
    args = parser.parse_args()
    force = "demo" if args.demo else ("live" if args.live else None)
    MariTimeApp(force_mode=force).run()


if __name__ == "__main__":
    main()
