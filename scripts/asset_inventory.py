#!/usr/bin/env python3
"""
ASSET INVENTORY — Passive Asset Discovery and Device Fingerprinting

Part of the MariTime Modbus OT/ICS Security Monitor.

Watches every Modbus packet, builds a passive database of observed devices,
computes behavioural fingerprints, and emits alerts when:

* A brand-new IP is seen for the first time (new device discovered).
* A known device starts using a function code it never used during its first
  60 seconds of observation (behavioural drift).

Device classification heuristics
---------------------------------
plc      — the IP appears only as a destination (never initiates in the
            capture feed), or it never generates write traffic.
hmi      — the IP exclusively uses fc 0x03 (read holding registers) and
            occasionally 0x06 (write single), with regular access intervals.
attacker — the IP has had any security alert fired against it via
           :py:meth:`flag_as_attacker`.
unknown  — everything else.

Topology output
---------------
``get_topology()`` returns::

    {
        "nodes": [{"id": ip, "ip": ip, "type": ..., "status": ...}, ...],
        "edges": [{"source": ip, "target": ip, "protocol": "modbus",
                   "port": 502, "active": bool}, ...]
    }

MITRE ATT&CK for ICS reference: T0886 – Remote Services.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger("asset_inventory")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(
        logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")
    )
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_FINGERPRINT_LOCK_SECONDS: float = 60.0  # window during which FC set is "baseline"
_ACTIVE_EDGE_TTL: float = 120.0          # seconds — edge is 'active' if seen recently


# ---------------------------------------------------------------------------
# Internal representation of a tracked asset
# ---------------------------------------------------------------------------
class _AssetRecord:
    """Mutable runtime record for a single observed IP."""

    __slots__ = (
        "ip",
        "first_seen_epoch",
        "last_seen_epoch",
        "slave_ids",
        "function_codes_used",
        "registers_accessed",
        "write_registers",
        "response_timing_samples",
        "total_packets",
        "_baseline_fcs",          # FCs seen in first 60 s (locked after that)
        "_baseline_locked",       # True once 60 s has elapsed
        "_classifications_dirty", # flag to recompute type on next query
        "is_attacker",
        "alert_count",
        "dest_ips",               # IPs this asset communicates with
        "os_profile",
        "vendor",
        "model",
        "firmware_version",
    )

    def __init__(self, ip: str, first_seen: float) -> None:
        self.ip: str = ip
        self.first_seen_epoch: float = first_seen
        self.last_seen_epoch: float = first_seen
        self.slave_ids: Set[int] = set()
        self.function_codes_used: Set[str] = set()
        self.registers_accessed: Set[str] = set()
        self.write_registers: Set[str] = set()
        self.response_timing_samples: List[float] = []
        self.total_packets: int = 0
        self._baseline_fcs: Set[str] = set()
        self._baseline_locked: bool = False
        self._classifications_dirty: bool = True
        self.is_attacker: bool = False
        self.alert_count: int = 0
        self.dest_ips: Set[str] = set()
        self.os_profile: str = "Unknown"
        self.vendor: str = ""
        self.model: str = ""
        self.firmware_version: str = ""

    # ------------------------------------------------------------------
    def update(self, packet: Dict, now: float) -> Optional[str]:
        """Update this record from *packet*.

        Returns the new function code if it constitutes a behavioural drift,
        otherwise ``None``.
        """
        self.total_packets += 1
        self.last_seen_epoch = now
        self._classifications_dirty = True

        fc = str(packet.get("function_code", ""))
        reg = packet.get("register")
        slave = packet.get("slave_id")
        dest = packet.get("dest_ip") or packet.get("destination_ip")
        timing = packet.get("response_time_ms")
        op = str(packet.get("operation", "")).lower()

        if fc:
            self.function_codes_used.add(fc)
        if slave is not None:
            try:
                self.slave_ids.add(int(slave))
            except (ValueError, TypeError):
                pass
        if reg is not None:
            self.registers_accessed.add(str(reg))
            if op in {"write", "w"} or fc in {
                "0x06", "0x10", "0x0f", "6", "10", "15", "16"
            }:
                self.write_registers.add(str(reg))
        if dest:
            self.dest_ips.add(str(dest))
        if timing is not None:
            try:
                self.response_timing_samples.append(float(timing))
                # Keep last 500 samples.
                if len(self.response_timing_samples) > 500:
                    self.response_timing_samples = self.response_timing_samples[-500:]
            except (ValueError, TypeError):
                pass

        # Manage baseline FC window.
        age = now - self.first_seen_epoch
        drift_fc: Optional[str] = None
        if not self._baseline_locked:
            if age <= _FINGERPRINT_LOCK_SECONDS:
                if fc:
                    self._baseline_fcs.add(fc)
            else:
                # Lock the baseline.
                self._baseline_locked = True
        else:
            # Check for drift.
            if fc and fc not in self._baseline_fcs:
                drift_fc = fc

        return drift_fc

    # ------------------------------------------------------------------
    @property
    def packet_rate_per_min(self) -> float:
        """Approximate packet rate (packets per minute) over the asset lifetime."""
        age_seconds = max(self.last_seen_epoch - self.first_seen_epoch, 1.0)
        return (self.total_packets / age_seconds) * 60.0

    # ------------------------------------------------------------------
    @property
    def device_signature(self) -> str:
        """SHA-256 fingerprint of the asset's sorted function codes + slave IDs."""
        raw = (
            ",".join(sorted(self.function_codes_used))
            + "|"
            + ",".join(str(s) for s in sorted(self.slave_ids))
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable snapshot of this asset record."""
        return {
            "ip": self.ip,
            "first_seen": datetime.fromtimestamp(self.first_seen_epoch).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen_epoch).isoformat(),
            "slave_ids": sorted(self.slave_ids),
            "function_codes_used": sorted(self.function_codes_used),
            "registers_accessed": sorted(self.registers_accessed),
            "write_registers": sorted(self.write_registers),
            "response_timing_samples": self.response_timing_samples[-20:],
            "total_packets": self.total_packets,
            "packet_rate_per_min": round(self.packet_rate_per_min, 2),
            "device_signature": self.device_signature,
            "is_attacker": self.is_attacker,
            "alert_count": self.alert_count,
            "baseline_fcs": sorted(self._baseline_fcs),
            "baseline_locked": self._baseline_locked,
            "dest_ips": sorted(self.dest_ips),
            "os_profile": self.os_profile,
            "vendor": self.vendor,
            "model": self.model,
            "firmware_version": self.firmware_version,
        }

    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "_AssetRecord":
        """Reconstruct from a serialised dict (e.g. from assets.json)."""
        try:
            first_ts = datetime.fromisoformat(d["first_seen"]).timestamp()
        except (KeyError, ValueError):
            first_ts = time.time()

        rec = cls(d.get("ip", "unknown"), first_ts)
        try:
            rec.last_seen_epoch = datetime.fromisoformat(
                d.get("last_seen", d["first_seen"])
            ).timestamp()
        except (ValueError, TypeError):
            rec.last_seen_epoch = first_ts

        rec.slave_ids = set(d.get("slave_ids", []))
        rec.function_codes_used = set(d.get("function_codes_used", []))
        rec.registers_accessed = set(d.get("registers_accessed", []))
        rec.write_registers = set(d.get("write_registers", []))
        rec.response_timing_samples = list(d.get("response_timing_samples", []))
        rec.total_packets = d.get("total_packets", 0)
        rec._baseline_fcs = set(d.get("baseline_fcs", []))
        rec._baseline_locked = bool(d.get("baseline_locked", False))
        rec.is_attacker = bool(d.get("is_attacker", False))
        rec.alert_count = int(d.get("alert_count", 0))
        rec.dest_ips = set(d.get("dest_ips", []))
        rec.os_profile = d.get("os_profile", "Unknown")
        rec.vendor = d.get("vendor", "")
        rec.model = d.get("model", "")
        rec.firmware_version = d.get("firmware_version", "")
        return rec


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class AssetInventory:
    """Passive asset discovery and device-fingerprinting engine.

    Call :py:meth:`observe` for every captured Modbus packet.  Pending alerts
    (new device, behavioural drift) accumulate in an internal queue and can be
    flushed via :py:meth:`get_new_device_alerts`.

    Example::

        inventory = AssetInventory(assets_path='assets.json')
        inventory.load()
        for pkt in stream:
            alerts = inventory.observe(pkt)
            for a in alerts:
                publish(a)
        inventory.save()
    """

    def __init__(self, assets_path: str = "assets.json") -> None:
        """Initialise the inventory.

        Args:
            assets_path: Path to the JSON persistence file.
        """
        self.assets_path: str = assets_path

        # { ip: _AssetRecord }
        self._assets: Dict[str, _AssetRecord] = {}

        # Pending alert queue (flushed by get_new_device_alerts).
        self._pending_alerts: List[Dict[str, Any]] = []

        # Edges seen recently: { (src, dst): last_seen_epoch }
        self._edges: Dict[tuple, float] = {}

        logger.info(
            "AssetInventory initialised — assets_path=%s", assets_path
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def observe(self, packet: Dict) -> List[Dict]:
        """Observe a Modbus packet and update the asset database.

        Args:
            packet: Modbus packet dict with at least ``source_ip``,
                ``function_code``, ``register``, ``operation``,
                ``timestamp``.

        Returns:
            List of newly generated alert dicts (new device or
            behavioural drift).  Alerts are *also* queued internally
            for :py:meth:`get_new_device_alerts`.
        """
        ip: str = packet.get("source_ip", "unknown")
        dest: str = packet.get("dest_ip") or packet.get("destination_ip") or "unknown"
        now: float = time.time()
        alerts: List[Dict] = []

        # Track edge.
        if ip != "unknown" and dest != "unknown":
            self._edges[(ip, dest)] = now

        # New device?
        if ip not in self._assets:
            self._assets[ip] = _AssetRecord(ip, now)
            alert = self._new_device_alert(ip, packet)
            alerts.append(alert)
            self._pending_alerts.append(alert)
            logger.info("AssetInventory: new device discovered — %s", ip)

        # Update record; check for behavioural drift.
        rec = self._assets[ip]
        drift_fc = rec.update(packet, now)
        if drift_fc is not None:
            alert = self._drift_alert(ip, drift_fc, packet)
            alerts.append(alert)
            self._pending_alerts.append(alert)
            rec.alert_count += 1
            logger.info(
                "AssetInventory: behavioural drift for %s — new FC %s",
                ip,
                drift_fc,
            )

        return alerts

    # ------------------------------------------------------------------

    def get_assets(self) -> List[Dict]:
        """Return all tracked assets as a list of serialisable dicts.

        Returns:
            List of asset record dicts, sorted by ``first_seen``.
        """
        return sorted(
            (r.to_dict() for r in self._assets.values()),
            key=lambda d: d["first_seen"],
        )

    # ------------------------------------------------------------------

    def get_topology(self) -> Dict[str, Any]:
        """Build a topology graph suitable for rendering in the TUI.

        Returns:
            ``{"nodes": [...], "edges": [...]}`` where each node has
            ``id``, ``ip``, ``type``, ``status`` and each edge has
            ``source``, ``target``, ``protocol``, ``port``, ``active``.
        """
        now = time.time()
        nodes: List[Dict[str, Any]] = []
        for rec in self._assets.values():
            node_type = self._classify_device(rec)
            status = self._classify_status(rec)
            nodes.append(
                {
                    "id": rec.ip,
                    "ip": rec.ip,
                    "type": node_type,
                    "status": status,
                    "total_packets": rec.total_packets,
                    "device_signature": rec.device_signature,
                }
            )

        edges: List[Dict[str, Any]] = []
        for (src, dst), last_seen in self._edges.items():
            active = (now - last_seen) <= _ACTIVE_EDGE_TTL
            edges.append(
                {
                    "source": src,
                    "target": dst,
                    "protocol": "modbus",
                    "port": 502,
                    "active": active,
                    "last_seen": datetime.fromtimestamp(last_seen).isoformat(),
                }
            )

        return {"nodes": nodes, "edges": edges}

    # ------------------------------------------------------------------

    def get_new_device_alerts(self) -> List[Dict]:
        """Flush and return all pending alerts (new device + drift alerts).

        Returns:
            List of alert dicts.  Subsequent calls will return an empty
            list until new alerts are queued.
        """
        pending = list(self._pending_alerts)
        self._pending_alerts.clear()
        return pending

    # ------------------------------------------------------------------

    def save(self) -> None:
        """Persist the current asset database to ``assets_path`` as JSON."""
        snapshot: Dict[str, Any] = {
            "saved_at": datetime.now().isoformat(),
            "assets": {ip: rec.to_dict() for ip, rec in self._assets.items()},
            "edges": [
                {
                    "source": src,
                    "target": dst,
                    "last_seen": datetime.fromtimestamp(ts).isoformat(),
                }
                for (src, dst), ts in self._edges.items()
            ],
        }
        try:
            with open(self.assets_path, "w", encoding="utf-8") as fh:
                json.dump(snapshot, fh, indent=2)
            logger.info(
                "AssetInventory: saved %d assets to %s",
                len(self._assets),
                self.assets_path,
            )
        except OSError as exc:
            logger.error("AssetInventory: could not save assets: %s", exc)

    # ------------------------------------------------------------------

    def load(self) -> bool:
        """Load persisted assets from ``assets_path``.

        Returns:
            ``True`` if loaded successfully; ``False`` otherwise.
        """
        if not os.path.exists(self.assets_path):
            logger.info(
                "AssetInventory: no asset file found at %s", self.assets_path
            )
            return False
        try:
            with open(self.assets_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            for ip, d in data.get("assets", {}).items():
                self._assets[ip] = _AssetRecord.from_dict(d)

            for edge_entry in data.get("edges", []):
                src = edge_entry.get("source", "")
                dst = edge_entry.get("target", "")
                ts_str = edge_entry.get("last_seen", "")
                if src and dst:
                    try:
                        ts = datetime.fromisoformat(ts_str).timestamp()
                    except (ValueError, TypeError):
                        ts = 0.0
                    self._edges[(src, dst)] = ts

            logger.info(
                "AssetInventory: loaded %d assets from %s",
                len(self._assets),
                self.assets_path,
            )
            return True

        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.error("AssetInventory: failed to load assets: %s", exc)
            return False

    # ------------------------------------------------------------------

    def flag_as_attacker(self, ip: str) -> None:
        """Mark *ip* as an attacker (called when the rule engine fires an alert).

        If the IP is not yet in the inventory, a skeleton record is created.

        Args:
            ip: Source IP address to mark.
        """
        if ip not in self._assets:
            self._assets[ip] = _AssetRecord(ip, time.time())
        self._assets[ip].is_attacker = True
        self._assets[ip].alert_count += 1
        logger.info("AssetInventory: IP %s flagged as attacker.", ip)

    # ------------------------------------------------------------------
    # Classification helpers
    # ------------------------------------------------------------------

    def _classify_device(self, rec: _AssetRecord) -> str:
        """Return device type string based on observed behaviour.

        Returns one of: ``'plc'``, ``'hmi'``, ``'attacker'``, ``'unknown'``.
        """
        if rec.is_attacker:
            return "attacker"

        fcs = rec.function_codes_used
        writes = rec.write_registers

        # PLC heuristic: observed on destination side only (no write traffic
        # originating from this IP, never appears as a source of reads).
        if not writes and not fcs:
            return "plc"

        # HMI heuristic: only uses fc 0x03 (+maybe 0x06), no exotic codes.
        hmi_fcs = {"0x03", "0x06", "3", "6"}
        exotic = fcs - hmi_fcs
        if not exotic and len(fcs) <= 2:
            return "hmi"

        # PLC heuristic v2: responds but never writes.
        if not writes:
            return "plc"

        return "unknown"

    # ------------------------------------------------------------------

    def _classify_status(self, rec: _AssetRecord) -> str:
        """Return operational status string.

        Returns one of: ``'ok'``, ``'suspicious'``, ``'attacking'``.
        """
        if rec.is_attacker:
            return "attacking"
        if rec.alert_count > 0:
            return "suspicious"
        return "ok"

    # ------------------------------------------------------------------
    # Alert factories
    # ------------------------------------------------------------------

    def _new_device_alert(self, ip: str, packet: Dict) -> Dict[str, Any]:
        """Build a NEW_DEVICE_DISCOVERED alert."""
        return {
            "alert_id": str(uuid.uuid4()),
            "alert_type": "new_device_discovered",
            "severity": "high",
            "message": f"New device discovered: {ip}",
            "timestamp": datetime.now().isoformat(),
            "packet_details": packet,
            "analysis_details": {
                "ip": ip,
                "first_function_code": str(packet.get("function_code", "")),
                "first_register": packet.get("register"),
            },
            "mitre_id": "T0886",
            "mitre_name": "Remote Services",
            "is_read": False,
        }

    # ------------------------------------------------------------------

    def _drift_alert(
        self, ip: str, new_fc: str, packet: Dict
    ) -> Dict[str, Any]:
        """Build a DEVICE_BEHAVIORAL_DRIFT alert."""
        rec = self._assets.get(ip)
        baseline = sorted(rec._baseline_fcs) if rec else []
        return {
            "alert_id": str(uuid.uuid4()),
            "alert_type": "device_behavioral_drift",
            "severity": "high",
            "message": (
                f"Device {ip} behavioral drift: new function code {new_fc}"
            ),
            "timestamp": datetime.now().isoformat(),
            "packet_details": packet,
            "analysis_details": {
                "ip": ip,
                "new_function_code": new_fc,
                "baseline_function_codes": baseline,
                "all_function_codes_seen": (
                    sorted(rec.function_codes_used) if rec else []
                ),
            },
            "mitre_id": "T0886",
            "mitre_name": "Remote Services",
            "is_read": False,
        }
