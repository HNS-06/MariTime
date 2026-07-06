#!/usr/bin/env python3
"""
CORRELATION ENGINE — Sliding-Window Multi-Packet Attack Pattern Detection

Part of the MariTime Modbus OT/ICS Security Monitor.

Maintains a rolling deque of recent packets per source IP (configurable
window, default 120 s) and applies named pattern detectors to identify
multi-step attack sequences that no single-packet rule can catch.

Detected patterns
-----------------
1. RECON_THEN_STRIKE  — ≥5 different register READs then a WRITE within 60 s
                         MITRE T0888
2. REGISTER_SWEEP     — ≥8 consecutive register READs within 10 s
                         MITRE T0846
3. SLOW_BURN          — ≥3 WRITEs to the same register spread over >120 s
                         MITRE T0831
4. SAFETY_BYPASS_SEQ  — READ register 40006 then WRITE register 40006 within 60 s
                         MITRE T0838
5. RAPID_FUNC_PIVOT   — ≥3 different function codes from same IP within 30 s
                         MITRE T0814

All alerts include the key 'correlated': True and
'constituent_packets': [list of the contributing packets].
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger("correlation_engine")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(
        logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")
    )
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Tiny helper — extract numeric epoch from a packet's timestamp field.
# ---------------------------------------------------------------------------

def _epoch(packet: Dict) -> float:
    """Return a float Unix timestamp from packet['timestamp'] (ISO string)."""
    raw = packet.get("timestamp", "")
    try:
        return datetime.fromisoformat(str(raw)).timestamp()
    except (ValueError, TypeError):
        # Fall back to now if unparseable.
        return datetime.now().timestamp()


def _is_write(packet: Dict) -> bool:
    """Return True when the packet represents a Modbus write operation."""
    op = str(packet.get("operation", "")).lower()
    fc = str(packet.get("function_code", ""))
    return op in {"write", "w"} or fc in {
        "0x06", "0x10", "0x0f", "6", "10", "15", "16"
    }


def _is_read(packet: Dict) -> bool:
    """Return True when the packet represents a Modbus read operation."""
    return not _is_write(packet)


# ---------------------------------------------------------------------------
# Per-IP sliding window — a typed named class for clarity.
# ---------------------------------------------------------------------------

class _IPWindow:
    """Sliding deque of packets for one source IP."""

    __slots__ = ("ip", "window_seconds", "_packets")

    def __init__(self, ip: str, window_seconds: float) -> None:
        self.ip: str = ip
        self.window_seconds: float = window_seconds
        self._packets: Deque[Dict] = deque()

    def add(self, packet: Dict) -> None:
        """Append *packet* and evict entries older than the window."""
        self._packets.append(packet)
        self._evict()

    def _evict(self) -> None:
        """Remove packets outside the sliding window."""
        if not self._packets:
            return
        newest = _epoch(self._packets[-1])
        cutoff = newest - self.window_seconds
        while self._packets and _epoch(self._packets[0]) < cutoff:
            self._packets.popleft()

    def recent(self, max_age: float) -> List[Dict]:
        """Return packets no older than *max_age* seconds from the newest."""
        if not self._packets:
            return []
        newest = _epoch(self._packets[-1])
        cutoff = newest - max_age
        return [p for p in self._packets if _epoch(p) >= cutoff]

    def all(self) -> List[Dict]:
        """Return all packets currently in the window."""
        return list(self._packets)


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Sliding-window sequence-of-events correlation engine.

    Call :py:meth:`ingest` for every packet arriving at the monitor.
    Any newly detected composite attack patterns are returned immediately
    as a list of alert dicts.

    Example::

        ce = CorrelationEngine(window_seconds=120.0)
        for pkt in stream:
            alerts = ce.ingest(pkt)
            for a in alerts:
                publish(a)
    """

    def __init__(self, window_seconds: float = 120.0) -> None:
        """Initialise the engine.

        Args:
            window_seconds: Maximum age (in seconds) of packets kept per
                source IP.  Packets older than this are evicted.
        """
        self.window_seconds: float = window_seconds

        # One _IPWindow per source IP.
        self._windows: Dict[str, _IPWindow] = {}

        # Running counts of each pattern type detected so far.
        self._pattern_counts: Dict[str, int] = {
            "RECON_THEN_STRIKE": 0,
            "REGISTER_SWEEP": 0,
            "SLOW_BURN": 0,
            "SAFETY_BYPASS_SEQUENCE": 0,
            "RAPID_FUNCTION_PIVOT": 0,
        }

        # Deduplicate recently-fired alerts to avoid a flood of identical
        # composite alerts per tick.  Key: (ip, pattern, trigger_ts_bucket).
        self._recent_fire_keys: Set[str] = set()
        self._fire_key_ttl: float = 30.0   # seconds before re-arming

        # Store references to in-progress sequences for introspection.
        # { ip: { pattern: {'started': float, 'packets': [...]} } }
        self._active: Dict[str, Dict[str, Any]] = defaultdict(dict)

        logger.info(
            "CorrelationEngine initialised — window=%.0fs", window_seconds
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, packet: Dict) -> List[Dict]:
        """Process *packet* and return any newly fired composite alerts.

        Args:
            packet: Modbus packet dict with fields ``source_ip``,
                ``function_code``, ``register``, ``value``, ``operation``,
                ``timestamp``.

        Returns:
            List of alert dicts (may be empty).  Each alert has
            ``correlated=True`` and ``constituent_packets``.
        """
        ip: str = packet.get("source_ip", "unknown")

        # Initialise per-IP window on first sight.
        if ip not in self._windows:
            self._windows[ip] = _IPWindow(ip, self.window_seconds)

        win = self._windows[ip]
        win.add(packet)

        alerts: List[Dict] = []
        alerts.extend(self._check_recon_then_strike(ip, win))
        alerts.extend(self._check_register_sweep(ip, win))
        alerts.extend(self._check_slow_burn(ip, win))
        alerts.extend(self._check_safety_bypass(ip, win))
        alerts.extend(self._check_rapid_function_pivot(ip, win))

        return alerts

    # ------------------------------------------------------------------

    def get_pattern_stats(self) -> Dict[str, int]:
        """Return cumulative detection counts per pattern name.

        Returns:
            ``{pattern_name: count}``
        """
        return dict(self._pattern_counts)

    # ------------------------------------------------------------------

    def get_active_sequences(self) -> List[Dict]:
        """Return currently tracked in-progress sequences across all IPs.

        Returns:
            List of dicts, each with keys ``ip``, ``pattern``,
            ``started_at`` (ISO timestamp), ``packet_count``.
        """
        result: List[Dict] = []
        for ip, patterns in self._active.items():
            for pattern, state in patterns.items():
                result.append(
                    {
                        "ip": ip,
                        "pattern": pattern,
                        "started_at": datetime.fromtimestamp(
                            state.get("started", 0.0)
                        ).isoformat(),
                        "packet_count": len(state.get("packets", [])),
                    }
                )
        return result

    # ------------------------------------------------------------------
    # Pattern detectors
    # ------------------------------------------------------------------

    def _check_recon_then_strike(
        self, ip: str, win: _IPWindow
    ) -> List[Dict]:
        """RECON_THEN_STRIKE: ≥5 different register READs then a WRITE within 60 s.

        MITRE T0888 – Remote System Information Discovery.
        """
        alerts: List[Dict] = []
        packets_60s = win.recent(60.0)

        # Collect reads.
        read_regs: Set[str] = set()
        read_pkts: List[Dict] = []
        write_pkts: List[Dict] = []
        for p in packets_60s:
            reg = p.get("register")
            if reg is None:
                continue
            if _is_read(p):
                read_regs.add(str(reg))
                read_pkts.append(p)
            elif _is_write(p):
                write_pkts.append(p)

        if len(read_regs) >= 5 and write_pkts:
            constituent = read_pkts + write_pkts
            fire_key = self._fire_key(ip, "RECON_THEN_STRIKE", write_pkts[-1])
            if fire_key not in self._recent_fire_keys:
                self._recent_fire_keys.add(fire_key)
                self._pattern_counts["RECON_THEN_STRIKE"] += 1
                alerts.append(
                    self._make_alert(
                        pattern="RECON_THEN_STRIKE",
                        severity="critical",
                        mitre_id="T0888",
                        mitre_name="Remote System Information Discovery",
                        message=(
                            f"IP {ip} performed reconnaissance on "
                            f"{len(read_regs)} registers then issued a "
                            f"write within 60 s — likely RECON_THEN_STRIKE"
                        ),
                        ip=ip,
                        constituent=constituent,
                        analysis={
                            "read_registers": sorted(read_regs),
                            "unique_registers_read": len(read_regs),
                            "write_count": len(write_pkts),
                        },
                    )
                )
        return alerts

    # ------------------------------------------------------------------

    def _check_register_sweep(
        self, ip: str, win: _IPWindow
    ) -> List[Dict]:
        """REGISTER_SWEEP: ≥8 consecutive register READs within 10 s.

        'Consecutive' means the register numbers form a contiguous run
        (any ordering) with no gap larger than 1.

        MITRE T0846 – Remote System Discovery.
        """
        alerts: List[Dict] = []
        packets_10s = win.recent(10.0)

        read_pkts = [p for p in packets_10s if _is_read(p) and p.get("register") is not None]
        if len(read_pkts) < 8:
            return alerts

        reg_nums: List[int] = []
        reg_to_pkt: Dict[int, Dict] = {}
        for p in read_pkts:
            try:
                r = int(p["register"])
                reg_nums.append(r)
                reg_to_pkt[r] = p
            except (ValueError, TypeError):
                pass

        if len(reg_nums) < 8:
            return alerts

        reg_nums_sorted = sorted(set(reg_nums))
        # Find the longest consecutive run.
        best_run: List[int] = []
        current_run: List[int] = [reg_nums_sorted[0]]
        for i in range(1, len(reg_nums_sorted)):
            if reg_nums_sorted[i] - reg_nums_sorted[i - 1] <= 1:
                current_run.append(reg_nums_sorted[i])
            else:
                if len(current_run) > len(best_run):
                    best_run = current_run
                current_run = [reg_nums_sorted[i]]
        if len(current_run) > len(best_run):
            best_run = current_run

        if len(best_run) >= 8:
            constituent = [reg_to_pkt[r] for r in best_run if r in reg_to_pkt]
            fire_key = self._fire_key(ip, "REGISTER_SWEEP", read_pkts[-1])
            if fire_key not in self._recent_fire_keys:
                self._recent_fire_keys.add(fire_key)
                self._pattern_counts["REGISTER_SWEEP"] += 1
                alerts.append(
                    self._make_alert(
                        pattern="REGISTER_SWEEP",
                        severity="high",
                        mitre_id="T0846",
                        mitre_name="Remote System Discovery",
                        message=(
                            f"IP {ip} performed a sequential sweep of "
                            f"{len(best_run)} consecutive registers "
                            f"({best_run[0]}–{best_run[-1]}) within 10 s"
                        ),
                        ip=ip,
                        constituent=constituent,
                        analysis={
                            "run_start": best_run[0],
                            "run_end": best_run[-1],
                            "run_length": len(best_run),
                            "registers": best_run,
                        },
                    )
                )
        return alerts

    # ------------------------------------------------------------------

    def _check_slow_burn(
        self, ip: str, win: _IPWindow
    ) -> List[Dict]:
        """SLOW_BURN: ≥3 writes to the same register spread over >120 s.

        MITRE T0831 – Manipulation of Control.
        """
        alerts: List[Dict] = []
        all_pkts = win.all()

        # Group write packets by register.
        reg_writes: Dict[str, List[Dict]] = defaultdict(list)
        for p in all_pkts:
            if _is_write(p) and p.get("register") is not None:
                reg_writes[str(p["register"])].append(p)

        for reg_key, wpkts in reg_writes.items():
            if len(wpkts) < 3:
                continue
            times = sorted(_epoch(p) for p in wpkts)
            spread = times[-1] - times[0]
            if spread > 120.0:
                fire_key = self._fire_key(
                    ip, f"SLOW_BURN_{reg_key}", wpkts[-1]
                )
                if fire_key not in self._recent_fire_keys:
                    self._recent_fire_keys.add(fire_key)
                    self._pattern_counts["SLOW_BURN"] += 1
                    alerts.append(
                        self._make_alert(
                            pattern="SLOW_BURN",
                            severity="warning",
                            mitre_id="T0831",
                            mitre_name="Manipulation of Control",
                            message=(
                                f"IP {ip} wrote to register {reg_key} "
                                f"{len(wpkts)} times over "
                                f"{spread:.0f} s — possible slow-burn manipulation"
                            ),
                            ip=ip,
                            constituent=wpkts,
                            analysis={
                                "register": reg_key,
                                "write_count": len(wpkts),
                                "spread_seconds": round(spread, 1),
                            },
                        )
                    )
        return alerts

    # ------------------------------------------------------------------

    def _check_safety_bypass(
        self, ip: str, win: _IPWindow
    ) -> List[Dict]:
        """SAFETY_BYPASS_SEQUENCE: READ 40006, then WRITE 40006 within 60 s.

        MITRE T0838 – Modify Alarm Settings.
        """
        alerts: List[Dict] = []
        packets_60s = win.recent(60.0)

        safety_reg = "40006"
        read_of_safety: Optional[Dict] = None
        for p in packets_60s:
            reg = str(p.get("register", ""))
            if reg != safety_reg:
                continue
            if _is_read(p) and read_of_safety is None:
                read_of_safety = p
            elif _is_write(p) and read_of_safety is not None:
                fire_key = self._fire_key(ip, "SAFETY_BYPASS_SEQUENCE", p)
                if fire_key not in self._recent_fire_keys:
                    self._recent_fire_keys.add(fire_key)
                    self._pattern_counts["SAFETY_BYPASS_SEQUENCE"] += 1
                    alerts.append(
                        self._make_alert(
                            pattern="SAFETY_BYPASS_SEQUENCE",
                            severity="critical",
                            mitre_id="T0838",
                            mitre_name="Modify Alarm Settings",
                            message=(
                                f"IP {ip} read safety-critical register "
                                f"{safety_reg}, then wrote to it within 60 s "
                                f"— potential alarm bypass"
                            ),
                            ip=ip,
                            constituent=[read_of_safety, p],
                            analysis={
                                "safety_register": safety_reg,
                                "read_ts": read_of_safety.get("timestamp"),
                                "write_ts": p.get("timestamp"),
                                "write_value": p.get("value"),
                            },
                        )
                    )
                break   # only fire once per scan of this window

        return alerts

    # ------------------------------------------------------------------

    def _check_rapid_function_pivot(
        self, ip: str, win: _IPWindow
    ) -> List[Dict]:
        """RAPID_FUNCTION_PIVOT: ≥3 different function codes from same IP within 30 s.

        MITRE T0814 – Denial of Control.
        """
        alerts: List[Dict] = []
        packets_30s = win.recent(30.0)

        fcs: Set[str] = set()
        fc_pkts: Dict[str, Dict] = {}
        for p in packets_30s:
            fc = str(p.get("function_code", ""))
            if fc:
                fcs.add(fc)
                fc_pkts[fc] = p

        if len(fcs) >= 3:
            constituent = list(fc_pkts.values())
            fire_key = self._fire_key(ip, "RAPID_FUNCTION_PIVOT", packets_30s[-1])
            if fire_key not in self._recent_fire_keys:
                self._recent_fire_keys.add(fire_key)
                self._pattern_counts["RAPID_FUNCTION_PIVOT"] += 1
                alerts.append(
                    self._make_alert(
                        pattern="RAPID_FUNCTION_PIVOT",
                        severity="high",
                        mitre_id="T0814",
                        mitre_name="Denial of Control",
                        message=(
                            f"IP {ip} used {len(fcs)} different function "
                            f"codes ({', '.join(sorted(fcs))}) within 30 s "
                            f"— rapid function-code pivoting"
                        ),
                        ip=ip,
                        constituent=constituent,
                        analysis={
                            "function_codes": sorted(fcs),
                            "unique_count": len(fcs),
                        },
                    )
                )
        return alerts

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fire_key(self, ip: str, pattern: str, trigger_pkt: Dict) -> str:
        """Produce a deduplication key bucketed to 30-second intervals."""
        ts = _epoch(trigger_pkt)
        bucket = int(ts / self._fire_key_ttl)
        return f"{ip}|{pattern}|{bucket}"

    # ------------------------------------------------------------------

    def _make_alert(
        self,
        *,
        pattern: str,
        severity: str,
        mitre_id: str,
        mitre_name: str,
        message: str,
        ip: str,
        constituent: List[Dict],
        analysis: Dict,
    ) -> Dict[str, Any]:
        """Build a JSON-serialisable composite alert dict."""
        logger.warning(
            "CorrelationEngine: %s fired for IP %s — %s",
            pattern,
            ip,
            message[:80],
        )
        return {
            "alert_id": str(uuid.uuid4()),
            "alert_type": f"correlation_{pattern.lower()}",
            "severity": severity,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "source_ip": ip,
            "correlated": True,
            "pattern": pattern,
            "constituent_packets": constituent,
            "analysis_details": analysis,
            "mitre_id": mitre_id,
            "mitre_name": mitre_name,
            "is_read": False,
        }
