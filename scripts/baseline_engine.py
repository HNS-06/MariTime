#!/usr/bin/env python3
"""
BASELINE ENGINE — Two-Phase Statistical Anomaly Detection

Part of the MariTime Modbus OT/ICS Security Monitor.

Phase 1 – Learning (default 300 s in demo mode):
  Ingests labelled-normal Modbus packets and builds a rich statistical
  profile of per-register value distributions, Markov chains of
  function-code transitions, per-IP request rates, and register
  access maps.

Phase 2 – Detection:
  Every new packet is scored against the learned profile.  Alerts are
  returned as JSON-serialisable dicts that are wire-compatible with
  rule_engine.py alerts so the TUI can render them without extra
  adaptation.

MITRE ATT&CK for ICS reference: T0831 – Manipulation of Control.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import statistics
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger("baseline_engine")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")
    )
    logger.addHandler(_handler)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_ZSCORE_THRESHOLD: float = 2.5          # z-score above which a value is anomalous
_MARKOV_MIN_PROB: float = 0.02          # transition probability below which it is anomalous
_RATE_MULTIPLIER: float = 2.5           # factor above baseline rate that triggers alert
_MIN_SAMPLES_FOR_STAT: int = 5          # minimum samples before statistical checks fire
_MINUTE: float = 60.0                   # seconds per minute (for rate accounting)


# ---------------------------------------------------------------------------
# Helper – tiny running-stats accumulator
# ---------------------------------------------------------------------------
class _RunningStats:
    """Welford online algorithm for mean and variance without storing all samples."""

    __slots__ = ("_n", "_mean", "_M2", "_min", "_max", "_samples")

    def __init__(self) -> None:
        self._n: int = 0
        self._mean: float = 0.0
        self._M2: float = 0.0
        self._min: float = math.inf
        self._max: float = -math.inf
        # Keep first 200 raw samples for percentile computation.
        self._samples: list[float] = []

    # ------------------------------------------------------------------
    def update(self, x: float) -> None:
        """Add a new observation."""
        self._n += 1
        delta = x - self._mean
        self._mean += delta / self._n
        delta2 = x - self._mean
        self._M2 += delta * delta2
        if x < self._min:
            self._min = x
        if x > self._max:
            self._max = x
        if len(self._samples) < 200:
            self._samples.append(x)

    # ------------------------------------------------------------------
    @property
    def n(self) -> int:
        """Number of observations."""
        return self._n

    @property
    def mean(self) -> float:
        """Sample mean."""
        return self._mean

    @property
    def stddev(self) -> float:
        """Sample standard deviation (Bessel-corrected)."""
        if self._n < 2:
            return 0.0
        return math.sqrt(self._M2 / (self._n - 1))

    @property
    def min(self) -> float:
        """Minimum observed value."""
        return self._min if self._n > 0 else 0.0

    @property
    def max(self) -> float:
        """Maximum observed value."""
        return self._max if self._n > 0 else 0.0

    def percentile(self, p: float) -> float:
        """Return approximate p-th percentile (0–100) from stored samples."""
        if not self._samples:
            return 0.0
        sorted_s = sorted(self._samples)
        idx = (p / 100.0) * (len(sorted_s) - 1)
        lo = int(idx)
        hi = min(lo + 1, len(sorted_s) - 1)
        frac = idx - lo
        return sorted_s[lo] * (1 - frac) + sorted_s[hi] * frac

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict (JSON-safe)."""
        return {
            "count": self._n,
            "mean": round(self._mean, 4),
            "stddev": round(self.stddev, 4),
            "min": round(self.min, 4),
            "max": round(self.max, 4),
            "p5": round(self.percentile(5), 4),
            "p95": round(self.percentile(95), 4),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "_RunningStats":
        """Reconstruct from a serialised dict (approximate — full state not stored)."""
        rs = cls()
        rs._n = d.get("count", 0)
        rs._mean = d.get("mean", 0.0)
        rs._min = d.get("min", math.inf)
        rs._max = d.get("max", -math.inf)
        # M2 cannot be reconstructed exactly; approximate from stddev.
        sd = d.get("stddev", 0.0)
        if rs._n >= 2:
            rs._M2 = sd ** 2 * (rs._n - 1)
        return rs


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------
class BaselineEngine:
    """Two-phase statistical anomaly detection engine for Modbus traffic.

    Usage::

        engine = BaselineEngine(learning_duration=60.0)  # 60-second demo
        for pkt in stream:
            alerts = engine.tick(pkt)
            for alert in alerts:
                handle_alert(alert)

    The engine automatically transitions from learning to detection once
    ``learning_duration`` seconds of wall-clock time have elapsed since the
    first packet was ingested (or after :py:meth:`force_complete_learning` is
    called).
    """

    # ------------------------------------------------------------------
    # Construction / configuration
    # ------------------------------------------------------------------
    def __init__(
        self,
        learning_duration: float = 300.0,
        profile_path: str = "baseline_profile.json",
    ) -> None:
        """Initialise the engine.

        Args:
            learning_duration: Number of seconds to spend in the learning
                phase before automatically switching to detection.
            profile_path: Path to persist / load the learned profile.
        """
        self.learning_duration: float = learning_duration
        self.profile_path: str = profile_path

        # --- phase state ---
        self.is_learning: bool = True
        self.learning_progress: float = 0.0   # 0.0 – 1.0
        self._learning_start: Optional[float] = None  # wall-clock epoch

        # --- per-register statistics ---
        # { register_key: _RunningStats }
        self._register_stats: Dict[str, _RunningStats] = defaultdict(
            _RunningStats
        )
        # { register_key: int }  number of write operations
        self._register_write_count: Dict[str, int] = defaultdict(int)
        # { register_key: set[str] }  IPs that wrote to this register
        self._register_write_ips: Dict[str, Set[str]] = defaultdict(set)
        # { register_key: set[str] }  IPs that accessed register at all
        self._register_access_ips: Dict[str, Set[str]] = defaultdict(set)

        # --- Markov chain on function_code sequences ---
        # { prev_fc: { next_fc: count } }
        self._markov: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._last_fc: Optional[str] = None   # function code of previous packet

        # --- per-IP request-rate tracking ---
        # { ip: deque of epoch timestamps (last 10 minutes) }
        self._ip_timestamps: Dict[str, deque] = defaultdict(deque)
        # Learned baseline rate (requests / minute) per IP
        # { ip: float }
        self._ip_baseline_rate: Dict[str, float] = {}

        # --- per-IP function-code map ---
        # { ip: set[function_code] }
        self._ip_fc_map: Dict[str, Set[str]] = defaultdict(set)

        # --- register access frequency across all IPs (count per register) ---
        self._register_access_frequency: Dict[str, int] = defaultdict(int)

        # --- packet counter ---
        self._total_packets: int = 0

        logger.info(
            "BaselineEngine initialised — learning_duration=%.1fs  profile=%s",
            learning_duration,
            profile_path,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def tick(self, packet: Dict) -> List[Dict]:
        """Process a single Modbus packet.

        During the **learning phase** the packet is used to update the
        statistical profile; an empty list is returned.

        During the **detection phase** the packet is scored and any
        triggered anomaly alerts are returned.

        Args:
            packet: Dict with at minimum the keys produced by
                ``packet_capture.py``:
                ``timestamp``, ``source_ip``, ``function_code``,
                ``register``, ``value``, ``operation``.

        Returns:
            List of alert dicts (may be empty).
        """
        self._total_packets += 1

        # Initialise learning start clock on first packet.
        if self._learning_start is None:
            self._learning_start = time.monotonic()
            logger.info("BaselineEngine: learning phase started.")

        # Always ingest packet data.
        self._ingest(packet)

        # Determine phase.
        if self.is_learning:
            elapsed = time.monotonic() - self._learning_start
            self.learning_progress = min(elapsed / self.learning_duration, 1.0)
            if elapsed >= self.learning_duration:
                self._complete_learning()
            return []

        # Detection phase.
        return self._detect(packet)

    # ------------------------------------------------------------------
    def get_status(self) -> Dict[str, Any]:
        """Return a JSON-serialisable status snapshot.

        Returns:
            Dict containing ``is_learning``, ``progress``,
            ``total_packets``, and a brief ``profile_summary``.
        """
        elapsed = (
            time.monotonic() - self._learning_start
            if self._learning_start is not None
            else 0.0
        )
        return {
            "is_learning": self.is_learning,
            "progress": round(self.learning_progress, 4),
            "elapsed_seconds": round(elapsed, 1),
            "learning_duration": self.learning_duration,
            "total_packets": self._total_packets,
            "profile_summary": {
                "registers_tracked": len(self._register_stats),
                "markov_states": len(self._markov),
                "ips_seen": len(self._ip_timestamps),
            },
        }

    # ------------------------------------------------------------------
    def save_profile(self) -> None:
        """Persist the learned profile to ``profile_path`` as JSON."""
        profile: Dict[str, Any] = {
            "saved_at": datetime.now().isoformat(),
            "learning_duration": self.learning_duration,
            "total_packets": self._total_packets,
            "register_stats": {
                k: v.to_dict() for k, v in self._register_stats.items()
            },
            "register_write_count": dict(self._register_write_count),
            "register_write_ips": {
                k: sorted(v) for k, v in self._register_write_ips.items()
            },
            "register_access_ips": {
                k: sorted(v) for k, v in self._register_access_ips.items()
            },
            "markov": {
                k: dict(v) for k, v in self._markov.items()
            },
            "ip_baseline_rate": dict(self._ip_baseline_rate),
            "ip_fc_map": {
                k: sorted(v) for k, v in self._ip_fc_map.items()
            },
            "register_access_frequency": dict(self._register_access_frequency),
        }
        try:
            with open(self.profile_path, "w", encoding="utf-8") as fh:
                json.dump(profile, fh, indent=2)
            logger.info("BaselineEngine: profile saved to %s", self.profile_path)
        except OSError as exc:
            logger.error("BaselineEngine: could not save profile: %s", exc)

    # ------------------------------------------------------------------
    def load_profile(self) -> bool:
        """Load a previously saved profile from ``profile_path``.

        Returns:
            ``True`` if the profile was loaded successfully; ``False``
            otherwise (file missing, JSON error, etc.).
        """
        if not os.path.exists(self.profile_path):
            logger.info(
                "BaselineEngine: no profile found at %s", self.profile_path
            )
            return False
        try:
            with open(self.profile_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            # Restore register stats.
            for k, d in data.get("register_stats", {}).items():
                self._register_stats[k] = _RunningStats.from_dict(d)

            self._register_write_count = defaultdict(
                int, data.get("register_write_count", {})
            )
            self._register_write_ips = {
                k: set(v)
                for k, v in data.get("register_write_ips", {}).items()
            }
            self._register_access_ips = {
                k: set(v)
                for k, v in data.get("register_access_ips", {}).items()
            }

            # Restore Markov chain.
            self._markov = defaultdict(
                lambda: defaultdict(int),
                {
                    k: defaultdict(int, v)
                    for k, v in data.get("markov", {}).items()
                },
            )

            self._ip_baseline_rate = dict(data.get("ip_baseline_rate", {}))
            self._ip_fc_map = {
                k: set(v) for k, v in data.get("ip_fc_map", {}).items()
            }
            self._register_access_frequency = defaultdict(
                int, data.get("register_access_frequency", {})
            )
            self._total_packets = data.get("total_packets", 0)

            # Switch immediately to detection phase.
            self.is_learning = False
            self.learning_progress = 1.0
            logger.info(
                "BaselineEngine: profile loaded from %s — switching to detection.",
                self.profile_path,
            )
            return True

        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.error("BaselineEngine: failed to load profile: %s", exc)
            return False

    # ------------------------------------------------------------------
    def force_complete_learning(self) -> None:
        """Immediately end the learning phase and switch to detection.

        Useful for demo / testing when you don't want to wait for the full
        ``learning_duration``.  The learned profile is saved automatically.
        """
        if self.is_learning:
            self._complete_learning()
        else:
            logger.info(
                "BaselineEngine: already in detection phase — no-op."
            )

    # ------------------------------------------------------------------
    def get_markov_stats(self) -> Dict[str, Dict[str, int]]:
        """Return a copy of the Markov transition matrix as a plain dict.

        Returns:
            ``{previous_fc: {next_fc: count, ...}, ...}``
        """
        return {k: dict(v) for k, v in self._markov.items()}

    # ------------------------------------------------------------------
    # Internal helpers — data ingestion
    # ------------------------------------------------------------------
    def _ingest(self, packet: Dict) -> None:
        """Update all internal models from *packet* (learning + detection phases)."""
        ip: str = packet.get("source_ip", "unknown")
        fc: str = str(packet.get("function_code", ""))
        reg = packet.get("register")
        value = packet.get("value")
        operation: str = str(packet.get("operation", "read")).lower()
        now = time.monotonic()

        # --- per-IP timestamps for rate tracking ---
        ts_deque = self._ip_timestamps[ip]
        ts_deque.append(now)
        # Keep only last 10 minutes worth of timestamps.
        cutoff = now - 600.0
        while ts_deque and ts_deque[0] < cutoff:
            ts_deque.popleft()

        # --- per-IP function-code map ---
        if fc:
            self._ip_fc_map[ip].add(fc)

        # --- Markov chain update ---
        if fc:
            if self._last_fc is not None:
                self._markov[self._last_fc][fc] += 1
            self._last_fc = fc

        # --- register-level statistics ---
        if reg is not None:
            reg_key = str(reg)
            self._register_access_frequency[reg_key] += 1
            self._register_access_ips[reg_key].add(ip)

            if value is not None:
                try:
                    self._register_stats[reg_key].update(float(value))
                except (TypeError, ValueError):
                    pass

            if operation in {"write", "w"} or fc in {
                "0x06", "0x10", "0x0f", "6", "10", "15", "16"
            }:
                self._register_write_count[reg_key] += 1
                self._register_write_ips[reg_key].add(ip)

        # --- baseline rate snapshot during learning ---
        if self.is_learning and self._learning_start is not None:
            elapsed = time.monotonic() - self._learning_start
            if elapsed > 0:
                for _ip, _dq in self._ip_timestamps.items():
                    # count packets in last 60 s during learning window
                    recent = sum(1 for t in _dq if t >= now - _MINUTE)
                    self._ip_baseline_rate[_ip] = float(recent)

    # ------------------------------------------------------------------
    # Internal helpers — phase transition
    # ------------------------------------------------------------------
    def _complete_learning(self) -> None:
        """Finalise learning and persist the profile."""
        self.is_learning = False
        self.learning_progress = 1.0
        # Compute final per-IP baseline rates (packets / minute).
        now = time.monotonic()
        for ip, dq in self._ip_timestamps.items():
            recent = sum(1 for t in dq if t >= now - _MINUTE)
            self._ip_baseline_rate[ip] = float(recent)
        self.save_profile()
        logger.info(
            "BaselineEngine: learning complete — %d registers, %d IPs, "
            "%d Markov states tracked.  Switching to detection.",
            len(self._register_stats),
            len(self._ip_timestamps),
            len(self._markov),
        )

    # ------------------------------------------------------------------
    # Internal helpers — detection
    # ------------------------------------------------------------------
    def _detect(self, packet: Dict) -> List[Dict]:
        """Score *packet* against the learned profile and return alerts."""
        alerts: List[Dict] = []
        ip: str = packet.get("source_ip", "unknown")
        fc: str = str(packet.get("function_code", ""))
        reg = packet.get("register")
        value = packet.get("value")

        # 1. Z-score check on register value.
        if reg is not None and value is not None:
            reg_key = str(reg)
            rs = self._register_stats.get(reg_key)
            if rs is not None and rs.n >= _MIN_SAMPLES_FOR_STAT:
                sd = rs.stddev
                if sd > 0:
                    try:
                        z = abs(float(value) - rs.mean) / sd
                        if z > _ZSCORE_THRESHOLD:
                            alerts.append(
                                self._make_alert(
                                    severity="high",
                                    message=(
                                        f"Register {reg} value {value} deviates "
                                        f"{z:.2f}σ from baseline mean "
                                        f"{rs.mean:.2f} ± {sd:.2f}"
                                    ),
                                    packet=packet,
                                    analysis={
                                        "check": "zscore",
                                        "register": reg,
                                        "value": value,
                                        "mean": round(rs.mean, 4),
                                        "stddev": round(sd, 4),
                                        "z_score": round(z, 4),
                                        "threshold": _ZSCORE_THRESHOLD,
                                    },
                                )
                            )
                    except (TypeError, ValueError):
                        pass

        # 2. Markov chain: low-probability function-code transition.
        if fc and self._last_fc is not None:
            prev = self._last_fc
            transitions = self._markov.get(prev)
            if transitions:
                total = sum(transitions.values())
                count = transitions.get(fc, 0)
                prob = count / total if total > 0 else 0.0
                if prob < _MARKOV_MIN_PROB and total >= _MIN_SAMPLES_FOR_STAT:
                    alerts.append(
                        self._make_alert(
                            severity="warning",
                            message=(
                                f"Rare function-code transition "
                                f"{prev} → {fc}  (p={prob:.1%}, threshold={_MARKOV_MIN_PROB:.0%})"
                            ),
                            packet=packet,
                            analysis={
                                "check": "markov_transition",
                                "prev_fc": prev,
                                "next_fc": fc,
                                "probability": round(prob, 6),
                                "threshold": _MARKOV_MIN_PROB,
                                "transition_count": count,
                                "total_from_state": total,
                            },
                        )
                    )

        # 3. IP accessing register it never accessed during learning.
        if reg is not None:
            reg_key = str(reg)
            known_ips = self._register_access_ips.get(reg_key, set())
            if known_ips and ip not in known_ips:
                alerts.append(
                    self._make_alert(
                        severity="high",
                        message=(
                            f"IP {ip} accessed register {reg} — "
                            "never seen during baseline learning"
                        ),
                        packet=packet,
                        analysis={
                            "check": "new_ip_register_access",
                            "ip": ip,
                            "register": reg,
                            "known_ips_for_register": sorted(known_ips),
                        },
                    )
                )

        # 4. Request rate from IP > 2.5x learned baseline rate.
        baseline_rate = self._ip_baseline_rate.get(ip, 0.0)
        if baseline_rate > 0:
            now = time.monotonic()
            dq = self._ip_timestamps.get(ip, deque())
            current_rate = sum(1 for t in dq if t >= now - _MINUTE)
            if current_rate > _RATE_MULTIPLIER * baseline_rate:
                alerts.append(
                    self._make_alert(
                        severity="critical",
                        message=(
                            f"IP {ip} request rate {current_rate:.0f}/min exceeds "
                            f"{_RATE_MULTIPLIER}× baseline of {baseline_rate:.0f}/min"
                        ),
                        packet=packet,
                        analysis={
                            "check": "rate_spike",
                            "ip": ip,
                            "current_rate_per_min": current_rate,
                            "baseline_rate_per_min": round(baseline_rate, 2),
                            "multiplier_threshold": _RATE_MULTIPLIER,
                        },
                    )
                )

        return alerts

    # ------------------------------------------------------------------
    # Alert factory
    # ------------------------------------------------------------------
    def _make_alert(
        self,
        *,
        severity: str,
        message: str,
        packet: Dict,
        analysis: Dict,
    ) -> Dict[str, Any]:
        """Build a JSON-serialisable alert dict.

        The format is wire-compatible with ``rule_engine.py`` alerts.
        """
        return {
            "alert_id": str(uuid.uuid4()),
            "alert_type": "baseline_anomaly",
            "severity": severity,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "packet_details": packet,
            "analysis_details": analysis,
            "mitre_id": "T0831",
            "mitre_name": "Manipulation of Control",
            "is_read": False,
        }
