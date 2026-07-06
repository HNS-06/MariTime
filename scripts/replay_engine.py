#!/usr/bin/env python3
"""
Historical Traffic Replay Engine
=================================

Load a JSONL capture file and replay every packet through the ModbusRuleEngine
at the original inter-packet timing (or faster / instant).  Useful for:

* Regression-testing rule changes against recorded attack traffic.
* Demo / training walkthroughs without a live PLC.
* Post-incident re-analysis.

Usage::

    engine = ModbusRuleEngine()
    replay = ReplayEngine()

    if replay.load_jsonl('captured_packets.jsonl'):
        alerts = await replay.replay(engine, speed=2.0)
        print(f"Replayed {replay.replayed_packets} packets, "
              f"generated {len(alerts)} alerts")

JSONL format (one JSON object per line)::

    {"timestamp": "2026-07-05T12:00:00.123", "source_ip": "10.0.1.99", ...}
"""

import asyncio
import glob
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger("replay_engine")


class ReplayEngine:
    """Replay pre-recorded Modbus packet streams through a rule engine.

    Attributes:
        progress:         Fraction of packets replayed so far (0.0 – 1.0).
        is_replaying:     True while a replay is running.
        total_packets:    Total packets in the loaded file.
        replayed_packets: Packets replayed in the current (or last) run.
        current_file:     Path to the currently loaded JSONL file.
        speed:            Current replay speed multiplier.
    """

    def __init__(self) -> None:
        self.progress: float = 0.0
        self.is_replaying: bool = False
        self.total_packets: int = 0
        self.replayed_packets: int = 0
        self.current_file: str = ""
        self.speed: float = 1.0

        self._packets: List[Dict] = []
        self._stop_requested: bool = False

    # ------------------------------------------------------------------
    # File loading
    # ------------------------------------------------------------------

    def load_jsonl(self, filepath: str) -> bool:
        """Load a JSONL file into memory, sorted by timestamp.

        Each line must be a valid JSON object.  Lines that cannot be parsed
        are skipped with a warning.

        Args:
            filepath: Absolute or relative path to the JSONL file.

        Returns:
            *True* on success, *False* if the file cannot be loaded.
        """
        if not os.path.exists(filepath):
            logger.error("load_jsonl: file not found: %s", filepath)
            return False

        raw_packets: List[Dict] = []
        parse_errors = 0

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        pkt = json.loads(line)
                        if isinstance(pkt, dict):
                            raw_packets.append(pkt)
                        else:
                            logger.warning(
                                "load_jsonl: line %d is not a JSON object — skipped",
                                lineno,
                            )
                            parse_errors += 1
                    except json.JSONDecodeError as exc:
                        logger.warning(
                            "load_jsonl: line %d JSON error (%s) — skipped",
                            lineno,
                            exc,
                        )
                        parse_errors += 1

        except OSError as exc:
            logger.error("load_jsonl: cannot open %s: %s", filepath, exc)
            return False

        if not raw_packets:
            logger.error("load_jsonl: no valid packets found in %s", filepath)
            return False

        # Sort by timestamp (ISO-8601 string sort is lexicographically correct)
        def _ts_key(pkt: Dict) -> str:
            return pkt.get("timestamp", "") or ""

        raw_packets.sort(key=_ts_key)

        self._packets = raw_packets
        self.total_packets = len(raw_packets)
        self.current_file = os.path.abspath(filepath)
        self.progress = 0.0
        self.replayed_packets = 0

        logger.info(
            "load_jsonl: loaded %d packets from %s (%d parse errors)",
            self.total_packets,
            filepath,
            parse_errors,
        )
        return True

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    async def replay(
        self,
        rule_engine: Any,
        speed: float = 1.0,
        callback: Optional[Callable[[List[Dict]], Coroutine]] = None,
    ) -> List[Dict]:
        """Replay all loaded packets through *rule_engine*.

        Preserves the original inter-packet timing scaled by *speed*.
        Setting ``speed=0.0`` replays all packets with no delays.

        Args:
            rule_engine: A :class:`ModbusRuleEngine` instance (or any object
                         with a ``process_packet(Dict) -> List[Dict]`` method).
            speed:       Playback speed multiplier.
                         1.0 = real-time, 2.0 = 2× faster, 0.0 = instant.
            callback:    Optional async callable invoked after each packet with
                         the alerts it produced::

                             async def on_alerts(alerts: List[Dict]) -> None: ...

        Returns:
            Complete list of every alert generated during the replay.

        Raises:
            RuntimeError: If no packets are loaded (call :meth:`load_jsonl` first).
        """
        if not self._packets:
            raise RuntimeError(
                "No packets loaded.  Call load_jsonl() before replay()."
            )

        if self.is_replaying:
            logger.warning("replay: already running — stop the current replay first")
            return []

        self.is_replaying = True
        self._stop_requested = False
        self.speed = speed
        self.replayed_packets = 0
        self.progress = 0.0
        all_alerts: List[Dict] = []

        logger.info(
            "Replay starting: %d packets  speed=%.2f  file=%s",
            self.total_packets,
            speed,
            self.current_file,
        )

        prev_ts: Optional[float] = None

        try:
            for idx, pkt in enumerate(self._packets):
                if self._stop_requested:
                    logger.info("Replay stopped at packet %d / %d", idx, self.total_packets)
                    break

                # Compute and apply inter-packet delay
                if speed != 0.0:
                    pkt_ts = self._parse_timestamp(pkt.get("timestamp", ""))
                    if pkt_ts is not None and prev_ts is not None:
                        gap = pkt_ts - prev_ts
                        if gap > 0:
                            delay = gap / speed
                            # Cap individual delays at 5 s to avoid stalling
                            await asyncio.sleep(min(delay, 5.0))
                    prev_ts = pkt_ts
                else:
                    # Yield control periodically to avoid blocking the event loop
                    if idx % 50 == 0:
                        await asyncio.sleep(0)

                # Process packet through rule engine
                try:
                    pkt_alerts: List[Dict] = rule_engine.process_packet(pkt)
                except Exception as exc:
                    logger.error(
                        "replay: rule engine error on packet %d: %s", idx, exc
                    )
                    pkt_alerts = []

                all_alerts.extend(pkt_alerts)

                # Fire callback
                if callback is not None and pkt_alerts:
                    try:
                        await callback(pkt_alerts)
                    except Exception as exc:
                        logger.warning("replay: callback raised: %s", exc)

                # Update progress
                self.replayed_packets = idx + 1
                self.progress = self.replayed_packets / self.total_packets

        finally:
            self.is_replaying = False

        logger.info(
            "Replay complete: %d/%d packets replayed, %d alerts generated",
            self.replayed_packets,
            self.total_packets,
            len(all_alerts),
        )
        return all_alerts

    # ------------------------------------------------------------------
    # Control
    # ------------------------------------------------------------------

    def stop(self) -> None:
        """Request a graceful stop of the running replay.

        The replay loop checks this flag between packets.
        """
        if self.is_replaying:
            self._stop_requested = True
            logger.info("ReplayEngine: stop requested")
        else:
            logger.debug("ReplayEngine.stop() called but not replaying")

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> Dict:
        """Return a JSON-serialisable status snapshot.

        Returns:
            ::

                {
                    "is_replaying":     False,
                    "progress":         0.73,
                    "total_packets":    4800,
                    "replayed_packets": 3504,
                    "current_file":     "/abs/path/captured_packets.jsonl",
                    "speed":            2.0,
                }
        """
        return {
            "is_replaying": self.is_replaying,
            "progress": round(self.progress, 4),
            "total_packets": self.total_packets,
            "replayed_packets": self.replayed_packets,
            "current_file": self.current_file,
            "speed": self.speed,
        }

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def find_replay_files(search_dir: str = ".") -> List[str]:
        """Return a sorted list of ``.jsonl`` files found in *search_dir*.

        Args:
            search_dir: Directory to search (non-recursive).

        Returns:
            Sorted list of absolute paths.
        """
        pattern = os.path.join(search_dir, "*.jsonl")
        files = glob.glob(pattern)
        files.sort()
        return [os.path.abspath(f) for f in files]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_timestamp(ts_str: str) -> Optional[float]:
        """Convert an ISO-8601 timestamp string to a POSIX float.

        Returns *None* if parsing fails.
        """
        if not ts_str:
            return None
        # Support both 'T' and space separators; trim trailing Z/timezone
        ts_str = ts_str.replace("Z", "").replace(" ", "T")
        # Strip sub-second precision beyond microseconds
        if "." in ts_str:
            date_part, frac = ts_str.split(".", 1)
            frac = frac[:6]
            ts_str = f"{date_part}.{frac}"
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                dt = datetime.strptime(ts_str, fmt)
                return dt.timestamp()
            except ValueError:
                continue
        return None

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"ReplayEngine("
            f"is_replaying={self.is_replaying}, "
            f"progress={self.progress:.1%}, "
            f"packets={self.replayed_packets}/{self.total_packets})"
        )
