#!/usr/bin/env python3
"""
PLC Firmware / Configuration Integrity Monitor
===============================================

Simulates a PLC configuration blob and detects unauthorized in-memory or on-disk
changes using SHA-256 hash chaining.  Any divergence from the stored baseline is
surfaced as a CRITICAL security alert mapped to MITRE ATT&CK ICS technique T0839
(Modify Program).

Typical usage::

    watcher = FirmwareWatcher(config_path='plc_firmware.json')
    alert = watcher.check()          # None if integrity OK
    if alert:
        # forward alert to rule engine / TUI

Demo::

    watcher.tamper_for_demo()        # corrupt in-memory config
    alert = watcher.check()          # returns CRITICAL alert
    watcher.restore_integrity()      # undo tampering
"""

import hashlib
import json
import logging
import os
import random
import time
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger("firmware_watcher")

# ---------------------------------------------------------------------------
# Default factory config (written to disk on first run)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG: Dict[str, Any] = {
    "version": "2.1.4",
    "firmware_hash_baseline": "",   # filled in on first save
    "registers": {
        "40001": {
            "min": 0,
            "max": 100,
            "unit": "percent",
            "description": "Pump speed",
            "writable": False,
        },
        "40002": {
            "min": 0,
            "max": 100,
            "unit": "percent",
            "description": "Valve position",
            "writable": True,
        },
        "40003": {
            "min": 0,
            "max": 150,
            "unit": "celsius_x10",
            "description": "Temperature",
            "writable": False,
        },
        "40004": {
            "min": 0,
            "max": 10,
            "unit": "bar_x10",
            "description": "Pressure",
            "writable": False,
        },
        "40005": {
            "min": 0,
            "max": 100,
            "unit": "percent",
            "description": "Flow rate",
            "writable": True,
        },
        "40006": {
            "min": 0,
            "max": 10,
            "unit": "count",
            "description": "Alarm status (SAFETY CRITICAL)",
            "writable": False,
            "safety_critical": True,
        },
    },
    "allowed_ips": ["10.0.1.1", "10.0.1.2", "10.0.2.1"],
    "maintenance_windows": [
        {"day": "Sunday", "start": "02:00", "end": "04:00"},
        {"day": "Wednesday", "start": "03:00", "end": "04:00"},
    ],
}


def _compute_hash(config: Dict) -> str:
    """Return a reproducible SHA-256 hex digest of *config*.

    Keys are sorted recursively so insertion order does not matter.
    """
    canonical: str = json.dumps(config, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class FirmwareWatcher:
    """Monitor the integrity of a PLC firmware/configuration blob.

    On construction the watcher either loads an existing config from
    *config_path* or writes a default one.  A SHA-256 baseline hash is
    computed and stored.  Subsequent calls to :meth:`check` re-hash the
    in-memory configuration and compare it against the baseline.

    Args:
        config_path: Path to the JSON firmware configuration file.
    """

    # Log file written alongside the config (relative to CWD or absolute)
    _HASH_CHAIN_LOG = "hash_chain.log"
    _MAX_CHAIN_ENTRIES_DISPLAYED = 20

    def __init__(self, config_path: str = "plc_firmware.json") -> None:
        self._config_path: str = config_path
        self._check_count: int = 0
        self._last_check_time: Optional[str] = None

        # Load or create configuration
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as fh:
                self._current_config: Dict = json.load(fh)
            logger.info("FirmwareWatcher: loaded config from %s", config_path)
        else:
            self._current_config = dict(_DEFAULT_CONFIG)
            self._save_config()
            logger.info("FirmwareWatcher: created default config at %s", config_path)

        # Establish the baseline hash
        self._baseline_hash: str = _compute_hash(self._current_config)
        self._append_chain_entry(self._baseline_hash, status="baseline")
        logger.info("FirmwareWatcher: baseline hash = %s", self._baseline_hash)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _save_config(self) -> None:
        """Persist the current in-memory config to disk."""
        with open(self._config_path, "w", encoding="utf-8") as fh:
            json.dump(self._current_config, fh, indent=2, sort_keys=True)

    def _append_chain_entry(self, current_hash: str, status: str) -> None:
        """Append a single entry to the hash-chain log."""
        entry: Dict = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "hash": current_hash,
            "status": status,
        }
        with open(self._HASH_CHAIN_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def _find_changed_fields(self, actual_config: Dict) -> List[str]:
        """Return a list of top-level and nested keys that differ from baseline."""
        changed: List[str] = []

        # Compare top-level keys
        all_keys = set(self._current_config) | set(actual_config)
        for key in sorted(all_keys):
            baseline_val = self._current_config.get(key)
            actual_val = actual_config.get(key)
            if baseline_val != actual_val:
                changed.append(key)

        return changed

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self) -> Optional[Dict]:
        """Re-hash the in-memory config and compare to the baseline.

        Returns:
            *None* if integrity is intact.  Otherwise a CRITICAL alert dict
            with the following structure::

                {
                    "alert_type":       "firmware_tampering",
                    "severity":         "critical",
                    "message":          "PLC firmware/config tampered: hash mismatch",
                    "timestamp":        "<ISO-8601>",
                    "analysis_details": {
                        "expected_hash":  "<hex>",
                        "actual_hash":    "<hex>",
                        "changed_fields": ["<field>", ...]
                    },
                    "mitre_id":         "T0839",
                    "mitre_name":       "Modify Program",
                    "mitre_tactic":     "Persistence",
                }
        """
        self._check_count += 1
        self._last_check_time = datetime.utcnow().isoformat() + "Z"

        actual_hash = _compute_hash(self._current_config)

        if actual_hash == self._baseline_hash:
            self._append_chain_entry(actual_hash, status="ok")
            logger.debug("FirmwareWatcher: integrity OK (check #%d)", self._check_count)
            return None

        # Hash mismatch — build CRITICAL alert
        changed_fields = self._find_changed_fields(self._current_config)
        self._append_chain_entry(actual_hash, status="TAMPERED")

        logger.critical(
            "FIRMWARE TAMPERING DETECTED!  expected=%s  actual=%s  fields=%s",
            self._baseline_hash,
            actual_hash,
            changed_fields,
        )

        alert: Dict = {
            "alert_type": "firmware_tampering",
            "severity": "critical",
            "message": "PLC firmware/config tampered: hash mismatch",
            "timestamp": self._last_check_time,
            "alert_id": f"fw_{int(time.time())}_{self._check_count}",
            "analysis_details": {
                "expected_hash": self._baseline_hash,
                "actual_hash": actual_hash,
                "changed_fields": changed_fields,
            },
            "mitre_id": "T0839",
            "mitre_name": "Modify Program",
            "mitre_tactic": "Persistence",
            "packet_details": {},
            "is_read": False,
        }
        return alert

    def get_hash_chain(self) -> List[Dict]:
        """Return the last *N* entries from the hash-chain log.

        Returns:
            List of up to :attr:`_MAX_CHAIN_ENTRIES_DISPLAYED` log entry dicts
            in reverse-chronological order (most recent first).
        """
        if not os.path.exists(self._HASH_CHAIN_LOG):
            return []

        entries: List[Dict] = []
        with open(self._HASH_CHAIN_LOG, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        # Most recent first, capped
        return list(reversed(entries[-self._MAX_CHAIN_ENTRIES_DISPLAYED :]))

    def tamper_for_demo(self, field: Optional[str] = None) -> None:
        """Simulate in-memory tampering for demonstration purposes.

        Modifies *self._current_config* in memory only — the on-disk file is
        left untouched so the next :meth:`check` call will detect a hash
        mismatch.

        Args:
            field: Name of a top-level config key to mutate.  If *None* a
                   random field is chosen automatically.
        """
        tamperable_fields = ["version", "allowed_ips", "maintenance_windows"]

        if field is None:
            field = random.choice(tamperable_fields)

        original_value = self._current_config.get(field)

        if field == "version":
            # Bump minor version unexpectedly
            parts = str(original_value).split(".")
            parts[-1] = str(int(parts[-1]) + 99)
            self._current_config[field] = ".".join(parts)
        elif field == "allowed_ips":
            # Inject a rogue IP
            rogue_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
            self._current_config[field] = list(original_value) + [rogue_ip]
        elif field == "maintenance_windows":
            # Add a suspicious off-hours window
            self._current_config[field] = list(original_value) + [
                {"day": "Monday", "start": "23:00", "end": "23:59"}
            ]
        else:
            # Generic mutation
            self._current_config[field] = f"__TAMPERED__{original_value}"

        logger.warning(
            "tamper_for_demo: mutated field '%s'  was=%r  now=%r",
            field,
            original_value,
            self._current_config[field],
        )

    def restore_integrity(self) -> None:
        """Reload the on-disk config to undo any in-memory tampering."""
        with open(self._config_path, "r", encoding="utf-8") as fh:
            self._current_config = json.load(fh)
        logger.info("FirmwareWatcher: in-memory config restored from disk")

    def get_status(self) -> Dict:
        """Return a status summary suitable for the TUI dashboard.

        Returns:
            ::

                {
                    "is_healthy":   True,
                    "last_check":   "<ISO-8601>",
                    "hash":         "<hex>",
                    "check_count":  42,
                }
        """
        current_hash = _compute_hash(self._current_config)
        is_healthy = current_hash == self._baseline_hash
        return {
            "is_healthy": is_healthy,
            "last_check": self._last_check_time or "never",
            "hash": current_hash,
            "baseline_hash": self._baseline_hash,
            "check_count": self._check_count,
            "config_path": self._config_path,
        }
