#!/usr/bin/env python3
"""
Protocol Parsers for OT/ICS Protocols

Provides parser classes for DNP3 and S7comm protocols to detect unauthorized control
commands such as DNP3 restarts and S7comm CPU stops.
"""

from __future__ import annotations
import logging
from typing import Any, Dict, Optional

# Setup module-level logger
logger = logging.getLogger("protocol_parsers")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(
        logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")
    )
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


class DNP3Parser:
    """Parser for the DNP3 (Distributed Network Protocol 3) industrial protocol."""

    def __init__(self) -> None:
        """Initialize the DNP3Parser."""
        logger.info("DNP3Parser initialized.")

    def parse(self, payload: bytes) -> Optional[Dict[str, Any]]:
        """Parse DNP3 payload to extract address header and application function codes.

        Detects unauthorized control commands (e.g., cold/warm restarts) and raises alerts.

        Args:
            payload: Raw bytes of the captured network packet payload.

        Returns:
            An alert dict if unauthorized control is detected,
            a standard packet dict if parse succeeds,
            or None if payload is not a valid DNP3 packet.
        """
        if len(payload) < 11:
            return None

        # DNP3 packets must start with 0x05 0x64
        if payload[0] != 0x05 or payload[1] != 0x64:
            return None

        # Parse basic fields
        # Length: Byte 2
        # Control: Byte 3
        length = payload[2]
        control = payload[3]

        # Destination Address: Bytes 4-5 (Little-endian)
        dst = payload[4] | (payload[5] << 8)

        # Source Address: Bytes 6-7 (Little-endian)
        src = payload[6] | (payload[7] << 8)

        # Application Layer Function Code: Byte 10
        fc = payload[10]

        # Function Codes: 13 (Cold Restart), 14 (Warm Restart)
        if fc in (13, 14):
            logger.warning(
                "DNP3 Restart command (FC %d) sent from source %d to destination %d",
                fc, src, dst
            )
            return {
                "alert_type": "unauthorized_dnp3_control",
                "severity": "critical",
                "message": f"DNP3 Restart command (FC {fc}) sent from source {src} to destination {dst}",
                "mitre_id": "T0806",
                "mitre_name": "Reimport Control System Devices"
            }

        return {
            "protocol": "DNP3",
            "source": src,
            "destination": dst,
            "function_code": fc
        }


class S7CommParser:
    """Parser for the Siemens S7comm industrial Ethernet protocol."""

    def __init__(self) -> None:
        """Initialize the S7CommParser."""
        logger.info("S7CommParser initialized.")

    def parse(self, payload: bytes) -> Optional[Dict[str, Any]]:
        """Parse S7comm payload to extract ROSCTR and Function Codes.

        Detects critical control commands (e.g., CPU STOP command) and raises alerts.

        Args:
            payload: Raw bytes of the captured network packet payload.

        Returns:
            An alert dict if unauthorized control is detected,
            a standard packet dict if parse succeeds,
            or None if payload is not a valid S7comm packet.
        """
        if len(payload) < 11:
            return None

        # S7comm starts with a TPKT header (usually 0x03 0x00 in the first 2 bytes)
        if payload[0] != 0x03 or payload[1] != 0x00:
            return None

        # Locate the S7 Header magic 0x32
        s7_idx = -1
        if payload[7] == 0x32:
            s7_idx = 7
        else:
            # Fallback search for S7 magic in initial bytes
            for i in range(2, min(15, len(payload))):
                if payload[i] == 0x32:
                    s7_idx = i
                    break

        if s7_idx == -1:
            return None

        # ROSCTR is at s7_idx + 1
        rosctr = payload[s7_idx + 1]

        # Determine S7 Header length to find start of Parameter section
        # 1=Job (10 bytes header), 2=Ack (12 bytes header), 3=Ack_Data (12 bytes header)
        if rosctr in (2, 3):
            header_len = 12
        else:
            header_len = 10

        fc_idx = s7_idx + header_len
        if len(payload) <= fc_idx:
            return None

        # Function Code is the first byte of the parameter section
        fc = payload[fc_idx]

        # S7 control Function Code 0x2d is PLC Stop
        if fc == 0x2d:
            logger.warning("S7comm STOP command (ROSCTR Job FC 0x2D) issued to Siemens PLC")
            return {
                "alert_type": "unauthorized_s7_control",
                "severity": "critical",
                "message": "S7comm STOP command (ROSCTR Job FC 0x2D) issued to Siemens PLC",
                "mitre_id": "T0814",
                "mitre_name": "Denial of Control"
            }

        return {
            "protocol": "S7COMM",
            "rosctr": rosctr,
            "function_code": fc
        }
