#!/usr/bin/env python3
"""
Deep Packet Inspection (DPI) Validator for Modbus TCP.

This module provides the DPIValidator class, which validates raw Modbus TCP frame
structures and MBAP headers to detect protocol-level anomalies and malformed payloads.
"""

import logging
import struct

logger = logging.getLogger("dpi_validator")


class DPIValidator:
    """DPI Engine for Modbus TCP structural validation."""

    def __init__(self) -> None:
        """Initialize the DPIValidator."""
        self.logger = logging.getLogger("dpi_validator")
        # Allowed standard Modbus function codes
        self.allowed_function_codes = {
            0x01,  # Read Coils
            0x02,  # Read Discrete Inputs
            0x03,  # Read Holding Registers
            0x04,  # Read Input Registers
            0x05,  # Write Single Coil
            0x06,  # Write Single Register
            0x08,  # Diagnostics
            0x0F,  # Write Multiple Coils
            0x10,  # Write Multiple Registers
            0x11,  # Report Slave ID
            0x16,  # Mask Write Register
            0x17,  # Read/Write Multiple Registers
            0x2B,  # Encapsulated Interface Transport (Device ID)
        }

    def validate_modbus_frame(self, frame: bytes) -> bool:
        """
        Validate a raw Modbus TCP ADU.

        Checks:
        1. Minimum length requirement (7 bytes MBAP + 1 byte PDU).
        2. Protocol identifier field (must be 0x0000).
        3. Header length consistency (matches actual remaining frame length).
        4. Valid function code range.

        Args:
            frame: The raw byte sequence of the Modbus TCP packet.

        Returns:
            True if the packet passes all DPI checks, False otherwise.
        """
        if len(frame) < 8:
            self.logger.warning(f"DPI Failure: Frame too short ({len(frame)} bytes)")
            return False

        try:
            # Unpack MBAP header:
            # Transaction ID (2B), Protocol ID (2B), Length (2B), Unit ID (1B)
            trans_id, proto_id, length, unit_id = struct.unpack("!HHHB", frame[:7])

            # Protocol ID must be 0 for Modbus
            if proto_id != 0:
                self.logger.warning(f"DPI Failure: Invalid Protocol ID {proto_id}")
                return False

            # Length field specifies the remaining bytes starting from Unit ID (byte 6)
            # So actual frame length must be 6 + length
            expected_len = 6 + length
            if len(frame) != expected_len:
                self.logger.warning(
                    f"DPI Failure: Header length {expected_len} does not match actual length {len(frame)}"
                )
                return False

            # Check function code
            func_code = frame[7]
            # Strip exception bit if present (0x80)
            base_func_code = func_code & 0x7F

            if base_func_code not in self.allowed_function_codes:
                self.logger.warning(f"DPI Failure: Unauthorized/Invalid Function Code 0x{func_code:02X}")
                return False

            return True

        except Exception as e:
            self.logger.error(f"DPI Engine Exception during validation: {e}")
            return False
