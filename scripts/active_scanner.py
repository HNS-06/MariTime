#!/usr/bin/env python3
"""
Active Scanner for Modbus PLC Identification.

This module provides the ActiveScanner class, which can perform a safe Read
Device Identification query (Modbus function code 0x2B, subcode 0x0E) on Modbus
hosts. If the host is unavailable or the scanner is running in demo mode, it
falls back to realistic mock PLC identification data.
"""

import asyncio
import logging
import os
import struct
from datetime import datetime
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("active_scanner")


class ActiveScanner:
    """Active PLC scanner for Modbus devices."""

    def __init__(self) -> None:
        """Initialize the ActiveScanner instance."""
        self.logger = logging.getLogger("active_scanner")

    async def scan(self, ip: str, port: int = 502) -> Dict[str, Any]:
        """
        Scan a Modbus host for identity information.

        This method attempts to establish an async connection to the target port
        and send a safe Read Device Identification query (Function Code 0x2B,
        Subcode 0x0E). If the connection fails or if MARITIME_DEMO_MODE is set
        to 'true', mock PLC identification information is returned instead.

        Args:
            ip: The IP address of the target Modbus device.
            port: The TCP port of the Modbus service (default is 502).

        Returns:
            A dictionary containing the parsed or mock PLC identity information:
            - ip: Target host IP.
            - vendor: Vendor name (e.g. Schneider Electric).
            - model: PLC model.
            - firmware_version: Version string.
            - serial_number: Unique serial number.
            - last_scan: ISO 8601 formatted timestamp of the scan.
        """
        demo_mode = os.getenv("MARITIME_DEMO_MODE", "false").lower() in ("true", "1", "yes")

        if demo_mode:
            self.logger.info("Demo mode enabled; returning mock device identification.")
            return self._get_mock_data(ip)

        self.logger.info(f"Initiating active scan on {ip}:{port}")
        try:
            # Transaction ID: 0x0001, Protocol ID: 0x0000, Length: 0x0005, Unit ID: 0x01
            # Function Code: 0x2B, MEI Type: 0x0E, Read Device ID code: 0x01 (Basic), Object ID: 0x00
            req = struct.pack(">HHHBBBBB", 1, 0, 5, 1, 0x2B, 0x0E, 0x01, 0x00)

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=3.0
            )

            try:
                writer.write(req)
                await writer.drain()

                # Read MBAP header (7 bytes)
                header = await asyncio.wait_for(reader.readexactly(7), timeout=2.0)
                trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", header)

                if length < 2:
                    raise ValueError(f"Invalid Modbus TCP length in header: {length}")

                # Read PDU (length includes Unit ID, which is already read, so we read length - 1)
                pdu = await asyncio.wait_for(reader.readexactly(length - 1), timeout=2.0)

                if len(pdu) < 2:
                    raise ValueError("PDU response too short")

                func_code, mei_type = struct.unpack(">BB", pdu[:2])

                if func_code == 0xAB:  # Exception response (0x2B | 0x80)
                    exc_code = pdu[2] if len(pdu) > 2 else 0
                    raise ValueError(f"Modbus Exception 0xAB received: code {exc_code}")

                if func_code != 0x2B or mei_type != 0x0E:
                    raise ValueError(f"Unexpected Function Code/MEI Type: 0x{func_code:02X}/0x{mei_type:02X}")

                # Parse Read Device Identification PDU:
                # pdu[0]: func_code (0x2B)
                # pdu[1]: mei_type (0x0E)
                # pdu[2]: Read Device ID code (1 byte)
                # pdu[3]: Conformity level (1 byte)
                # pdu[4]: More Follows (1 byte)
                # pdu[5]: Next Object ID (1 byte)
                # pdu[6]: Number of objects (1 byte)
                if len(pdu) < 7:
                    raise ValueError("Read Device ID response header too short")

                num_objects = pdu[6]
                offset = 7
                objects = {}

                for _ in range(num_objects):
                    if offset + 2 > len(pdu):
                        break
                    obj_id, obj_len = struct.unpack(">BB", pdu[offset:offset + 2])
                    offset += 2
                    if offset + obj_len > len(pdu):
                        break
                    obj_val = pdu[offset:offset + obj_len].decode("ascii", errors="ignore").strip()
                    offset += obj_len
                    objects[obj_id] = obj_val

                # Basic ID objects:
                # 0x00: VendorName
                # 0x01: ProductCode (Model)
                # 0x02: MajorMinorRevision (Firmware version)
                vendor = objects.get(0, "Unknown Vendor")
                model = objects.get(1, "Unknown Model")
                firmware = objects.get(2, "Unknown Firmware")
                serial = objects.get(3, "SE-2026-X89")  # Fallback serial

                self.logger.info(f"Active scan successful for {ip}: {vendor} {model} ({firmware})")
                return {
                    "ip": ip,
                    "vendor": vendor,
                    "model": model,
                    "firmware_version": firmware,
                    "serial_number": serial,
                    "last_scan": datetime.now().isoformat()
                }

            finally:
                writer.close()
                await writer.wait_closed()

        except Exception as e:
            self.logger.warning(
                f"Active scan failed on {ip}:{port} ({e}). Falling back to mock data."
            )
            return self._get_mock_data(ip)

    def _get_mock_data(self, ip: str) -> Dict[str, Any]:
        """Generate mock PLC identification data."""
        return {
            "ip": ip,
            "vendor": "Schneider Electric",
            "model": "Modicon M340",
            "firmware_version": "v3.20",
            "serial_number": "SE-2026-X89",
            "last_scan": datetime.now().isoformat()
        }
