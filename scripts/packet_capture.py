#!/usr/bin/env python3
"""
Real-time OT/ICS Packet Capture System.

This module provides the PacketCapture class, which sniffs networks for Modbus
(502), S7comm (102), and DNP3 (20000) traffic. It leverages Scapy if available,
cascades to standard library raw sockets, and falls back to tailing/polling
local OT log files (hmi_traffic.log and plc_traffic.log) if administrative
privileges are unavailable.
"""

import json
import logging
import os
import re
import socket
import struct
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("packet_capture")

# Check if Scapy is available
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketCapture:
    """Network sniffer and traffic log simulator for OT/ICS environments."""

    def __init__(self, rule_engine: Any) -> None:
        """
        Initialize the PacketCapture system.

        Args:
            rule_engine: The rule engine instance used to process captured packets.
        """
        self.logger = logging.getLogger("packet_capture")
        self.rule_engine = rule_engine
        self._is_running = False
        self._polling_running = False
        self._sniffer_thread: Optional[threading.Thread] = None
        self._polling_thread: Optional[threading.Thread] = None

    def start(self, interface: Optional[str] = None) -> None:
        """
        Start the packet capture system.

        This method spins up a background thread that attempts to initialize
        either the Scapy-based sniffer or the raw socket sniffer. If both fail due
        to insufficient administrative privileges, the system cascades to log file
        polling fallback.

        Args:
            interface: The interface name to bind to (e.g. "eth0" or "lo").
        """
        if self._is_running:
            self.logger.warning("Packet capture is already running.")
            return

        self._is_running = True
        self._sniffer_thread = threading.Thread(
            target=self._initiate_sniffer, args=(interface,), daemon=True
        )
        self._sniffer_thread.start()
        self.logger.info("Packet capture background thread started.")

    def stop(self) -> None:
        """Stop all network sniffing and fallback log polling threads."""
        self.logger.info("Stopping packet capture system...")
        self._is_running = False
        self._polling_running = False

        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=2.0)

        if self._polling_thread and self._polling_thread.is_alive():
            self._polling_thread.join(timeout=2.0)

        self.logger.info("Packet capture system stopped.")

    def _initiate_sniffer(self, interface: Optional[str] = None) -> None:
        """Run the appropriate sniffer or trigger log file polling fallback."""
        if SCAPY_AVAILABLE:
            self._run_scapy_sniffer(interface)
        else:
            self._run_raw_socket_sniffer(interface)

    def _run_scapy_sniffer(self, interface: Optional[str] = None) -> None:
        """Run the Scapy sniffer loop."""
        self.logger.info("Attempting Scapy-based network sniffing.")
        try:
            def scapy_callback(pkt: Any) -> None:
                if not self._is_running:
                    return
                try:
                    if not pkt.haslayer("IP") or not pkt.haslayer("TCP"):
                        return

                    ip_layer = pkt["IP"]
                    tcp_layer = pkt["TCP"]

                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    payload = bytes(tcp_layer.payload)

                    self._process_payload(src_ip, dst_ip, src_port, dst_port, payload)
                except Exception as e:
                    self.logger.debug(f"Error parsing packet inside Scapy callback: {e}")

            bpf_filter = "tcp port 502 or tcp port 102 or tcp port 20000"
            sniff_args: Dict[str, Any] = {
                "filter": bpf_filter,
                "prn": scapy_callback,
                "store": 0,
                "timeout": 1.0  # Check _is_running periodically
            }
            if interface:
                sniff_args["iface"] = interface

            self.logger.info(f"Scapy sniffer successfully initialized with filter: {bpf_filter}")
            while self._is_running:
                scapy.sniff(**sniff_args)

        except Exception as e:
            self.logger.warning(
                f"Scapy sniffing initialization failed ({e}). Cascading to raw sockets."
            )
            self._run_raw_socket_sniffer(interface)

    def _run_raw_socket_sniffer(self, interface: Optional[str] = None) -> None:
        """Run the raw TCP socket sniffer loop."""
        self.logger.info("Attempting python raw socket sniffing.")
        try:
            # Sockets of type SOCK_RAW require administrator privileges
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

            if platform_is_windows():
                local_ip = self._get_local_ip()
                s.bind((local_ip, 0))
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                if interface:
                    s.bind((interface, 0))
                else:
                    s.bind(("", 0))

            s.settimeout(1.0)
            self.logger.info("Raw socket sniffer successfully initialized.")

            while self._is_running:
                try:
                    packet_data, _ = s.recvfrom(65535)
                    self._parse_raw_packet(packet_data)
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.error(f"Error reading raw socket stream: {e}")
                    break

        except Exception as e:
            self.logger.warning(
                f"Raw socket sniffer failed initialization ({e}). Cascading to log polling fallback."
            )
            self._start_fallback_polling()

    def _parse_raw_packet(self, packet: bytes) -> None:
        """Unpack IPv4 and TCP layers from raw socket packet data."""
        try:
            if len(packet) < 20:
                return

            iph = struct.unpack("!BBHHHBBH4s4s", packet[:20])
            version_ihl = iph[0]
            version = version_ihl >> 4
            if version != 4:
                return  # Limit parsing to IPv4

            ihl = version_ihl & 0x0F
            iph_length = ihl * 4

            if len(packet) < iph_length + 20:
                return

            protocol = iph[6]
            if protocol != 6:  # TCP is 6
                return

            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])

            tcp_header = packet[iph_length:iph_length + 20]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            src_port = tcph[0]
            dst_port = tcph[1]

            tcp_header_len = (tcph[4] >> 4) * 4
            payload_offset = iph_length + tcp_header_len

            monitored_ports = (502, 102, 20000)
            if src_port not in monitored_ports and dst_port not in monitored_ports:
                return

            payload = packet[payload_offset:]
            self._process_payload(src_ip, dst_ip, src_port, dst_port, payload)

        except Exception as e:
            self.logger.debug(f"Error parsing raw socket packet: {e}")

    def _process_payload(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes
    ) -> None:
        """Extract protocol identity and forward packet details to the rule engine."""
        protocol = "MODBUS"
        if src_port == 102 or dst_port == 102:
            protocol = "S7COMM"
        elif src_port == 20000 or dst_port == 20000:
            protocol = "DNP3"

        packet_dict: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "operation": "read",
            "function_code": "",
            "register": None,
            "value": None,
            "direction": "inbound" if dst_port in (502, 102, 20000) else "outbound",
            "protocol": protocol
        }

        # Protocol-specific payload decoding
        if protocol == "MODBUS" and len(payload) >= 8:
            try:
                # Modbus/TCP: MBAP header (7 bytes) + PDU Function Code (1 byte)
                _, _, _, _ = struct.unpack("!HHHB", payload[:7])
                func_code = payload[7]
                packet_dict["function_code"] = f"0x{func_code:02x}"

                if func_code in (0x06, 0x10):
                    packet_dict["operation"] = "write"

                if func_code in (0x03, 0x06) and len(payload) >= 12:
                    reg_addr, val = struct.unpack("!HH", payload[8:12])
                    packet_dict["register"] = reg_addr
                    if func_code == 0x06:
                        packet_dict["value"] = val
                elif func_code == 0x10 and len(payload) >= 14:
                    reg_addr, _ = struct.unpack("!HH", payload[8:12])
                    packet_dict["register"] = reg_addr
                    byte_count = payload[12]
                    if byte_count >= 2 and len(payload) >= 15:
                        val = struct.unpack("!H", payload[13:15])[0]
                        packet_dict["value"] = val
            except Exception as e:
                self.logger.debug(f"Failed to unpack Modbus payload bytes: {e}")

        elif protocol == "S7COMM":
            parsed = self._parse_s7comm(payload)
            if parsed:
                op, func, reg, val = parsed
                if op:
                    packet_dict["operation"] = op
                if func:
                    packet_dict["function_code"] = func
                if reg is not None:
                    packet_dict["register"] = reg
                if val is not None:
                    packet_dict["value"] = val

        elif protocol == "DNP3":
            parsed = self._parse_dnp3(payload)
            if parsed:
                op, func, reg, val = parsed
                if op:
                    packet_dict["operation"] = op
                if func:
                    packet_dict["function_code"] = func
                if reg is not None:
                    packet_dict["register"] = reg
                if val is not None:
                    packet_dict["value"] = val

        try:
            self.rule_engine.process_packet(packet_dict)
        except Exception as e:
            self.logger.error(f"Rule engine failed processing packet: {e}")

    def _parse_s7comm(self, payload: bytes) -> Optional[tuple]:
        """
        Partially decode S7comm protocol.

        Extracts operation, function code, and DB/offset register addresses.
        """
        try:
            if len(payload) < 8:
                return None

            # TPKT header (4 bytes): Version (0x03), Reserved (0x00), Length (2 bytes)
            if payload[0] != 0x03:
                return None

            # COTP header: starts at byte 4
            # Byte 4 is length of COTP header
            cotp_len = payload[4]
            s7_offset = 5 + cotp_len

            if len(payload) < s7_offset + 10:
                return None

            # S7comm: Protocol ID (always 0x32)
            if payload[s7_offset] != 0x32:
                return None

            rosctr = payload[s7_offset + 1]
            param_len = struct.unpack("!H", payload[s7_offset + 6:s7_offset + 8])[0]

            param_offset = s7_offset + 10
            if len(payload) < param_offset + param_len:
                return None

            if param_len > 0:
                s7_func = payload[param_offset]
                func_str = f"0x{s7_func:02x}"

                # S7 Function Codes: 0x04 Read Var, 0x05 Write Var
                operation = "read"
                if s7_func == 0x05:
                    operation = "write"

                register = None
                if s7_func in (0x04, 0x05) and param_len >= 12:
                    # Item description starts at param_offset + 2
                    item_offset = param_offset + 2
                    if len(payload) >= item_offset + 12:
                        syntax_id = payload[item_offset + 2]
                        if syntax_id == 0x10:
                            db_num = struct.unpack("!H", payload[item_offset + 6:item_offset + 8])[0]
                            # Address is 3 bytes (in bits) starting at item_offset + 9
                            addr_bytes = payload[item_offset + 9:item_offset + 12]
                            addr_bits = (addr_bytes[0] << 16) | (addr_bytes[1] << 8) | addr_bytes[2]
                            addr_byte = addr_bits // 8  # Convert bit address to byte address

                            if db_num > 0:
                                register = db_num * 10000 + addr_byte
                            else:
                                register = addr_byte

                return operation, func_str, register, None
        except Exception as e:
            self.logger.debug(f"Failed parsing S7comm payload: {e}")
        return None

    def _parse_dnp3(self, payload: bytes) -> Optional[tuple]:
        """
        Partially decode DNP3 protocol.

        Extracts operation, DNP3 function code, and Point index.
        """
        try:
            if len(payload) < 12:
                return None

            # DNP3 start bytes (0x05 0x64)
            if payload[0] != 0x05 or payload[1] != 0x64:
                return None

            # Header CRC is at bytes 8-9, payload starts at byte 10
            # Transport Header is 1 byte at byte 10
            # App Layer PDU starts at byte 11
            # App Control (Byte 11), Function Code (Byte 12)
            dnp3_func = payload[12]
            func_str = f"0x{dnp3_func:02x}"

            # DNP3 Function Codes: 0x01 Read, 0x02 Write, 0x03 Select, 0x04 Operate, 0x05 DirectOperate
            operation = "read"
            if dnp3_func in (0x02, 0x03, 0x04, 0x05, 0x06):
                operation = "write"

            register = None
            # Object header starts at Byte 13: Group (13), Var (14), Qualifier (15)
            if len(payload) >= 18:
                qualifier = payload[15]
                if qualifier == 0x00 and len(payload) >= 18:  # 1-byte index
                    register = payload[16]
                elif qualifier == 0x01 and len(payload) >= 20:  # 2-byte index
                    register = struct.unpack("<H", payload[16:18])[0]

            return operation, func_str, register, None
        except Exception as e:
            self.logger.debug(f"Failed parsing DNP3 payload: {e}")
        return None

    def _start_fallback_polling(self) -> None:
        """Start polling OT traffic logs as sniffing fallback."""
        self.logger.info("Initializing fallback log file polling...")
        self._polling_running = True
        self._polling_thread = threading.Thread(
            target=self._poll_logs_loop, daemon=True
        )
        self._polling_thread.start()

    def _poll_logs_loop(self) -> None:
        """Loop to poll active OT/ICS transaction logs and feed rule engine."""
        hmi_path = "hmi_traffic.log"
        plc_path = "plc_traffic.log"

        hmi_offset = 0
        plc_offset = 0

        # Seek to end of logs to process entries generated in real time
        if os.path.exists(hmi_path):
            hmi_offset = os.path.getsize(hmi_path)
        if os.path.exists(plc_path):
            plc_offset = os.path.getsize(plc_path)

        self.logger.info(f"Polling active logs. HMI offset: {hmi_offset}, PLC offset: {plc_offset}")

        while self._is_running and self._polling_running:
            # Poll Legitimate HMI client traffic log
            if os.path.exists(hmi_path):
                try:
                    with open(hmi_path, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(hmi_offset)
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                packet = {
                                    "timestamp": entry.get("timestamp", datetime.now().isoformat()),
                                    "source_ip": "10.0.1.1",  # Whitelisted HMI IP
                                    "dest_ip": "10.0.1.2",    # PLC IP
                                    "operation": entry.get("operation", "read"),
                                    "function_code": entry.get("function_code", ""),
                                    "register": entry.get("register"),
                                    "value": entry.get("value"),
                                    "direction": "inbound",
                                    "protocol": "MODBUS"
                                }
                                self.rule_engine.process_packet(packet)
                            except Exception as e:
                                self.logger.debug(f"Error parsing HMI log entry: {e}")
                        hmi_offset = f.tell()
                except Exception as e:
                    self.logger.error(f"Error reading HMI log: {e}")

            # Poll Simulated PLC transaction log
            if os.path.exists(plc_path):
                try:
                    with open(plc_path, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(plc_offset)
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)

                                client_ip = entry.get("client_ip", "unknown")
                                if "'" in client_ip:
                                    match = re.search(r"'(.*?)'", client_ip)
                                    if match:
                                        client_ip = match.group(1)

                                val = None
                                values = entry.get("values")
                                if isinstance(values, list) and len(values) > 0:
                                    val = values[0]
                                elif isinstance(values, (int, float)):
                                    val = values

                                packet = {
                                    "timestamp": entry.get("timestamp", datetime.now().isoformat()),
                                    "source_ip": client_ip,
                                    "dest_ip": "10.0.1.2",
                                    "operation": "write" if entry.get("write") else "read",
                                    "function_code": entry.get("function_code", ""),
                                    "register": entry.get("start_register"),
                                    "value": val,
                                    "direction": "inbound",
                                    "protocol": "MODBUS"
                                }
                                self.rule_engine.process_packet(packet)
                            except Exception as e:
                                self.logger.debug(f"Error parsing PLC log entry: {e}")
                        plc_offset = f.tell()
                except Exception as e:
                    self.logger.error(f"Error reading PLC log: {e}")

            time.sleep(0.5)

    def _get_local_ip(self) -> str:
        """Retrieve local IP address for socket binding."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"


def platform_is_windows() -> bool:
    """Helper to detect Windows platform."""
    import platform
    return platform.system() == "Windows"
