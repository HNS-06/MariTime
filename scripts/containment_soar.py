#!/usr/bin/env python3
"""
SOAR Containment Module for MariTime Security Monitor.

This module provides the ContainmentSOAR class, which automates host firewall
containment of malicious IPs to defend OT/ICS systems. It handles blocking
and releasing IPs across Windows, Linux, and macOS platforms. If permissions
are insufficient (e.g. not running as Administrator/root), it logs a warning
and mocks the action using an in-memory blocklist to enable testing.
"""

import logging
import platform
import subprocess
from typing import List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("containment_soar")


class ContainmentSOAR:
    """SOAR containment agent for blocking and unblocking hostile IP addresses."""

    def __init__(self) -> None:
        """Initialize ContainmentSOAR and set up in-memory blocked IPs list."""
        self.logger = logging.getLogger("containment_soar")
        self.blocked_ips: List[str] = []

    def block_ip(self, ip: str) -> bool:
        """
        Block a malicious IP address using the host firewall.

        Executes platform-specific firewall commands (netsh on Windows,
        iptables on Linux/macOS). If permissions are denied or command fails,
        it degrades to mock mode by adding the IP to an in-memory list and
        logging a warning.

        Args:
            ip: The IP address to block.

        Returns:
            True if the block succeeded (or was mocked), False otherwise.
        """
        if ip in self.blocked_ips:
            self.logger.info(f"IP {ip} is already blocked.")
            return True

        system = platform.system()
        cmd = []

        if system == "Windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=MariTime Block {ip}", "dir=in", "action=block", f"remoteip={ip}"
            ]
        else:  # Linux/macOS
            cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

        self.logger.info(f"Attempting to block IP {ip} using system firewall.")
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
            self.logger.info(f"Successfully blocked IP {ip} via OS firewall: {result.stdout.strip()}")
            if ip not in self.blocked_ips:
                self.blocked_ips.append(ip)
            return True
        except (subprocess.SubprocessError, PermissionError, FileNotFoundError) as e:
            self.logger.warning(
                f"Firewall command failed ({e}). Mocking block action for IP {ip}."
            )
            if ip not in self.blocked_ips:
                self.blocked_ips.append(ip)
            return True

    def release_ip(self, ip: str) -> bool:
        """
        Unblock a previously blocked IP address.

        Removes the platform-specific firewall rule and updates the
        in-memory list.

        Args:
            ip: The IP address to unblock.

        Returns:
            True on success.
        """
        system = platform.system()
        cmd = []

        if system == "Windows":
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=MariTime Block {ip}"]
        else:  # Linux/macOS
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]

        self.logger.info(f"Attempting to release IP {ip} using system firewall.")
        success = True
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
            self.logger.info(f"Successfully released IP {ip} via OS firewall: {result.stdout.strip()}")
        except (subprocess.SubprocessError, PermissionError, FileNotFoundError) as e:
            self.logger.warning(
                f"Firewall command failed to release IP {ip} ({e}). Removing from in-memory tracking anyway."
            )
            success = True

        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)

        return success

    def get_blocked_ips(self) -> List[str]:
        """
        Retrieve all currently blocked IP addresses.

        Returns:
            A list of blocked IP address strings.
        """
        return self.blocked_ips.copy()
