#!/usr/bin/env python3
"""
Passive OS Fingerprinting Module.

This module provides the OSFingerprinter class, which guesses the Operating System
of a network host by analyzing IP/TCP header fields such as TTL (Time to Live),
TCP Window Size, and the Don't Fragment (DF) flag from SYN packets.
"""

import logging

logger = logging.getLogger("os_fingerprint")


class OSFingerprinter:
    """Passive OS fingerprinter utilizing TCP/IP header parameters."""

    def __init__(self) -> None:
        """Initialize the OSFingerprinter."""
        self.logger = logging.getLogger("os_fingerprint")
        # Define OS signature heuristics: (TTL, Window Size, DF) -> OS name
        # TTL is checked using a range to account for router hops (TTL decrement).
        self.signatures = [
            {"os": "Linux", "max_ttl": 64, "window": 29200, "df": True},
            {"os": "Linux", "max_ttl": 64, "window": 5840, "df": True},
            {"os": "Windows", "max_ttl": 128, "window": 8192, "df": True},
            {"os": "Windows", "max_ttl": 128, "window": 64240, "df": True},
            {"os": "VxWorks", "max_ttl": 64, "window": 8192, "df": False},
            {"os": "VxWorks", "max_ttl": 64, "window": 16384, "df": False},
            {"os": "Cisco IOS", "max_ttl": 255, "window": 4128, "df": True},
        ]

    def fingerprint(self, ttl: int, window_size: int, df: bool = True) -> str:
        """
        Passive fingerprinter for remote hosts based on TCP SYN parameters.

        Args:
            ttl: Observed IP Time to Live value.
            window_size: Observed TCP Window Size.
            df: Observed Don't Fragment flag status.

        Returns:
            The matched OS name string (e.g. 'Linux', 'Windows', 'VxWorks',
            'Cisco IOS') or 'Embedded/RTOS' if within common industrial device
            ranges, or 'Unknown'.
        """
        self.logger.debug(f"Fingerprinting host: TTL={ttl}, Win={window_size}, DF={df}")

        # Find closest match
        for sig in self.signatures:
            # TTL starts at 64, 128, or 255 and decreases by 1 for each hop.
            # So if ttl is close to but less than max_ttl, it's a match.
            ttl_diff = sig["max_ttl"] - ttl
            if 0 <= ttl_diff <= 16:  # up to 16 hops away
                # Match window and DF
                if window_size == sig["window"] and df == sig["df"]:
                    return sig["os"]

        # General industrial/embedded heuristic fallbacks
        if 0 < ttl <= 64:
            if not df:
                return "VxWorks"
            return "Linux"
        elif 64 < ttl <= 128:
            return "Windows"
        elif 128 < ttl <= 255:
            return "Cisco IOS"

        if window_size in (1024, 2048, 4096, 8192, 16384):
            return "Embedded/RTOS"

        return "Unknown"
