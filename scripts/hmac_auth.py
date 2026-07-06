#!/usr/bin/env python3
"""
HMAC-SHA256 Out-of-Band Write Authorization Manager
====================================================

Legitimate Modbus writes must be pre-authorized via this manager before they
reach the PLC.  Any write that arrives without a valid, unexpired, single-use
HMAC-SHA256 token is flagged as unauthorized.

Usage::

    manager = HMACAuthManager()
    token_record = manager.generate_token(register=40002, value=75, client_id='10.0.1.1')
    ok = manager.verify_token(token_record['token'], 40002, 75, '10.0.1.1')

Integration with rule engine::

    result = manager.check_write(register=40002, value=75, source_ip='10.0.1.1')
    if not result['authorized']:
        # raise alert
"""

import hashlib
import hmac as _hmac
import json
import logging
import secrets
import time
from typing import Dict, List, Optional

logger = logging.getLogger("hmac_auth")


class HMACAuthManager:
    """HMAC-SHA256 write-authorization manager.

    Maintains an in-memory registry of pending single-use tokens.  Each token
    is bound to a specific (register, value, client_id) triple and carries a
    hard expiry timestamp.

    Tokens are *consumed* on first successful verification so they cannot be
    replayed.  Expired tokens are pruned lazily on every public method call.
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        token_ttl: float = 30.0,
    ) -> None:
        """Initialize the manager.

        Args:
            secret_key: HMAC secret.  If *None* a cryptographically random
                        64-byte hex string is generated and logged (for
                        development / demo use only).
            token_ttl:  Token lifetime in seconds (default 30 s).
        """
        if secret_key is None:
            secret_key = secrets.token_hex(64)
            logger.warning(
                "HMACAuthManager: no secret_key supplied — generated ephemeral key: %s",
                secret_key,
            )

        self._secret_key: bytes = secret_key.encode("utf-8")
        self._token_ttl: float = token_ttl

        # {token_hash (str) → token_record (Dict)}
        self._tokens: Dict[str, Dict] = {}

        logger.info(
            "HMACAuthManager initialised  ttl=%.1f s",
            self._token_ttl,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prune_expired(self) -> None:
        """Remove expired tokens from the in-memory registry."""
        now = time.time()
        expired_keys = [
            k for k, rec in self._tokens.items() if rec["expires_at"] < now
        ]
        for k in expired_keys:
            del self._tokens[k]
        if expired_keys:
            logger.debug("Pruned %d expired token(s)", len(expired_keys))

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """Return a stable hex digest for a raw token string (for storage key)."""
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    def _sign(self, message: str) -> str:
        """Return the HMAC-SHA256 hex digest of *message* under the secret key."""
        return _hmac.new(
            self._secret_key,
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_token(
        self,
        register: int,
        value: int,
        client_id: str,
    ) -> Dict:
        """Create and store a new authorization token.

        The token payload is::

            HMAC-SHA256(secret, f'{register}:{value}:{client_id}:{expires_at}')

        Args:
            register:  Modbus register address (e.g. 40002).
            value:     Value to be written.
            client_id: Identifier for the requesting client (usually source IP).

        Returns:
            A JSON-serialisable dict::

                {
                    "token":      "<hex_hmac>",
                    "expires_at": <unix_timestamp_float>,
                    "register":   40002,
                    "value":      75,
                    "client_id":  "10.0.1.1",
                    "created_at": <unix_timestamp_float>,
                }
        """
        self._prune_expired()

        expires_at: float = time.time() + self._token_ttl
        message: str = f"{register}:{value}:{client_id}:{expires_at}"
        token: str = self._sign(message)

        token_record: Dict = {
            "token": token,
            "expires_at": expires_at,
            "register": register,
            "value": value,
            "client_id": client_id,
            "created_at": time.time(),
        }

        storage_key = self._hash_token(token)
        self._tokens[storage_key] = token_record

        logger.info(
            "Token generated  register=%d  value=%d  client=%s  expires_at=%.3f",
            register,
            value,
            client_id,
            expires_at,
        )
        return dict(token_record)

    def verify_token(
        self,
        token: str,
        register: int,
        value: int,
        client_id: str,
    ) -> bool:
        """Verify and consume a token.

        Performs constant-time comparison to prevent timing side-channel leaks.
        A token is valid if and only if:

        * It exists in the registry.
        * It has not expired.
        * The (register, value, client_id) triple matches exactly.

        Tokens are single-use: a valid token is removed from the registry
        immediately after successful verification.

        Args:
            token:     Raw HMAC hex string (as returned by :meth:`generate_token`).
            register:  Modbus register address.
            value:     Value to be written.
            client_id: Client identifier.

        Returns:
            *True* if the token is valid and has been consumed; *False*
            otherwise.
        """
        self._prune_expired()

        storage_key = self._hash_token(token)
        record = self._tokens.get(storage_key)

        if record is None:
            logger.warning("verify_token: token not found  client=%s", client_id)
            return False

        now = time.time()
        if record["expires_at"] < now:
            logger.warning("verify_token: token expired  client=%s", client_id)
            del self._tokens[storage_key]
            return False

        # Constant-time comparison prevents timing attacks
        token_matches = _hmac.compare_digest(record["token"], token)
        register_matches = record["register"] == register
        value_matches = record["value"] == value
        client_matches = _hmac.compare_digest(record["client_id"], client_id)

        if token_matches and register_matches and value_matches and client_matches:
            # Consume the token (single-use)
            del self._tokens[storage_key]
            logger.info(
                "Token verified and consumed  register=%d  value=%d  client=%s",
                register,
                value,
                client_id,
            )
            return True

        logger.warning(
            "verify_token: field mismatch  "
            "token_ok=%s  register_ok=%s  value_ok=%s  client_ok=%s",
            token_matches,
            register_matches,
            value_matches,
            client_matches,
        )
        return False

    def check_write(
        self,
        register: int,
        value: int,
        source_ip: str,
    ) -> Dict:
        """Check whether a pending write is HMAC-authorized.

        Scans all valid (non-expired) tokens for a match on
        (register, value, source_ip).  The first match found is consumed and
        the write is approved.

        This method is called by the rule engine for every Modbus write packet.

        Args:
            register:  Modbus register address.
            value:     Value to be written.
            source_ip: Source IP address of the writer (used as client_id).

        Returns:
            A JSON-serialisable dict::

                {"authorized": True,  "reason": "Valid HMAC token found and consumed"}
                {"authorized": False, "reason": "No valid HMAC token for register/value"}
        """
        self._prune_expired()

        now = time.time()
        for storage_key, record in list(self._tokens.items()):
            if (
                record["register"] == register
                and record["value"] == value
                and record["client_id"] == source_ip
                and record["expires_at"] >= now
            ):
                # Consume the token
                del self._tokens[storage_key]
                logger.info(
                    "check_write: authorized  register=%d  value=%d  ip=%s",
                    register,
                    value,
                    source_ip,
                )
                return {
                    "authorized": True,
                    "reason": "Valid HMAC token found and consumed",
                }

        logger.warning(
            "check_write: UNAUTHORIZED  register=%d  value=%d  ip=%s",
            register,
            value,
            source_ip,
        )
        return {
            "authorized": False,
            "reason": "No valid HMAC token for this register/value/IP combination",
        }

    def get_pending_tokens(self) -> List[Dict]:
        """Return a list of all non-expired pending tokens.

        Suitable for display in the TUI dashboard.  Tokens are returned as
        copies so the caller cannot mutate internal state.

        Returns:
            List of token record dicts (same schema as :meth:`generate_token`
            return value).
        """
        self._prune_expired()
        return [dict(rec) for rec in self._tokens.values()]

    def revoke_all(self) -> None:
        """Emergency revocation: invalidate *all* pending tokens immediately.

        Call this during an incident or when the PLC enters a safe state.
        """
        count = len(self._tokens)
        self._tokens.clear()
        logger.critical("EMERGENCY REVOKE: invalidated %d token(s)", count)

    # ------------------------------------------------------------------
    # Repr / debug
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"HMACAuthManager("
            f"pending_tokens={len(self._tokens)}, "
            f"token_ttl={self._token_ttl}s)"
        )
