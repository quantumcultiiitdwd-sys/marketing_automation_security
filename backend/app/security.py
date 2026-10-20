import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
import socket
import time
from datetime import timedelta
from urllib.parse import urlparse

import httpx
import jwt
from cryptography.fernet import Fernet, InvalidToken

from .config import settings
from .db import utcnow

_PBKDF2_ROUNDS = 240_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2${_PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, rounds, salt, digest = stored.split("$")
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
    return hmac.compare_digest(dk.hex(), digest)


def create_token(user_id: str, session_id: str) -> str:
    exp = utcnow() + timedelta(hours=settings.session_hours)
    return jwt.encode({"sub": user_id, "sid": session_id, "exp": exp}, settings.secret_key, algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])


def new_api_key(prefix: str) -> tuple[str, str, str]:
    """Returns (plaintext, sha256 hash, display prefix). Plaintext is shown once."""
    key = f"{prefix}_{secrets.token_urlsafe(32)}"
    return key, sha256(key), key[:12]


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _fernet() -> Fernet:
    key = settings.encryption_key or base64.urlsafe_b64encode(hashlib.sha256(settings.secret_key.encode()).digest()).decode()
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as e:
        raise ValueError("Credential could not be decrypted") from e


def sign(value: str) -> str:
    return hmac.new(settings.secret_key.encode(), value.encode(), hashlib.sha256).hexdigest()


def verify_webhook_signature(secret: str, timestamp: str, body: bytes, signature: str, tolerance: int = 300) -> bool:
    """HMAC-SHA256 over '{timestamp}.{body}', rejects stale timestamps (replay protection)."""
    try:
        if abs(time.time() - int(timestamp)) > tolerance:
            return False
    except ValueError:
        return False
    expected = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.removeprefix("sha256="))


def check_url_safe(url: str) -> str:
    """SSRF guard for user-supplied integration URLs."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must be http(s) with a host")
    if settings.env == "production" and parsed.scheme != "https":
        raise ValueError("HTTPS is required in production")
    if settings.allow_private_hosts:
        return url
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
    except socket.gaierror as e:
        raise ValueError("Host could not be resolved") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("URL resolves to a private or reserved address")
    # ponytail: resolve-then-connect leaves a DNS-rebinding window; pin the resolved IP in the HTTP client if that matters.
    return url


_SECRET_KEYS = re.compile(r"(pass(word)?|secret|token|api[_-]?key|authorization|cookie|credential)", re.I)
_EMAIL = re.compile(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def redact(value, depth: int = 0):
    """Strip secrets and pseudonymise email addresses before storage/logging."""
    if depth > 8:
        return "[truncated]"
    if isinstance(value, dict):
        return {k: ("[redacted]" if _SECRET_KEYS.search(str(k)) else redact(v, depth + 1)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value]
    if isinstance(value, str):
        return _EMAIL.sub(lambda m: f"user-{sha256(m.group(0).lower())[:10]}@{m.group(2)}", value)
    return value


def verify_turnstile(token: str | None, action: str) -> bool:
    """Cloudflare Turnstile siteverify. Fails closed on any error, wrong action or unexpected hostname."""
    if not token or len(token) > 2048 or not settings.turnstile_hostnames:
        return False
    try:
        r = httpx.post("https://challenges.cloudflare.com/turnstile/v0/siteverify", timeout=10,
                       data={"secret": settings.turnstile_secret, "response": token})
        r.raise_for_status()
        result = r.json()
    except (httpx.HTTPError, ValueError):
        return False
    # Cloudflare test keys return no action; production refuses test keys at startup (config.validate).
    action_ok = result.get("action") == action or (result.get("metadata") or {}).get("result_with_testing_key") is True
    return result.get("success") is True and action_ok and result.get("hostname") in settings.turnstile_hostnames
