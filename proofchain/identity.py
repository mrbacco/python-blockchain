##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/identity.py
#
# domain verification of identities: an address
# that claims "domain example.com" is verified
# when https://example.com/.well-known/proofchain.json
# lists that address. this check happens when the
# data is read (never during consensus, which must
# stay deterministic) and results are cached.
##################################################

import ipaddress
import json
import logging
import socket
import threading
import time
from dataclasses import dataclass

import httpx

from proofchain.transaction import is_domain

log = logging.getLogger("proofchain.identity")

WELL_KNOWN_PATH = "/.well-known/proofchain.json"
MAX_RESPONSE_BYTES = 64 * 1024
CACHE_SECONDS = 600
FAILURE_CACHE_SECONDS = 30  # retry soon after an owner fixes their file


@dataclass(frozen=True)
class DomainCheck():
    verified: bool
    detail: str
    checked_at: int

    def to_dict(self) -> dict:
        return {"verified": self.verified, "detail": self.detail, "checked_at": self.checked_at}


def well_known_document(addresses: list[str]) -> str:
    # the file an owner publishes on their domain
    return json.dumps({"addresses": addresses}, indent=2)


class DomainVerifier():
    # allow_insecure: plain http and private/loopback hosts, for local testing only
    def __init__(self, allow_insecure: bool = False, timeout: float = 5.0, cache_seconds: int = CACHE_SECONDS):
        self.allow_insecure = allow_insecure
        self.timeout = timeout
        self.cache_seconds = cache_seconds
        self._cache: dict[str, tuple[float, set[str] | None, str]] = {}
        self._lock = threading.Lock()

    def check(self, domain: str, address: str) -> DomainCheck:
        addresses, detail = self._addresses(domain)
        now = int(time.time() * 1000)
        if addresses is None:
            return DomainCheck(False, detail, now)
        if address in addresses:
            return DomainCheck(True, f"listed in {domain}{WELL_KNOWN_PATH}", now)
        return DomainCheck(False, f"address not listed in {domain}{WELL_KNOWN_PATH}", now)

    def _addresses(self, domain: str) -> tuple[set[str] | None, str]:
        with self._lock:
            cached = self._cache.get(domain)
            if cached and time.monotonic() < cached[0]:
                return cached[1], cached[2]
        addresses, detail = self._fetch(domain)
        with self._lock:
            ttl = self.cache_seconds if addresses is not None else min(self.cache_seconds, FAILURE_CACHE_SECONDS)
            self._cache[domain] = (time.monotonic() + ttl, addresses, detail)
        return addresses, detail

    def _host_allowed(self, domain: str) -> str | None:
        # returns a reason when the host must not be contacted (SSRF protection)
        if not is_domain(domain):
            return "invalid domain"
        if self.allow_insecure:
            return None
        host, _, port = domain.partition(":")
        if port:
            return "custom ports are only allowed in insecure (local test) mode"
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return "domain does not resolve"
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if not ip.is_global:
                return "domain resolves to a private or reserved address"
        return None

    def _fetch(self, domain: str) -> tuple[set[str] | None, str]:
        refused = self._host_allowed(domain)
        if refused:
            return None, refused
        scheme = "http" if self.allow_insecure else "https"
        url = f"{scheme}://{domain}{WELL_KNOWN_PATH}"
        try:
            # no redirects: the document must live on the claimed domain itself
            with httpx.stream("GET", url, timeout=self.timeout, follow_redirects=False) as response:
                if response.status_code != 200:
                    return None, f"{url} returned HTTP {response.status_code}"
                body = b""
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE_BYTES:
                        return None, f"{url} is larger than {MAX_RESPONSE_BYTES} bytes"
            addresses = json.loads(body)["addresses"]
            if not isinstance(addresses, list) or not all(isinstance(a, str) for a in addresses):
                raise TypeError("addresses must be a list of strings")
        except httpx.HTTPError as exc:
            log.info("identity check for %s failed: %s", domain, exc)
            return None, f"could not fetch {url}"
        except (ValueError, KeyError, TypeError) as exc:
            return None, f"{url} is not a valid proofchain.json ({exc})"
        return set(addresses), "ok"
