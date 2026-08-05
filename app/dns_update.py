"""RFC2136 dynamic DNS updates against BIND, authenticated with TSIG."""
from __future__ import annotations

import logging
import socket

import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.update
import dns.zone

from app.config import DnsConfig

logger = logging.getLogger(__name__)

_ALGORITHM_ALIASES = {
    "hmac-md5": dns.tsig.HMAC_MD5,
    "hmac-sha1": dns.tsig.HMAC_SHA1,
    "hmac-sha224": dns.tsig.HMAC_SHA224,
    "hmac-sha256": dns.tsig.HMAC_SHA256,
    "hmac-sha384": dns.tsig.HMAC_SHA384,
    "hmac-sha512": dns.tsig.HMAC_SHA512,
}

_MANAGED_RDTYPES = ("A", "AAAA", "PTR")


class DnsUpdateError(RuntimeError):
    def __init__(self, rcode_text: str, zone: str, owner: str):
        self.rcode_text = rcode_text
        self.zone = zone
        self.owner = owner
        super().__init__(f"nsupdate to zone {zone!r} for {owner!r} failed: {rcode_text}")


def _resolve_algorithm(name: str) -> dns.name.Name:
    key = name.strip().lower()
    if key in _ALGORITHM_ALIASES:
        return _ALGORITHM_ALIASES[key]
    return dns.name.from_text(name)


class DnsUpdater:
    """Thin wrapper around dnspython's Update/query for our two primitives:
    replace a record set, and delete a record set. Both are idempotent.
    """

    def __init__(self, cfg: DnsConfig):
        self._cfg = cfg
        self._keyring = dns.tsigkeyring.from_text({cfg.tsig.key_name: cfg.tsig.secret})
        self._keyalgorithm = _resolve_algorithm(cfg.tsig.algorithm)

    def _send(self, update: dns.update.Update, zone: str, owner: str) -> None:
        query_fn = dns.query.tcp if self._cfg.use_tcp else dns.query.udp
        # dnspython's query functions want a literal IP address, not a
        # hostname - resolve here so `dns.server` can be a DNS/container name.
        server_ip = socket.gethostbyname(self._cfg.server)
        response = query_fn(
            update, server_ip, port=self._cfg.port, timeout=self._cfg.timeout
        )
        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            raise DnsUpdateError(dns.rcode.to_text(rcode), zone, owner)

    def replace_record(
        self, zone: str, owner_fqdn: str, rdtype: str, ttl: int, values: list[str]
    ) -> None:
        update = dns.update.Update(
            zone, keyring=self._keyring, keyalgorithm=self._keyalgorithm
        )
        update.replace(owner_fqdn, ttl, rdtype, *values)
        logger.info("nsupdate replace zone=%s owner=%s type=%s values=%s", zone, owner_fqdn, rdtype, values)
        self._send(update, zone, owner_fqdn)

    def delete_record(self, zone: str, owner_fqdn: str, rdtype: str) -> None:
        update = dns.update.Update(
            zone, keyring=self._keyring, keyalgorithm=self._keyalgorithm
        )
        update.delete(owner_fqdn, rdtype)
        logger.info("nsupdate delete zone=%s owner=%s type=%s", zone, owner_fqdn, rdtype)
        self._send(update, zone, owner_fqdn)

    def axfr(self, zone: str) -> dns.zone.Zone:
        server_ip = socket.gethostbyname(self._cfg.server)
        keyname = dns.name.from_text(self._cfg.tsig.key_name)
        xfr = dns.query.xfr(
            server_ip,
            zone,
            port=self._cfg.port,
            timeout=self._cfg.timeout,
            keyring=self._keyring,
            keyname=keyname,
            keyalgorithm=self._keyalgorithm,
            relativize=False,
        )
        return dns.zone.from_xfr(xfr, relativize=False)

    def current_managed_records(self, zone: str) -> dict[tuple[str, str], list[str]]:
        """AXFR `zone` and return ONLY A/AAAA/PTR records, keyed by
        (owner_fqdn, rdtype) -> sorted rdata strings. Every other record
        type (SOA/NS/MX/TXT/CNAME/...) is dropped here - this is the one
        choke point that keeps --prune scoped to what this tool manages.

        A/AAAA records at a name targeted by one of the zone's own NS
        records are also excluded - these are nameserver glue (zone
        infrastructure, not NetBox-managed data), and BIND itself refuses
        dynamic-update deletes against them in some configurations; treating
        them as permanently unmanaged here makes that safety property
        explicit and provider-agnostic rather than relying on BIND to
        enforce it.

        Raises on transfer failure (e.g. no allow-transfer for the TSIG
        key) - not caught here, same "raise on failure" posture as _send().
        """
        z = self.axfr(zone)

        ns_targets = {
            rdata.target.to_text().lower()
            for _, rdataset in z.iterate_rdatasets(rdtype=dns.rdatatype.NS)
            for rdata in rdataset
        }

        current: dict[tuple[str, str], list[str]] = {}
        for name, rdataset in z.iterate_rdatasets():
            rdtype = dns.rdatatype.to_text(rdataset.rdtype)
            if rdtype not in _MANAGED_RDTYPES:
                continue
            owner = name.to_text().lower()
            if rdtype in ("A", "AAAA") and owner in ns_targets:
                continue
            current[(owner, rdtype)] = sorted(rdata.to_text() for rdata in rdataset)
        return current
