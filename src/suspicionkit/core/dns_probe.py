from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field

import dns.resolver


@dataclass
class DnsProbeResult:
    ok: bool
    addresses: list[str] = field(default_factory=list)
    name_servers: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    has_private_ip: bool = False
    error: str | None = None


def probe_dns(host: str, lifetime: float = 3.0) -> DnsProbeResult:
    result = DnsProbeResult(ok=False)

    try:
        socket.gethostbyname(host)

        for record_type in ("A", "AAAA"):
            try:
                answers = dns.resolver.resolve(host, record_type, lifetime=lifetime)
                for answer in answers:
                    value = str(answer)
                    result.addresses.append(value)

                    try:
                        ip = ipaddress.ip_address(value)
                        if ip.is_private or ip.is_loopback or ip.is_link_local:
                            result.has_private_ip = True
                    except ValueError:
                        pass
            except Exception:
                pass

        for record_type, target in (
            ("NS", result.name_servers),
            ("MX", result.mx_records),
            ("CNAME", result.cname_records),
        ):
            try:
                answers = dns.resolver.resolve(host, record_type, lifetime=lifetime)
                for answer in answers:
                    target.append(str(answer).rstrip("."))
            except Exception:
                pass

        if result.addresses:
            result.ok = True
            return result

        result.error = "Domain resolved by socket, but no A/AAAA records were collected."
        return result

    except Exception as exc:
        result.error = str(exc)
        return result