"""Best-effort hostname <-> IP resolution for CMDB display purposes.

Purely informational -- the results are shown to a user, never used to open
an outbound connection, so the SSRF-focused address-allowlist checks used for
webhook delivery (app.py's `_integration_address_allowed`) don't apply here.
Mirrors the existing `reverse_dns_lookup` in `network_discovery.py`: a short
bounded timeout, and any failure just means no answer, never an error."""
import socket


def resolve_hostname(ip):
    """PTR lookup for a single IP. Returns "" on any failure.

    No explicit timeout is set here, matching `reverse_dns_lookup`'s own
    `socket.gethostbyaddr` call in network_discovery.py: `socket.setdefaulttimeout`
    is process-global, not per-call, so mutating it around a single lookup
    would race with any other request's outbound socket calls running
    concurrently in the same worker."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        return ""


def resolve_ip(hostname):
    """Forward A/AAAA lookup for a single hostname. Returns [] on any failure."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (OSError, socket.herror, socket.gaierror):
        return []
    seen = []
    for info in infos:
        address = info[4][0]
        if address not in seen:
            seen.append(address)
    return seen
