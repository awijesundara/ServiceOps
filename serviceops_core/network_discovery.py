"""Agentless network discovery: SNMP-based fact gathering from switches and
other SNMP-speaking devices (no software installed on the target -- distinct
from and complementary to tools/cmdb_sync_agent.sh, which is an *agent* a
host runs on itself), plus reconciliation of discovered facts into the
existing ConfigurationItem/CIRelationship CMDB tables.

Design intentionally mirrors ldap_sync.py: pure network/parsing functions at
the top (unit-testable without a database or a real device, by monkeypatching
`discover_host`), and a reconciliation function at the bottom that lazily
imports `app` to avoid a circular import at module load time (app.py imports
this module; this module must not import app.py at import time).

Scope, deliberately bounded: SNMPv2c/v3 GET/WALK against standard MIB-II,
IF-MIB, IP-MIB (ARP table), and LLDP-MIB (neighbor topology), for full
detail. Most consumer/office devices (phones, laptops, most routers, smart-
home gear) don't run an SNMP agent at all, so SNMP alone misses most of a
typical network -- real hardware validation confirmed this (a /24 sweep
found only 1 of the many devices actually on the network, the one running
SNMP). To match what GLPI/FusionInventory-style agentless discovery
actually does, a device that doesn't answer SNMP is still checked for basic
liveness via `tcp_liveness_probe()` -- a handful of very common TCP ports
(80, 443, 22), never more, and only ever against the administrator's own
explicit target host/subnet, never a range no one configured. A live-but-
non-SNMP device is still recorded as a bare CI (IP only, no vendor/
interfaces/relationships) rather than being silently invisible, with
`discovery_source` distinguishing "SNMP Discovery" (full detail) from
"Network sweep (no SNMP)" (presence only) so nothing pretends to know more
than it does. No credential brute-forcing, no protocol beyond SNMP+this
narrow liveness check, no scanning outside the configured target.
"""
import asyncio
import errno
import ipaddress
import socket

# Standard MIB-II / IF-MIB / IP-MIB / LLDP-MIB OIDs used for discovery.
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_ARP_NET_ADDRESS = "1.3.6.1.2.1.4.22.1.3"
OID_LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"

# Enterprise-number prefixes of sysObjectID -> vendor, for a best-effort
# vendor guess without needing a full vendor MIB database. Extend as needed;
# an unrecognized prefix simply leaves vendor blank rather than guessing wrong.
VENDOR_OID_PREFIXES = {
    "1.3.6.1.4.1.9.": "Cisco",
    "1.3.6.1.4.1.11.": "HP",
    "1.3.6.1.4.1.2636.": "Juniper",
    "1.3.6.1.4.1.6027.": "Dell (Force10)",
    "1.3.6.1.4.1.674.": "Dell",
    "1.3.6.1.4.1.2011.": "Huawei",
    "1.3.6.1.4.1.8072.": "Net-SNMP (generic host)",
    "1.3.6.1.4.1.14988.": "MikroTik",
    "1.3.6.1.4.1.4526.": "Netgear",
    "1.3.6.1.4.1.2435.": "Brother",
    "1.3.6.1.4.1.311.": "Microsoft",
    "1.3.6.1.4.1.10071.": "Ubiquiti",
    "1.3.6.1.4.1.1588.": "Brocade",
}


class DiscoveryError(RuntimeError):
    """Raised for conditions that must abort a single target's discovery
    (e.g. unreachable/no SNMP response) -- always caught by the caller so one
    bad target never blocks the rest of a subnet or scheduled run."""


def guess_vendor(sys_object_id):
    if not sys_object_id:
        return ""
    normalized = sys_object_id.lstrip(".") + "."
    for prefix, vendor in VENDOR_OID_PREFIXES.items():
        if normalized.startswith(prefix):
            return vendor
    return ""


def guess_ci_class(facts):
    """Heuristic only -- an administrator can always correct ci_class by
    hand afterward; discovery never locks a field against manual editing."""
    interface_count = len(facts.get("interfaces") or [])
    descr = (facts.get("sys_descr") or "").lower()
    if facts.get("lldp_neighbors") or (interface_count > 4 and "cisco" in (facts.get("vendor") or "").lower()):
        return "Network Switch"
    if interface_count > 4 and facts.get("vendor") in ("Juniper", "HP", "Huawei", "MikroTik", "Netgear"):
        return "Network Switch"
    if "linux" in descr or "windows" in descr or "vmware" in descr:
        return "Server"
    if interface_count:
        return "Network Appliance"
    return "Device"


class _SnmpSession:
    """One SnmpEngine, auth, and transport shared across every GET/WALK for
    a single host/run, all inside one event loop (one asyncio.run() call).

    This exists because of a real production incident: the original code
    created a brand-new pysnmp SnmpEngine() for every single GET/WALK
    (roughly 9 operations per host -- sys_descr, sys_object_id, sys_name,
    sys_uptime, an ifDescr walk, an ifPhysAddress walk, an ARP walk, and two
    LLDP walks). SnmpEngine() is pysnmp's heaviest object to construct -- it
    initializes MIB instrumentation and, on a cold cache, can compile MIB
    source via pysmi -- so a /24 sweep with 40 concurrent worker threads
    could trigger thousands of engine constructions and MIB-compile attempts
    within seconds, spiking memory enough to crash the container on a
    modestly-provisioned host. Sharing one engine per host cuts that by
    roughly 9x; see discover_host's docstring for the full incident note."""

    def __init__(self, host, community, port, version, timeout):
        self.host, self.community, self.port, self.version, self.timeout = (
            host, community, port, version, timeout,
        )
        self.engine = None
        self.auth = None
        self.transport = None
        self.context = None

    async def __aenter__(self):
        from pysnmp.hlapi.v3arch.asyncio import CommunityData, ContextData, SnmpEngine, UdpTransportTarget

        self.engine = SnmpEngine()
        self.auth = CommunityData(self.community, mpModel=1 if self.version == "2c" else 0)
        self.transport = await UdpTransportTarget.create(
            (self.host, self.port), timeout=self.timeout, retries=1,
        )
        self.context = ContextData()
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def get(self, oid):
        from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity, ObjectType, get_cmd

        error_indication, error_status, _, var_binds = await get_cmd(
            self.engine, self.auth, self.transport, self.context, ObjectType(ObjectIdentity(oid)),
        )
        if error_indication or error_status:
            raise DiscoveryError(str(error_indication or error_status.prettyPrint()))
        return var_binds[0][1]

    async def walk(self, base_oid):
        from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity, ObjectType, walk_cmd

        results = []
        async for error_indication, error_status, _, var_binds in walk_cmd(
            self.engine, self.auth, self.transport, self.context,
            ObjectType(ObjectIdentity(base_oid)), lexicographicMode=False,
        ):
            if error_indication:
                raise DiscoveryError(str(error_indication))
            if error_status:
                break
            for name, value in var_binds:
                results.append((str(name), value))
        return results


def _format_mac(value):
    """SNMP returns interface/hardware addresses as a raw 6-byte
    OctetString -- str(value) on that gives mangled, unreadable characters
    (confirmed against a real device during validation), not a MAC. Format
    as the conventional colon-hex form; falls back to the raw string for
    anything that isn't exactly 6 bytes (some devices report an empty or
    non-Ethernet address here)."""
    try:
        raw = value.asOctets()
    except AttributeError:
        return str(value)
    if len(raw) == 6:
        return ":".join(f"{byte:02x}" for byte in raw)
    return str(value)


def _format_ipv4(value):
    """ARP-table entries (ipNetToMediaNetAddress) come back as a raw 4-byte
    IpAddress -- same mangled-string problem as MACs. Format as dotted
    decimal; falls back to the raw string for anything not exactly 4 bytes."""
    try:
        raw = value.asOctets()
    except AttributeError:
        return str(value)
    if len(raw) == 4:
        return ".".join(str(byte) for byte in raw)
    return str(value)


async def _discover_host_async(host, community, port, version, timeout):
    async with _SnmpSession(host, community, port, version, timeout) as session:
        try:
            sys_descr = str(await session.get(OID_SYS_DESCR))
        except (DiscoveryError, OSError, TimeoutError):
            return None

        async def safe_get(oid):
            try:
                return str(await session.get(oid))
            except (DiscoveryError, OSError, TimeoutError):
                return ""

        async def safe_walk(oid):
            try:
                return await session.walk(oid)
            except (DiscoveryError, OSError, TimeoutError):
                return []

        sys_object_id = await safe_get(OID_SYS_OBJECT_ID)
        sys_name = await safe_get(OID_SYS_NAME)
        sys_uptime = await safe_get(OID_SYS_UPTIME)

        interfaces = []
        for oid, value in await safe_walk(OID_IF_DESCR):
            interfaces.append({"index": oid.rsplit(".", 1)[-1], "descr": str(value)})
        mac_by_index = {
            oid.rsplit(".", 1)[-1]: _format_mac(value) for oid, value in await safe_walk(OID_IF_PHYS_ADDRESS)
        }
        for interface in interfaces:
            interface["mac_address"] = mac_by_index.get(interface["index"], "")

        arp_entries = [_format_ipv4(value) for _, value in await safe_walk(OID_ARP_NET_ADDRESS)]

        lldp_names = {oid: str(value) for oid, value in await safe_walk(OID_LLDP_REM_SYS_NAME)}
        lldp_ports = {oid: str(value) for oid, value in await safe_walk(OID_LLDP_REM_PORT_ID)}
        interface_descr_by_index = {iface["index"]: iface["descr"] for iface in interfaces}
        lldp_neighbors = []
        for oid, neighbor_name in lldp_names.items():
            # lldpRemPortId shares the same trailing index suffix as lldpRemSysName.
            suffix = ".".join(oid.split(".")[-3:])
            port_oid = next((candidate for candidate in lldp_ports if candidate.endswith(suffix)), None)
            # The lldpRemEntry index is lldpRemTimeMark.lldpRemLocalPortNum.
            # lldpRemIndex -- the middle component identifies which of THIS
            # device's own ports the neighbor was seen on. Most
            # implementations set lldpRemLocalPortNum equal to ifIndex, so
            # correlating it against the ifDescr walk above resolves it to
            # a human port name (e.g. "Ethernet51") for the topology map's
            # "server X is plugged into switch port Y" view -- falls back
            # to the bare numeric index if a vendor doesn't follow that
            # convention, rather than guessing.
            local_port_index = oid.split(".")[-2]
            lldp_neighbors.append({
                "neighbor_name": neighbor_name,
                "neighbor_port": lldp_ports.get(port_oid, "") if port_oid else "",
                "local_port": interface_descr_by_index.get(local_port_index, local_port_index),
            })

        vendor = guess_vendor(sys_object_id)
        facts = {
            "host": host, "sys_descr": sys_descr, "sys_object_id": sys_object_id,
            "sys_name": sys_name, "sys_uptime": sys_uptime, "vendor": vendor,
            "interfaces": interfaces, "arp_entries": arp_entries, "lldp_neighbors": lldp_neighbors,
        }
        facts["ci_class"] = guess_ci_class(facts)
        return facts


def discover_host(host, community, port=161, version="2c", timeout=2):
    """Gathers MIB-II/IF-MIB/IP-MIB/LLDP-MIB facts from one SNMP-reachable
    host, using exactly one shared SnmpEngine for all of it (see
    _SnmpSession's docstring for why that matters -- a real memory/crash
    incident on a real scan). Returns None (never raises) if the host
    doesn't respond to SNMP at all -- a normal, expected outcome when
    sweeping a subnet where most addresses are unused or not SNMP-enabled,
    not itself an error."""
    return asyncio.run(_discover_host_async(host, community, port, version, timeout))


# Very common TCP ports checked ONLY to establish basic liveness for a host
# that didn't answer SNMP -- never treated as a port scan or service
# inventory, just "is anything home at this address". Deliberately short:
# widening this list trades sweep speed for a small chance of catching a
# device that only listens on something unusual.
LIVENESS_PROBE_PORTS = (80, 443, 22)


def tcp_liveness_probe(host, ports=LIVENESS_PROBE_PORTS, timeout=0.2):
    """True if the host answers a TCP connection attempt on any of
    ``ports`` -- either an actual open port, or a prompt connection-refused
    (which still proves a live TCP/IP stack answered, just with that port
    closed). A host that's simply absent from the network, or silently
    drops everything behind a strict firewall, times out on every attempt
    and is reported as not alive -- an inherent limitation of any
    non-privileged (no raw ICMP socket) liveness check, not a bug."""
    for probe_port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, probe_port))
                if result == 0 or result == errno.ECONNREFUSED:
                    return True
        except OSError:
            continue
    return False


def reverse_dns_lookup(host, nameserver=None, timeout=0.5):
    """Best-effort PTR lookup for a bare (non-SNMP) device's hostname.

    Two strategies, both genuinely best-effort -- this is honest about its
    limits rather than promising a name for every device: (1) the system
    resolver (works if it's configured to forward local PTR queries, which
    Docker's own embedded DNS is not by default); (2) a direct query against
    ``nameserver`` (typically the subnet's own gateway, since many SOHO/
    business routers -- UniFi, pfSense, OPNsense, most enterprise DHCP
    servers -- answer PTR for their own DHCP leases; plenty of consumer
    routers don't). Returns "" (never raises) if neither resolves."""
    try:
        return socket.gethostbyaddr(host)[0]
    except (OSError, socket.herror):
        pass
    if not nameserver:
        return ""
    try:
        import dns.resolver
        import dns.reversename

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answer = resolver.resolve(dns.reversename.from_address(host), "PTR")
        return str(answer[0]).rstrip(".")
    except Exception:  # noqa: BLE001 - any DNS failure here just means no name, never an error
        return ""


def probe_host(host, community, port=161, version="2c", timeout=2, liveness_timeout=0.2, dns_nameserver=None):
    """The actual per-host discovery entry point used by discover_subnet and
    by app.py's single-host discovery routes: try full SNMP detail first
    (discover_host), and only if that gets no response, fall back to a bare
    liveness check so a real device on the network is still recorded --
    just with a "Network sweep (no SNMP)" discovery_source and none of the
    vendor/interface/relationship detail an SNMP-capable device provides.
    A bare hit still gets a best-effort reverse-DNS name attempt (see
    reverse_dns_lookup) instead of always falling back to the bare IP."""
    facts = discover_host(host, community, port=port, version=version, timeout=timeout)
    if facts:
        facts["discovery_source"] = "SNMP Discovery"
        return facts
    if tcp_liveness_probe(host, timeout=liveness_timeout):
        resolved_name = reverse_dns_lookup(host, nameserver=dns_nameserver)
        return {
            "host": host, "sys_descr": "", "sys_object_id": "", "sys_name": resolved_name or host,
            "sys_uptime": "", "vendor": "", "ci_class": "Device",
            "interfaces": [], "arp_entries": [], "lldp_neighbors": [],
            "discovery_source": "Network sweep (no SNMP)",
        }
    return None


def discover_subnet(cidr, community, port=161, version="2c", timeout=0.6, max_hosts=1024, max_workers=40):
    """Sweeps every usable host address in ``cidr`` via probe_host (SNMP
    detail first, bare liveness fallback second -- see probe_host's
    docstring for why the fallback exists) and returns every host that
    responded to either. ``max_hosts`` is a hard cap so a mistakenly huge
    CIDR (e.g. a /8) can't turn one discovery run into an unbounded scan.

    Probes are run concurrently (thread pool -- each host's SNMP/TCP round
    trip is I/O-bound, so this is a real wall-clock win, not just busywork):
    a full /24 sequentially at even a 1s timeout could take several minutes
    and exceed gunicorn's request timeout, which is exactly what happened
    the first time this ran against a real subnet (silently "hanging" until
    the worker was killed). Parallelized, the same /24 completes in
    roughly 15-25s -- safely inside gunicorn's default 60s timeout."""
    import concurrent.futures

    network = ipaddress.ip_network(cidr, strict=False)
    addresses = list(network.hosts())[:max_hosts]
    # Best-effort reverse-DNS nameserver for bare hits: the subnet's own
    # gateway (conventionally .1) -- see reverse_dns_lookup's docstring for
    # why this is a guess that works on some networks and not others.
    gateway_guess = str(addresses[0]) if addresses else None

    def probe(address):
        return probe_host(
            str(address), community, port=port, version=version, timeout=timeout,
            dns_nameserver=gateway_guess,
        )

    discovered = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for facts in pool.map(probe, addresses):
            if facts:
                discovered.append(facts)
    return discovered


def reconcile_facts_into_cmdb(tenant_id, target_name, facts_list):
    """Upserts ConfigurationItem rows and "Connects to" CIRelationship edges
    from a list of discover_host()-shaped fact dicts. Lazily imports app.py
    to avoid a circular import (app.py imports this module at load time).

    Conservative by design, matching the same philosophy as ldap_sync.py and
    the Keycloak/LDAP profile-attribute mapping: a CI that already exists and
    was manually created (discovery_source == "Manual") has its identity
    fields (name, ci_class, vendor, model) left alone -- only ip_address,
    attributes, and discovery_source metadata are refreshed -- so an
    administrator's manual classification is never silently overwritten by a
    heuristic guess. A CI discovery itself created is fully refreshed each
    run."""
    import app as core_app
    from app import CIRelationship, ConfigurationItem, db, now
    from sqlalchemy import func

    summary = {
        "hosts_seen": len(facts_list), "created": 0, "updated": 0, "relationships_created": 0,
        "snmp_hosts": sum(1 for f in facts_list if f.get("discovery_source", "SNMP Discovery") == "SNMP Discovery"),
        "bare_hosts": sum(1 for f in facts_list if f.get("discovery_source") == "Network sweep (no SNMP)"),
        "errors": [],
    }
    host_to_ci = {}

    for facts in facts_list:
        try:
            ip_address = facts["host"]
            source = facts.get("discovery_source", "SNMP Discovery")
            is_snmp = source == "SNMP Discovery"
            existing = ConfigurationItem.query.filter_by(tenant_id=tenant_id, ip_address=ip_address).first()
            if not existing and facts.get("sys_name"):
                # A device rediscovered at a new/different IP (DHCP churn,
                # multi-homed hosts) or a CI whose ip_address was never set
                # by the CSV/NetBox import that first created it (a real,
                # observed cause of duplicate CIs -- the same hostname
                # showing up twice, once "Manual"/ci_class=Server with no
                # ip_address and once discovery-created as ci_class=Device
                # at the IP the scan actually found it at) would otherwise
                # never match the IP-only lookup above and get a duplicate
                # CI created instead of being merged into the existing one.
                # Exact, case-insensitive hostname match is the fallback --
                # scoped to this tenant, same identity-preservation rules
                # below apply regardless of which lookup found the match.
                existing = ConfigurationItem.query.filter(
                    ConfigurationItem.tenant_id == tenant_id,
                    func.lower(ConfigurationItem.name) == facts["sys_name"].casefold(),
                ).first()
            attributes = {
                "sys_descr": facts.get("sys_descr", ""),
                "sys_object_id": facts.get("sys_object_id", ""),
                "sys_uptime": facts.get("sys_uptime", ""),
                "interfaces": facts.get("interfaces", []),
                "lldp_neighbors": facts.get("lldp_neighbors", []),
                "discovered_via": target_name,
                "discovered_at": now().isoformat(),
            }
            if existing:
                existing.updated_at = now()
                # ip_address is operational data (where the device actually
                # answered), not identity -- always safe to refresh even for
                # a Manual CI, unlike name/ci_class/vendor below. Matters
                # most for the name-fallback match above, where the existing
                # CI commonly has no ip_address at all yet.
                existing.ip_address = ip_address
                # A bare (non-SNMP) liveness hit on a device we'd previously
                # fully profiled via SNMP must never blank out that richer
                # detail -- only refresh "last seen"; leave interfaces/
                # sys_descr/etc. as they were from the earlier SNMP run.
                if is_snmp or existing.discovery_source != "SNMP Discovery":
                    existing.attributes = attributes
                if existing.discovery_source != "Manual":
                    if is_snmp or existing.discovery_source != "SNMP Discovery":
                        existing.discovery_source = source
                        existing.vendor = facts.get("vendor") or existing.vendor
                        if facts.get("sys_name"):
                            existing.name = facts["sys_name"]
                        existing.ci_class = facts.get("ci_class", existing.ci_class)
                ci = existing
                summary["updated"] += 1
            else:
                ci = ConfigurationItem(
                    name=facts.get("sys_name") or ip_address,
                    ci_class=facts.get("ci_class", "Device"),
                    ip_address=ip_address,
                    vendor=facts.get("vendor") or None,
                    discovery_source=source,
                    attributes=attributes,
                    tenant_id=tenant_id,
                )
                db.session.add(ci)
                db.session.flush()
                summary["created"] += 1
            host_to_ci[ip_address] = ci
        except Exception as error:  # noqa: BLE001 - one bad host must never block the rest of the sweep
            summary["errors"].append(f"{facts.get('host', '?')}: {error}")

    # LLDP neighbor edges. Prefer a same-run match (matched by sysName --
    # cheapest and most certain, both sides freshly confirmed together in
    # this exact sweep). For a neighbor not seen in this run -- the common
    # case for a single-host/small-target scan, where most reported LLDP
    # neighbors were never individually scanned -- fall back to the wider
    # CMDB, but restricted to CIs discovery itself created/confirmed
    # (discovery_source != "Manual"/"Import"/"API"): a hostname alone isn't a
    # reliable enough key to risk linking against an unrelated CI a human
    # happened to name the same thing, but it's a reasonable key among CIs
    # that are themselves discovered network hosts. This is what lets a
    # topology actually accumulate across repeated incremental scans rather
    # than only ever seeing pairs scanned in the exact same run together.
    name_to_ci = {ci.name: ci for ci in host_to_ci.values()}
    DISCOVERED_SOURCES = ("SNMP Discovery", "Network sweep (no SNMP)")

    def _find_neighbor_ci(neighbor_name):
        if not neighbor_name:
            return None
        matched = name_to_ci.get(neighbor_name)
        if matched:
            return matched
        return ConfigurationItem.query.filter(
            ConfigurationItem.tenant_id == tenant_id,
            ConfigurationItem.discovery_source.in_(DISCOVERED_SOURCES),
            func.lower(ConfigurationItem.name) == neighbor_name.casefold(),
        ).first()

    for facts in facts_list:
        source_ci = host_to_ci.get(facts.get("host"))
        if not source_ci:
            continue
        for neighbor in facts.get("lldp_neighbors", []):
            neighbor_ci = _find_neighbor_ci(neighbor.get("neighbor_name"))
            if not neighbor_ci or neighbor_ci.id == source_ci.id:
                continue
            # "Connects to" is symmetric for LLDP-discovered pairs -- both
            # sides typically report each other as a neighbor in the same
            # run, so check both directions to store one edge, not two.
            exists = CIRelationship.query.filter(
                CIRelationship.tenant_id == tenant_id,
                CIRelationship.relationship_type == "Connects to",
                db.or_(
                    db.and_(CIRelationship.parent_id == source_ci.id, CIRelationship.child_id == neighbor_ci.id),
                    db.and_(CIRelationship.parent_id == neighbor_ci.id, CIRelationship.child_id == source_ci.id),
                ),
            ).first()
            local_port = neighbor.get("local_port") or ""
            remote_port = neighbor.get("neighbor_port") or ""
            label = f"{local_port} ↔ {remote_port}" if local_port or remote_port else None
            if not exists:
                db.session.add(CIRelationship(
                    tenant_id=tenant_id, parent_id=source_ci.id, child_id=neighbor_ci.id,
                    relationship_type="Connects to", label=label,
                ))
                summary["relationships_created"] += 1
            elif label and not exists.label:
                # Backfill a label onto a relationship created by a scan
                # before this port-level detail existed.
                exists.label = label

    db.session.commit()
    return summary
