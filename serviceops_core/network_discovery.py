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
IF-MIB, IP-MIB (ARP table), and LLDP-MIB (neighbor topology). No active
credential brute-forcing, no port scanning beyond the explicit configured
target list/subnet, no protocol other than SNMP. A discovery target is
always an explicit administrator-entered host or CIDR range with its own
stored (encrypted) community/credentials -- this never scans arbitrary
unconfigured network ranges.
"""
import asyncio
import ipaddress

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


async def _snmp_session(host, community, port, version, timeout):
    from pysnmp.hlapi.v3arch.asyncio import CommunityData, SnmpEngine, UdpTransportTarget

    engine = SnmpEngine()
    auth = CommunityData(community, mpModel=1 if version == "2c" else 0)
    transport = await UdpTransportTarget.create((host, port), timeout=timeout, retries=1)
    return engine, auth, transport


async def _async_snmp_get(host, community, oid, port=161, version="2c", timeout=2):
    from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, get_cmd

    engine, auth, transport = await _snmp_session(host, community, port, version, timeout)
    error_indication, error_status, _, var_binds = await get_cmd(
        engine, auth, transport, ContextData(), ObjectType(ObjectIdentity(oid)),
    )
    if error_indication or error_status:
        raise DiscoveryError(str(error_indication or error_status.prettyPrint()))
    return str(var_binds[0][1])


async def _async_snmp_walk(host, community, base_oid, port=161, version="2c", timeout=2):
    from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, walk_cmd

    engine, auth, transport = await _snmp_session(host, community, port, version, timeout)
    results = []
    async for error_indication, error_status, _, var_binds in walk_cmd(
        engine, auth, transport, ContextData(), ObjectType(ObjectIdentity(base_oid)), lexicographicMode=False,
    ):
        if error_indication:
            raise DiscoveryError(str(error_indication))
        if error_status:
            break
        for name, value in var_binds:
            results.append((str(name), str(value)))
    return results


def snmp_get(host, community, oid, port=161, version="2c", timeout=2):
    return asyncio.run(_async_snmp_get(host, community, oid, port=port, version=version, timeout=timeout))


def snmp_walk(host, community, base_oid, port=161, version="2c", timeout=2):
    return asyncio.run(_async_snmp_walk(host, community, base_oid, port=port, version=version, timeout=timeout))


def discover_host(host, community, port=161, version="2c", timeout=2):
    """Gathers MIB-II/IF-MIB/IP-MIB/LLDP-MIB facts from one SNMP-reachable
    host. Returns None (never raises) if the host doesn't respond to SNMP at
    all -- a normal, expected outcome when sweeping a subnet where most
    addresses are unused or not SNMP-enabled, not itself an error."""
    try:
        sys_descr = snmp_get(host, community, OID_SYS_DESCR, port=port, version=version, timeout=timeout)
    except (DiscoveryError, OSError, TimeoutError):
        return None

    def safe_get(oid):
        try:
            return snmp_get(host, community, oid, port=port, version=version, timeout=timeout)
        except (DiscoveryError, OSError, TimeoutError):
            return ""

    def safe_walk(oid):
        try:
            return snmp_walk(host, community, oid, port=port, version=version, timeout=timeout)
        except (DiscoveryError, OSError, TimeoutError):
            return []

    sys_object_id = safe_get(OID_SYS_OBJECT_ID)
    sys_name = safe_get(OID_SYS_NAME)
    sys_uptime = safe_get(OID_SYS_UPTIME)

    interfaces = []
    for oid, value in safe_walk(OID_IF_DESCR):
        interfaces.append({"index": oid.rsplit(".", 1)[-1], "descr": value})
    mac_by_index = {oid.rsplit(".", 1)[-1]: value for oid, value in safe_walk(OID_IF_PHYS_ADDRESS)}
    for interface in interfaces:
        interface["mac_address"] = mac_by_index.get(interface["index"], "")

    arp_entries = [value for _, value in safe_walk(OID_ARP_NET_ADDRESS)]

    lldp_names = {oid: value for oid, value in safe_walk(OID_LLDP_REM_SYS_NAME)}
    lldp_ports = {oid: value for oid, value in safe_walk(OID_LLDP_REM_PORT_ID)}
    lldp_neighbors = []
    for oid, neighbor_name in lldp_names.items():
        # lldpRemPortId shares the same trailing index suffix as lldpRemSysName.
        suffix = ".".join(oid.split(".")[-3:])
        port_oid = next((candidate for candidate in lldp_ports if candidate.endswith(suffix)), None)
        lldp_neighbors.append({
            "neighbor_name": neighbor_name,
            "neighbor_port": lldp_ports.get(port_oid, "") if port_oid else "",
        })

    vendor = guess_vendor(sys_object_id)
    facts = {
        "host": host, "sys_descr": sys_descr, "sys_object_id": sys_object_id,
        "sys_name": sys_name, "sys_uptime": sys_uptime, "vendor": vendor,
        "interfaces": interfaces, "arp_entries": arp_entries, "lldp_neighbors": lldp_neighbors,
    }
    facts["ci_class"] = guess_ci_class(facts)
    return facts


def discover_subnet(cidr, community, port=161, version="2c", timeout=1, max_hosts=1024):
    """Sweeps every usable host address in ``cidr`` and returns discover_host
    results for those that actually respond to SNMP; non-responders are
    silently skipped (see discover_host's docstring). ``max_hosts`` is a hard
    cap so a mistakenly huge CIDR (e.g. a /8) can't turn one discovery run
    into an unbounded scan."""
    network = ipaddress.ip_network(cidr, strict=False)
    discovered = []
    for index, address in enumerate(network.hosts()):
        if index >= max_hosts:
            break
        facts = discover_host(str(address), community, port=port, version=version, timeout=timeout)
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

    summary = {"hosts_seen": len(facts_list), "created": 0, "updated": 0, "relationships_created": 0, "errors": []}
    host_to_ci = {}

    for facts in facts_list:
        try:
            ip_address = facts["host"]
            existing = ConfigurationItem.query.filter_by(tenant_id=tenant_id, ip_address=ip_address).first()
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
                existing.attributes = attributes
                existing.updated_at = now()
                if existing.discovery_source != "Manual":
                    existing.discovery_source = "SNMP Discovery"
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
                    discovery_source="SNMP Discovery",
                    attributes=attributes,
                    tenant_id=tenant_id,
                )
                db.session.add(ci)
                db.session.flush()
                summary["created"] += 1
            host_to_ci[ip_address] = ci
        except Exception as error:  # noqa: BLE001 - one bad host must never block the rest of the sweep
            summary["errors"].append(f"{facts.get('host', '?')}: {error}")

    # LLDP neighbor edges: only link pairs where BOTH sides were discovered
    # in this same run (matched by sysName), since a neighbor name alone
    # isn't a reliable enough key to match against unrelated existing CIs.
    name_to_ci = {ci.name: ci for ci in host_to_ci.values()}
    for facts in facts_list:
        source_ci = host_to_ci.get(facts.get("host"))
        if not source_ci:
            continue
        for neighbor in facts.get("lldp_neighbors", []):
            neighbor_ci = name_to_ci.get(neighbor.get("neighbor_name"))
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
            if not exists:
                db.session.add(CIRelationship(
                    tenant_id=tenant_id, parent_id=source_ci.id, child_id=neighbor_ci.id,
                    relationship_type="Connects to",
                ))
                summary["relationships_created"] += 1

    db.session.commit()
    return summary
