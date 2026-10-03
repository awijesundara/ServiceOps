"""Offline, conservative identification for physical rack equipment.

An illustration identifies a category, never claims an exact model match.
Explicit roles/classes take precedence over model families and name hints.
"""
import re


def words(value):
    return " ".join(re.findall(r"[a-z0-9]+", str(value or "").casefold()))


VENDOR_ALIASES = {
    "dell": "dell", "dell inc": "dell", "dell technologies": "dell", "dell emc": "dell",
    "cisco": "cisco", "cisco systems": "cisco", "cisco systems inc": "cisco",
    "juniper": "juniper", "juniper networks": "juniper",
}
EXACT_MODELS = {
    "dell": {"poweredge r640": "dell-poweredge-r640", "r640": "dell-poweredge-r640"},
    "cisco": {"catalyst 9300 48p": "cisco-c9300-48p", "c9300 48p": "cisco-c9300-48p"},
    "juniper": {"ex4300 48p": "juniper-ex4300-48p"},
}


def local_device_artwork(vendor, model):
    raw_vendor, model_key = words(vendor), words(model)
    vendor_key = VENDOR_ALIASES.get(raw_vendor)
    # A manufacturer explicitly present in the model can supply a missing
    # vendor, but must never override a contradictory recorded vendor.
    if not raw_vendor:
        vendor_key = next((canonical for alias, canonical in VENDOR_ALIASES.items()
                           if model_key.startswith(alias + " ")), None)
    if not vendor_key:
        return None
    for alias in sorted(VENDOR_ALIASES, key=len, reverse=True):
        if VENDOR_ALIASES[alias] == vendor_key and model_key.startswith(alias + " "):
            model_key = model_key[len(alias):].strip()
            break
    return EXACT_MODELS.get(vendor_key, {}).get(model_key)


# More specific categories precede broad ones (storage server / console switch).
CATEGORIES = (
    ("patch-panel", "Patch panel", ("patch panel", "patchpanel", "fiber panel", "fibre panel", "odf")),
    ("pdu", "Power distribution unit", ("pdu", "power distribution", "power strip")),
    ("ups", "UPS / battery", ("ups", "uninterruptible power", "battery", "battery pack")),
    ("kvm", "KVM / console", ("kvm", "console server", "console switch", "terminal server")),
    ("firewall", "Firewall / security appliance", ("firewall", "security appliance", "utm")),
    ("load-balancer", "Load balancer", ("load balancer", "loadbalancer", "adc")),
    ("storage", "Storage array", ("storage", "san", "nas", "disk shelf", "disk enclosure")),
    ("blade", "Blade chassis", ("blade", "blade chassis", "chassis")),
    ("cooling", "Cooling unit", ("cooling", "fan tray", "rack fan", "air conditioner")),
    ("switch", "Network switch", ("switch", "switches")),
    ("router", "Router", ("router", "routers")),
    ("server", "Server", ("server", "servers", "compute", "hypervisor")),
    ("appliance", "Appliance", ("appliance", "tape library", "tape drive")),
)
FAMILIES = (
    ("server", r"\b(poweredge|proliant|thinksystem|primergy|supermicro|ucs c\d+)\b"),
    ("switch", r"\b(catalyst|nexus|c9300|ex4300|aruba|procurve)\b"),
    ("firewall", r"\b(fortigate|firepower|asa|palo alto|pa \d+)\b"),
    ("storage", r"\b(powerstore|powervault|netapp|pure storage|flasharray|unity|alletra)\b"),
    ("ups", r"\b(smart ups|symmetra|9px|9sx)\b"),
    ("load-balancer", r"\b(big ip|bigip)\b"),
)


def identify_equipment(ci_class, vendor=None, model=None, name=None, attributes=None):
    attributes = attributes if isinstance(attributes, dict) else {}
    roles = [attributes.get(key) for key in ("NetBox: Role", "NetBox: Device Role", "device_role", "role", "equipment_type")]
    sources = [("Recorded role", " ".join(words(role) for role in roles)), ("CI class", words(ci_class))]
    for source, value in sources:
        for kind, label, terms in CATEGORIES:
            if any(re.search(r"\b" + re.escape(term) + r"\b", value) for term in terms):
                return {"kind": kind, "label": label, "basis": source}
    exact = local_device_artwork(vendor, model)
    if exact:
        kind = "server" if exact.startswith("dell-") else "switch"
        return {"kind": kind, "label": next(label for key, label, _ in CATEGORIES if key == kind), "basis": "Exact model"}
    family = words(model)
    for kind, pattern in FAMILIES:
        if re.search(pattern, family):
            return {"kind": kind, "label": next(label for key, label, _ in CATEGORIES if key == kind), "basis": "Model family"}
    for kind, label, terms in CATEGORIES:
        if any(re.search(r"\b" + re.escape(term) + r"\b", words(name)) for term in terms):
            return {"kind": kind, "label": label, "basis": "Name hint"}
    return {"kind": "unknown", "label": "Unidentified equipment", "basis": "No recognized equipment metadata"}
