"""Who is on the other end of a request: real client address, device and location.

Behind Kubernetes the TCP peer is an ingress controller, a Cloudflare tunnel or
a node, so `REMOTE_ADDR` alone records an address shared by every user.
`ClientAddressMiddleware` replaces it with the real client address, using
forwarding headers only when the request actually came from a trusted proxy
(private/cluster ranges by default, plus Cloudflare's published edge ranges),
so a client that reaches the app directly cannot forge its address.

Browsers never reveal a computer's or phone's hostname. What is available is
recorded instead: a forward-confirmed reverse-DNS name for the real address
(meaningful on corporate networks whose DNS registers workstations), device
details from the User-Agent and User-Agent Client Hints, Cloudflare's visitor
location headers, and a device name the native app reports about itself.
"""
import ipaddress
import os
import re

# Private, loopback, link-local, carrier-grade NAT and unique-local ranges:
# where ingress controllers, tunnels, service meshes and nodes live.
PRIVATE_NETWORKS = (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10",
    "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
)
# Cloudflare's published edge ranges (https://www.cloudflare.com/ips/). An edge
# server appends the visitor's address to X-Forwarded-For before forwarding.
CLOUDFLARE_NETWORKS = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
)
CLIENT_HINT_HEADERS = (
    "Sec-CH-UA-Platform-Version", "Sec-CH-UA-Model", "Sec-CH-UA-Arch",
    "Sec-CH-UA-Bitness", "Sec-CH-UA-Full-Version-List",
)


def _networks(values):
    networks = []
    for value in values:
        value = value.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def _address(value):
    value = (value or "").strip().strip('"')
    if value.startswith("[") and "]" in value:  # [2001:db8::1]:443
        value = value[1:value.index("]")]
    elif value.count(":") == 1:  # 203.0.113.9:51234
        value = value.split(":", 1)[0]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


class ClientAddressMiddleware:
    """WSGI middleware: set REMOTE_ADDR to the real client address.

    Configuration (environment):
      TRUSTED_PROXY_CIDRS     extra proxy networks, comma separated
      TRUST_CLOUDFLARE_PROXY  treat Cloudflare edge ranges as proxies (default true)
      CLIENT_IP_HEADER        a header a trusted proxy sets to the client address
                              (e.g. CF-Connecting-IP when X-Forwarded-For is rewritten)
    """

    def __init__(self, app, environ_source=os.environ):
        self.app = app
        extra = environ_source.get("TRUSTED_PROXY_CIDRS", "").split(",")
        trusted = list(PRIVATE_NETWORKS) + extra
        if environ_source.get("TRUST_CLOUDFLARE_PROXY", "true").strip().lower() in {"1", "true", "yes", "on"}:
            trusted += list(CLOUDFLARE_NETWORKS)
        self.trusted = _networks(trusted)
        header = environ_source.get("CLIENT_IP_HEADER", "").strip()
        self.header_key = "HTTP_" + header.upper().replace("-", "_") if header else None

    def is_trusted(self, address):
        return address is not None and any(address in network for network in self.trusted)

    def client_address(self, environ):
        peer = _address(environ.get("REMOTE_ADDR"))
        if not self.is_trusted(peer):
            return peer
        if self.header_key:
            supplied = _address(environ.get(self.header_key))
            if supplied:
                return supplied
        # Right to left, skipping our own proxies: the first address we do not
        # control is the client. Entries left of it were supplied by the client.
        chain = [_address(item) for item in environ.get("HTTP_X_FORWARDED_FOR", "").split(",")]
        chain = [item for item in chain if item]
        for hop in reversed(chain):
            if not self.is_trusted(hop):
                return hop
        return chain[0] if chain else peer

    def __call__(self, environ, start_response):
        client = self.client_address(environ)
        if client is not None:
            environ["serviceops.proxy_peer"] = environ.get("REMOTE_ADDR")
            environ["REMOTE_ADDR"] = str(client)
        return self.app(environ, start_response)


# --- device and location ----------------------------------------------------

_BROWSERS = (("Edg/", "Microsoft Edge"), ("OPR/", "Opera"), ("SamsungBrowser/", "Samsung Internet"),
             ("Firefox/", "Firefox"), ("CriOS/", "Chrome"), ("FxiOS/", "Firefox"), ("Chrome/", "Chrome"),
             ("Version/", "Safari"))


def _browser(user_agent, hints):
    full = hints.get("Sec-CH-UA-Full-Version-List", "")
    for brand in ("Microsoft Edge", "Opera", "Google Chrome", "Chromium"):
        match = re.search(rf'"{re.escape(brand)}";v="(\d+)', full)
        if match:
            return f"{'Chrome' if brand in ('Google Chrome', 'Chromium') else brand} {match.group(1)}"
    for marker, label in _BROWSERS:
        match = re.search(re.escape(marker) + r"(\d+)", user_agent)
        if match:
            return f"{label} {match.group(1)}"
    return "Browser"


def _operating_system(user_agent, hints):
    platform_version = hints.get("Sec-CH-UA-Platform-Version", "").strip('"')
    if "Windows" in user_agent:
        major = int(platform_version.split(".")[0]) if platform_version[:1].isdigit() else 0
        if major >= 13:
            return "Windows 11"
        return "Windows 10" if "Windows NT 10" in user_agent else "Windows"
    match = re.search(r"Android (\d+(?:\.\d+)?)", user_agent)
    if match:
        return f"Android {platform_version.split('.')[0] or match.group(1)}"
    if "iPhone" in user_agent or "iPad" in user_agent:
        os_match = re.search(r"OS (\d+)[_.](\d+)", user_agent)
        if os_match:
            platform = "iOS" if "iPhone" in user_agent else "iPadOS"
            return f"{platform} {os_match.group(1)}.{os_match.group(2)}"
    match = re.search(r"Mac OS X (\d+)[_.](\d+)", user_agent)
    if match:
        return f"macOS {platform_version or match.group(1) + '.' + match.group(2)}".strip()
    if "CrOS" in user_agent:
        return "ChromeOS"
    if "Linux" in user_agent:
        return "Linux"
    return "Unknown OS"


def describe_device(headers):
    """A readable, user-specific device label, e.g. "Chrome 141 on Windows 11
    (x86 64-bit)" or "Chrome 141 on Android 15 · Pixel 8"."""
    user_agent = headers.get("User-Agent", "") or ""
    hints = {name: headers.get(name, "") or "" for name in CLIENT_HINT_HEADERS}
    label = f"{_browser(user_agent, hints)} on {_operating_system(user_agent, hints)}"
    model = hints["Sec-CH-UA-Model"].strip('"')
    if not model:
        if "Android " in user_agent and "; " in user_agent:
            segment = user_agent.split("Android ", 1)[1].split(")", 1)[0]
            parts = segment.split("; ", 1)
            if len(parts) == 2:
                candidate = parts[1].split(" Build/", 1)[0].strip()
                if candidate not in {"K", "wv"}:
                    model = candidate
        elif "iPhone" in user_agent:
            model = "iPhone"
        elif "iPad" in user_agent:
            model = "iPad"
    arch = hints["Sec-CH-UA-Arch"].strip('"')
    bitness = hints["Sec-CH-UA-Bitness"].strip('"')
    if arch and not model:
        label += f" ({arch}{' ' + bitness + '-bit' if bitness else ''})"
    if model:
        label += f" · {model}"
    reported = (headers.get("X-Device-Name", "") or "").strip()
    if reported:
        # Sent by the native app about itself; useful, but not verifiable.
        label += f" · reported as {re.sub(r'[^A-Za-z0-9 ._()&-]', '', reported)[:60]}"
    return label[:160]


def client_location(headers):
    """Visitor location from Cloudflare headers, e.g. "Tokyo, 13, JP" ("JP" with
    only the default CF-IPCountry; city/region need Cloudflare's "Add visitor
    location headers" managed transform)."""
    country = (headers.get("CF-IPCountry", "") or "").strip().upper()
    if country in {"", "XX", "T1"}:  # unknown / Tor
        country = ""
    parts = [(headers.get(name, "") or "").strip() for name in ("CF-IPCity", "CF-Region-Code")]
    parts = [part for part in parts if part] + ([country] if country else [])
    return ", ".join(parts)[:120] or None
