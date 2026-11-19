"""
SSRF (Server-Side Request Forgery) protection.

Our server sends HTTP requests to URLs that users give us. Without checks, an
attacker could ask us to "scan" http://127.0.0.1:5432 (our own database) or
http://169.254.169.254/ (the cloud metadata service that holds server
credentials) and use OUR server to reach internal systems that are not exposed
to the internet.

So before EVERY request (including every redirect) we:
  1. allow only http:// and https://
  2. reject usernames/passwords inside the URL and non-standard ports
  3. resolve the hostname to IP addresses and reject anything that is not a
     public internet address (loopback, private, link-local, reserved ...)
"""
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {None, 80, 443}  # None = default port for the scheme


class UnsafeTargetError(ValueError):
    """Raised when a URL points somewhere we refuse to scan."""


def is_public_ip(ip_string):
    """True only for globally routable (public internet) IP addresses."""
    ip = ipaddress.ip_address(ip_string)
    # "::ffff:127.0.0.1" is an IPv4 address hidden inside IPv6 - unwrap it.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def validate_target(url):
    """Return the hostname if the URL is safe to scan, else raise UnsafeTargetError."""
    try:
        parsed = urlparse(url)
        port = parsed.port  # raises ValueError for things like ":abc"
    except ValueError:
        raise UnsafeTargetError("Malformed URL.")

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeTargetError("Only http:// and https:// URLs can be scanned.")
    if parsed.username or parsed.password:
        raise UnsafeTargetError("URLs containing credentials are not allowed.")
    if port not in ALLOWED_PORTS:
        raise UnsafeTargetError("Only the standard web ports (80 and 443) can be scanned.")

    host = parsed.hostname
    if not host:
        raise UnsafeTargetError("URL has no hostname.")

    try:
        addresses = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        raise UnsafeTargetError("Hostname could not be resolved.")

    for *_, sockaddr in addresses:
        try:
            public = is_public_ip(sockaddr[0])
        except ValueError:
            public = False
        if not public:
            raise UnsafeTargetError(
                "Target resolves to a private/internal IP address - blocked to prevent SSRF."
            )
    return host
