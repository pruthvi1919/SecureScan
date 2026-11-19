"""
The scan engine: fetches a website safely and runs every security check.

Every check returns a list of "finding" dicts with these keys:
    category, check_name, severity, passed, description, recommendation, compliance_ref
The view saves each one to the database as a Finding row.

Checks performed:
    1. Transport   - is the site served over HTTPS? does http:// redirect to https://?
    2. Certificate - is the SSL certificate trusted, how long until it expires, which TLS version?
    3. Headers     - are the 6 important security headers present?
    4. Disclosure  - do headers leak software names/versions?
    5. Cookies     - do cookies have the Secure, HttpOnly and SameSite flags?
"""
import re
import socket
import ssl
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from django.conf import settings

from .ssrf import UnsafeTargetError, validate_target

HIGH, MEDIUM, LOW, INFO = "high", "medium", "low", "info"
SEVERITY_PENALTY = {HIGH: 20, MEDIUM: 10, LOW: 5, INFO: 0}
MAX_REDIRECTS = 5
USER_AGENT = "SecureScan/1.0 (security configuration audit)"

# Compliance references (OWASP Top 10 2021 + PCI DSS v4.0)
OWASP_CRYPTO = "OWASP A02:2021 Cryptographic Failures"
OWASP_INJECTION = "OWASP A03:2021 Injection"
OWASP_MISCONFIG = "OWASP A05:2021 Security Misconfiguration"
OWASP_AUTH = "OWASP A07:2021 Identification and Authentication Failures"
PCI_CRYPTO = "PCI DSS v4.0 Req 4.2 (strong cryptography in transit)"
PCI_SECURE_CODE = "PCI DSS v4.0 Req 6.2.4 (prevent common software attacks)"
PCI_SECURE_CONFIG = "PCI DSS v4.0 Req 2.2 (secure system configuration)"


class ScanError(Exception):
    """The scan could not be completed (site unreachable, too many redirects, ...)."""


@dataclass
class ScanResult:
    final_url: str
    findings: list
    score: int
    grade: str


def make_finding(category, check_name, severity, passed, description,
                 recommendation="", compliance=()):
    return {
        "category": category,
        "check_name": check_name,
        "severity": severity,
        "passed": passed,
        "description": description,
        "recommendation": "" if passed else recommendation,
        "compliance_ref": "; ".join(compliance),
    }


def _timeout():
    return getattr(settings, "SCANNER_TIMEOUT", 8)


# ---------------------------------------------------------------------------
# Safe fetching
# ---------------------------------------------------------------------------
def safe_fetch(url, verify=True):
    """
    GET a URL and return (response, final_url).

    Redirects are followed MANUALLY so that every hop is re-checked by the SSRF
    filter - otherwise a public site could redirect us to http://127.0.0.1/.
    Only the headers are needed, so the body is never downloaded (stream=True).
    """
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        validate_target(current)
        response = requests.get(
            current,
            timeout=_timeout(),
            allow_redirects=False,
            verify=verify,
            stream=True,
            headers={"User-Agent": USER_AGENT},
        )
        response.close()
        if response.is_redirect:
            current = urljoin(current, response.headers["Location"])
            continue
        return response, current
    raise ScanError(f"Too many redirects (more than {MAX_REDIRECTS}).")


def _fetch(url, verify=True):
    """safe_fetch, but turns network errors into a friendly ScanError."""
    try:
        return safe_fetch(url, verify=verify)
    except requests.exceptions.SSLError:
        raise  # handled separately by run_scan
    except requests.RequestException as exc:
        raise ScanError("Could not connect to the website (timeout or connection refused).") from exc


# ---------------------------------------------------------------------------
# 1. Transport security
# ---------------------------------------------------------------------------
def check_https(is_https):
    if is_https:
        return [make_finding("transport", "HTTPS", HIGH, True, "Site is served over HTTPS.")]
    return [make_finding(
        "transport", "HTTPS", HIGH, False,
        "Site is served over plain HTTP, so passwords and session cookies can be read "
        "or modified by anyone on the network (e.g. public Wi-Fi).",
        "Install a TLS certificate (free from Let's Encrypt) and serve every page over HTTPS.",
        (OWASP_CRYPTO, PCI_CRYPTO),
    )]


def check_http_redirect(host):
    """Does http://host/ send visitors to the HTTPS version?"""
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    try:
        _, final_url = safe_fetch(f"http://{host}/")
    except (requests.RequestException, ScanError, UnsafeTargetError):
        return [make_finding(
            "transport", "HTTP to HTTPS redirect", INFO, True,
            "Plain HTTP (port 80) is not reachable, so there is nothing to redirect.",
        )]
    if urlparse(final_url).scheme == "https":
        return [make_finding(
            "transport", "HTTP to HTTPS redirect", MEDIUM, True,
            "Visiting http:// correctly redirects to https://.",
        )]
    return [make_finding(
        "transport", "HTTP to HTTPS redirect", MEDIUM, False,
        "Visiting http:// does not redirect to https://, so users who type the address "
        "without https:// stay on an unencrypted connection.",
        "Redirect all HTTP requests to HTTPS with a 301 (permanent) redirect.",
        (OWASP_CRYPTO, PCI_CRYPTO),
    )]


# ---------------------------------------------------------------------------
# 2. SSL/TLS certificate
# ---------------------------------------------------------------------------
def _name_field(cert_field):
    """Turn the certificate's issuer/subject tuple into a readable name."""
    parts = dict(item[0] for item in cert_field)
    return parts.get("organizationName") or parts.get("commonName", "unknown")


def check_certificate(host, port=443):
    context = ssl.create_default_context()  # verifies the chain and hostname
    try:
        with socket.create_connection((host, port), timeout=_timeout()) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                tls_version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        return [make_finding(
            "certificate", "Certificate validity", HIGH, False,
            f"The certificate is not trusted: {exc.verify_message}. Browsers will show a "
            "security warning and users may be trained to click through it.",
            "Use a certificate from a trusted CA that matches the hostname and has not expired.",
            (OWASP_CRYPTO, PCI_CRYPTO),
        )]
    except (ssl.SSLError, OSError):
        return [make_finding(
            "certificate", "TLS handshake", HIGH, False,
            "The TLS handshake failed. The server may only support outdated protocols "
            "(SSLv3 / TLS 1.0 / TLS 1.1) that modern clients reject.",
            "Enable TLS 1.2 and TLS 1.3 and disable SSLv3, TLS 1.0 and TLS 1.1.",
            (OWASP_CRYPTO, PCI_CRYPTO),
        )]

    findings = [make_finding(
        "certificate", "Certificate validity", HIGH, True,
        f"Certificate is valid and trusted. Issued to {_name_field(cert['subject'])} "
        f"by {_name_field(cert['issuer'])}.",
    )]

    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    days_left = (expires - datetime.now(timezone.utc)).days
    findings.append(make_finding(
        "certificate", "Certificate expiry", MEDIUM, days_left >= 30,
        f"Certificate expires in {days_left} days ({expires:%Y-%m-%d}).",
        "Renew the certificate now and automate renewal (e.g. certbot).",
        (PCI_CRYPTO,),
    ))

    findings.append(make_finding(
        "certificate", "TLS version", HIGH, tls_version in ("TLSv1.2", "TLSv1.3"),
        f"Connection negotiated {tls_version}.",
        "Use TLS 1.2 or TLS 1.3 only.",
        (OWASP_CRYPTO, PCI_CRYPTO),
    ))
    return findings


# ---------------------------------------------------------------------------
# 3. Security headers
# ---------------------------------------------------------------------------
SECURITY_HEADERS = [
    {
        "header": "Strict-Transport-Security",
        "severity": HIGH,
        "why": "HSTS tells browsers to ALWAYS use HTTPS for this site, which blocks "
               "SSL-stripping / downgrade attacks.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "compliance": (OWASP_CRYPTO, PCI_CRYPTO),
    },
    {
        "header": "Content-Security-Policy",
        "severity": MEDIUM,
        "why": "CSP limits which scripts and resources the page may load - the main "
               "second line of defence against Cross-Site Scripting (XSS).",
        "fix": "Define a policy, starting with: Content-Security-Policy: default-src 'self'",
        "compliance": (OWASP_INJECTION, PCI_SECURE_CODE),
    },
    {
        "header": "X-Frame-Options",
        "severity": MEDIUM,
        "why": "Stops other websites from loading this page inside an invisible iframe "
               "to trick users into clicking (clickjacking).",
        "fix": "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'none')",
        "compliance": (OWASP_MISCONFIG, PCI_SECURE_CODE),
    },
    {
        "header": "X-Content-Type-Options",
        "severity": LOW,
        "why": "Stops browsers from 'guessing' (MIME-sniffing) a file's type, e.g. running "
               "an uploaded text file as JavaScript.",
        "fix": "Add: X-Content-Type-Options: nosniff",
        "compliance": (OWASP_MISCONFIG, PCI_SECURE_CONFIG),
    },
    {
        "header": "Referrer-Policy",
        "severity": LOW,
        "why": "Controls how much of the current URL (which may contain tokens or IDs) "
               "is sent to other websites in the Referer header.",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "compliance": (OWASP_MISCONFIG, PCI_SECURE_CONFIG),
    },
    {
        "header": "Permissions-Policy",
        "severity": LOW,
        "why": "Switches off browser features the site does not need (camera, microphone, "
               "location), so injected scripts cannot abuse them.",
        "fix": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "compliance": (OWASP_MISCONFIG, PCI_SECURE_CONFIG),
    },
]


def check_security_headers(headers, is_https):
    lower = {k.lower(): v for k, v in headers.items()}
    findings = []
    for spec in SECURITY_HEADERS:
        name = spec["header"]
        value = lower.get(name.lower())
        passed = value is not None

        # Special cases
        if name == "Strict-Transport-Security" and not is_https:
            passed = False  # HSTS only works on HTTPS sites
        if name == "X-Frame-Options" and not passed:
            passed = "frame-ancestors" in lower.get("content-security-policy", "").lower()
        if name == "X-Content-Type-Options" and passed:
            passed = value.strip().lower() == "nosniff"

        if passed:
            shown = value if value is not None else "covered by CSP frame-ancestors"
            description = f"{name} is set: {shown[:200]}"
        elif value is not None:
            description = f"{name} has an incorrect value '{value[:100]}'. {spec['why']}"
        else:
            description = f"{name} header is missing. {spec['why']}"
        findings.append(make_finding(
            "headers", name, spec["severity"], passed, description, spec["fix"], spec["compliance"]
        ))
    return findings


# ---------------------------------------------------------------------------
# 4. Information disclosure
# ---------------------------------------------------------------------------
TECH_HEADERS = ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


def check_information_disclosure(headers):
    lower = {k.lower(): v for k, v in headers.items()}
    findings = []

    server = lower.get("server")
    if server and re.search(r"\d", server):
        findings.append(make_finding(
            "disclosure", "Server version", LOW, False,
            f"The Server header reveals the software version: '{server}'. Attackers use exact "
            "versions to look up known vulnerabilities (CVEs).",
            "Hide version numbers (nginx: server_tokens off; Apache: ServerTokens Prod).",
            (OWASP_MISCONFIG, PCI_SECURE_CONFIG),
        ))
    else:
        findings.append(make_finding(
            "disclosure", "Server version", LOW, True,
            "The Server header does not reveal a version number.",
        ))

    leaked = [(h, lower[h.lower()]) for h in TECH_HEADERS if h.lower() in lower]
    for header, value in leaked:
        findings.append(make_finding(
            "disclosure", header, LOW, False,
            f"The {header} header reveals backend technology: '{value}'.",
            f"Remove the {header} header in the web server or framework configuration.",
            (OWASP_MISCONFIG, PCI_SECURE_CONFIG),
        ))
    if not leaked:
        findings.append(make_finding(
            "disclosure", "Technology headers", LOW, True,
            "No X-Powered-By / X-AspNet-Version headers found.",
        ))
    return findings


# ---------------------------------------------------------------------------
# 5. Cookie security
# ---------------------------------------------------------------------------
def check_cookies(set_cookie_headers):
    if not set_cookie_headers:
        return [make_finding(
            "cookies", "Cookie flags", INFO, True, "No cookies were set on the first response.",
        )]
    findings = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        attributes = {part.split("=", 1)[0].strip().lower() for part in raw.split(";")[1:]}
        missing = [flag for flag in ("Secure", "HttpOnly", "SameSite")
                   if flag.lower() not in attributes]
        if missing:
            findings.append(make_finding(
                "cookies", f"Cookie '{name}'", MEDIUM, False,
                f"Cookie '{name}' is missing the {', '.join(missing)} flag(s).",
                "Secure = only sent over HTTPS; HttpOnly = JavaScript cannot read it "
                "(limits session theft via XSS); SameSite=Lax/Strict = not sent with "
                "cross-site requests (limits CSRF).",
                (OWASP_AUTH, PCI_SECURE_CODE),
            ))
        else:
            findings.append(make_finding(
                "cookies", f"Cookie '{name}'", MEDIUM, True,
                f"Cookie '{name}' has Secure, HttpOnly and SameSite set.",
            ))
    return findings


def _set_cookie_headers(response):
    """requests merges repeated Set-Cookie headers; read them one by one from urllib3."""
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        return raw_headers.getlist("Set-Cookie")
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


# ---------------------------------------------------------------------------
# Scoring and the main entry point
# ---------------------------------------------------------------------------
def calculate_score(findings):
    """Start at 100 and subtract points for every failed check."""
    score = 100 - sum(SEVERITY_PENALTY[f["severity"]] for f in findings if not f["passed"])
    score = max(score, 0)
    for threshold, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= threshold:
            return score, grade
    return score, "F"


def run_scan(url):
    """Run every check against a URL and return a ScanResult."""
    validate_target(url)

    try:
        response, final_url = _fetch(url)
    except requests.exceptions.SSLError:
        # The certificate is broken. check_certificate() will report that; fetch
        # again without verification so we can still audit the headers.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # hide urllib3's InsecureRequestWarning
            try:
                response, final_url = _fetch(url, verify=False)
            except requests.exceptions.SSLError as exc:
                raise ScanError("TLS handshake with the website failed.") from exc

    parsed = urlparse(final_url)
    is_https = parsed.scheme == "https"

    findings = []
    findings += check_https(is_https)
    findings += check_http_redirect(parsed.hostname)
    if is_https:
        findings += check_certificate(parsed.hostname, parsed.port or 443)
    findings += check_security_headers(response.headers, is_https)
    findings += check_information_disclosure(response.headers)
    findings += check_cookies(_set_cookie_headers(response))

    score, grade = calculate_score(findings)
    return ScanResult(final_url=final_url, findings=findings, score=score, grade=grade)
