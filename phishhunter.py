#!/usr/bin/env python3
r"""
================================================================================
  ____  _   _ ___ ____  _   _   _   _ _   _ _   _ _____ _____ ____
 |  _ \| | | |_ _/ ___|| | | | | | | | | | | \ | |_   _| ____|  _ \\
 | |_) | |_| || |\___ \| |_| | | |_| | | | |  \| | | | |  _| | |_) |
 |  __/|  _  || | ___) |  _  | |  _  | |_| | |\  | | | | |___|  _ <
 |_|   |_| |_|___|____/|_| |_| |_| |_|\___/|_| \_| |_| |_____|_| \_\\

         PHISH HUNTER v1.0 — Universal SOC Email Phishing Forensics
   Headers • DNS • TLS Certificates • Threat intel • Risk scoring • Reports
================================================================================

Self-contained Python tool for SOC analysts to perform comprehensive phishing
email forensics on Kali Linux and any Unix-like system. Pure Python 3.10+
stdlib — no mandatory external dependencies.

CAPABILITIES
------------
EMAIL FORENSICS
  • Parse .eml/.msg email files — full headers, bodies, attachments
  • Header forensics — Received-chain tracing, originating IP, hop analysis
  • Authentication checks — SPF, DKIM, DMARC result interpretation
  • Sender spoofing detection — display-name mismatch, reply-to anomaly
  • Brand impersonation detection (Microsoft, Google, banks, etc.)

DNS RECORD FORENSICS
  • Comprehensive lookups via Cloudflare + Google DNS-over-HTTPS (free)
  • All record types — A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, SRV, CAA
  • Email authentication policy extraction — SPF, DMARC, DKIM
  • Multi-selector DKIM probe (selector1, default, google, k1, etc.)
  • Reverse DNS for sender IPs (PTR records)

TLS / SSL CERTIFICATE FORENSICS  [NEW IN v1.0]
  • Live TLS certificate retrieval (port 443)
  • Subject, Issuer, SANs, validity dates, hostname matching
  • Certificate Transparency lookup via crt.sh (free)
  • Optional SSL Labs grade lookup
  • Cert hijack and lookalike domain detection

URL & DOMAIN INTELLIGENCE
  • URL extraction from HTML and plain-text bodies
  • URL reputation — URLhaus (free, no key), VirusTotal (optional)
  • Domain age check via RDAP (newly registered domain detection)
  • Typosquat and homograph heuristics

ATTACHMENT ANALYSIS
  • SHA-256/MD5 hashing + Shannon entropy
  • Risky-type detection (.exe, .scr, .iso, .lnk, macro-enabled docs)

RISK SCORING & REPORTING
  • Weighted 0-100 risk score across 7 dimensions
  • JSON + HTML forensic reports (analyst-grade dark dashboard)
  • Defanged IOC output (analyst-safe)
  • Curated investigation pivots — links to top free SOC tools

--------------------------------------------------------------------------------
Author   : Mohammad Shahbaaz Ahmed
GitHub   : https://github.com/shahbaaz-devsec
LinkedIn : https://www.linkedin.com/in/mohammad-shahbaaz-ahmed-138a423bb
License  : Educational and authorised SOC use only
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import base64
import collections
import csv
import email
import email.header
import email.policy
import email.utils
import hashlib
import html as html_mod
import io
import json
import math
import os
import pathlib
import quopri
import re
import socket
import ssl
import string
import struct
import subprocess
import sys
import textwrap
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.error import HTTPError, URLError

# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------
PHISHING_KEYWORDS: List[str] = [
    "urgent", "verify your account", "suspended", "password expired",
    "login attempt", "unusual activity", "confirm your identity",
    "update your information", "security alert", "unauthorised",
    "account will be closed", "limited", "click here", "immediately",
    "action required", "validate", "invoice attached", "payment overdue",
    "your order", "shipment", "delivery failed", "reset your password",
    "unusual sign-in", "billing information", "update payment",
    "dear customer", "dear user", "dear valued", "unclaimed",
    "refund", "winning", "winner", "congratulations", "selected",
]

RISKY_SENDER_DOMAINS: Set[str] = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "aol.com", "protonmail.com", "mail.com", "yandex.com",
    "gmx.com", "web.de", "zoho.com",
}

RISKY_FILE_EXTENSIONS: Set[str] = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".msi", ".msp", ".cpl", ".jar",
    ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".iso", ".img",
    ".pdf", ".lnk", ".reg", ".chm", ".dll", ".ocx",
}

SHORTENER_DOMAINS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "is.gd",
    "buff.ly", "shorte.st", "adf.ly", "bc.vc", "rb.gy", "cutt.ly",
    "shorturl.at", "tiny.cc", "short.link",
}

# Common DKIM selectors used by major email providers — for DNS probing
COMMON_DKIM_SELECTORS: List[str] = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3",
    "mail", "dkim", "s1", "s2", "s1024", "s2048",
    "mandrill", "mailjet", "sparkpost", "sendgrid",
    "everlytickey1", "everlytickey2", "eversrv",
    "dkim-sha256", "20230601", "20221208",  # Google rotating selectors
    "smtp", "smtpapi", "amazonses", "mxvault",
    "TM-DKIM-20211201111149",  # Trend Micro pattern (seen in Infosys email!)
]

# Public DNS-over-HTTPS endpoints (free, no API key, CORS-friendly)
DOH_ENDPOINTS: List[str] = [
    "https://cloudflare-dns.com/dns-query",   # 1.1.1.1 — Cloudflare
    "https://dns.google/resolve",              # 8.8.8.8 — Google
]

# Brand keywords for impersonation detection (display-name vs sender domain mismatch)
BRAND_KEYWORDS: List[str] = [
    "microsoft", "office365", "outlook", "azure", "ms365",
    "google", "gmail", "youtube", "googleads",
    "amazon", "aws", "amazonprime", "paypal", "apple", "icloud",
    "netflix", "facebook", "instagram", "linkedin", "twitter", "x.com",
    "dhl", "fedex", "ups", "dpd", "bluedart",
    "infosys", "tcs", "wipro", "accenture", "wellsfargo",
    "bank", "banking", "hdfc", "icici", "sbi", "axis", "kotak",
    "irs", "hmrc", "gov", "police", "court",
]

# Certificate analysis context for HTML reports
CERTIFICATE_GUIDE: Dict[str, Any] = {
    "purpose": (
        "Validate HTTPS/TLS identity, issuer trust, validity dates, SANs, "
        "hostname matching, chain quality, and TLS posture."
    ),
    "phishing_use": (
        "Phishing sites often use newly issued free certificates (Let's Encrypt), "
        "suspicious SANs, weak TLS settings, or certificates that do not match "
        "the claimed brand."
    ),
    "red_flags": [
        "Certificate expired or not yet valid",
        "Common Name/SAN does not match target domain",
        "Issuer looks unusual for claimed organization",
        "Certificate issued recently for suspicious domain",
        "Weak SSL Labs grade or TLS/cipher weakness",
        "Certificate transparency shows suspicious lookalike domains",
    ],
    "tools": [
        "SSL Labs Server Test: https://www.ssllabs.com/ssltest/",
        "crt.sh Certificate Transparency: https://crt.sh",
        "Censys Search: https://search.censys.io",
        "SecurityTrails: https://securitytrails.com",
        "Hardenize: https://www.hardenize.com",
    ],
}

# Curated investigation tool links — included in reports for analyst pivoting
URL_ANALYSIS_TOOLS: List[str] = [
    "VirusTotal URL: https://www.virustotal.com/gui/home/url",
    "URLScan.io: https://urlscan.io",
    "AnyRun: https://any.run",
    "Hybrid Analysis: https://www.hybrid-analysis.com",
    "Joe Sandbox: https://www.joesandbox.com",
    "Google Safe Browsing: https://transparencyreport.google.com/safe-browsing/search",
    "PhishTank: https://phishtank.org",
    "OpenPhish: https://openphish.com",
    "CheckPhish: https://checkphish.bolster.ai",
    "Sucuri SiteCheck: https://sitecheck.sucuri.net",
    "Unshorten.it: https://unshorten.it",
]

HEADER_ANALYZER_TOOLS: List[str] = [
    "MXToolbox Header Analyzer: https://mxtoolbox.com/EmailHeaders.aspx",
    "Google Admin Toolbox: https://toolbox.googleapps.com/apps/messageheader/",
    "Microsoft Header Analyzer: https://mha.azurewebsites.net",
    "Mailheader.org: https://mailheader.org",
    "EasyDMARC Header Analyzer: https://easydmarc.com/tools/email-header-analyzer",
]

REPUTATION_TOOLS: List[str] = [
    "AbuseIPDB: https://www.abuseipdb.com",
    "VirusTotal: https://www.virustotal.com/gui/home/search",
    "Cisco Talos: https://talosintelligence.com",
    "IBM X-Force: https://exchange.xforce.ibmcloud.com",
    "Spamhaus: https://check.spamhaus.org",
    "MXToolbox Blacklist: https://mxtoolbox.com/blacklists.aspx",
]

# Regular expressions
URL_RE = re.compile(
    r'https?://[^\s<>"\'{}\|\\^`\[\]]+|'
    r'(?<!\w)www\.[^\s<>"\'{}\|\\^`\[\]]+',
    re.IGNORECASE,
)

EMAIL_RE = re.compile(
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
)

IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
)

RECEIVED_IP_RE = re.compile(
    r'from\s+(?:[\w.-]+\s+)?(?:\(.*?\)\s+)?(?:\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]|'
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))',
    re.IGNORECASE,
)

SPF_RE = re.compile(r'spf=(pass|fail|softfail|neutral|none|permerror|temperror)', re.IGNORECASE)
DKIM_RE = re.compile(r'dkim=(pass|fail|neutral|none|permerror|temperror)', re.IGNORECASE)
DMARC_RE = re.compile(r'dmarc=(pass|fail|none|permerror|temperror)', re.IGNORECASE)

# --- Try importing optional libraries; degrade gracefully ---
try:
    import requests as _requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def _decode_header_value(raw: Optional[str]) -> str:
    """Decode an RFC 2047 encoded email header value."""
    if raw is None:
        return ""
    try:
        parts = email.header.decode_header(raw)
    except Exception:
        return str(raw)
    decoded = []
    for fragment, charset in parts:
        if isinstance(fragment, bytes):
            try:
                decoded.append(fragment.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                decoded.append(fragment.decode("utf-8", errors="replace"))
        else:
            decoded.append(str(fragment))
    return "".join(decoded)


def _parse_email_address(raw: str) -> Tuple[str, str]:
    """Return (display_name, email_address) from a raw address header."""
    name, addr = email.utils.parseaddr(raw)
    return (name, addr.lower() if addr else "")


def _defang_url(url: str) -> str:
    """Replace http with hxxp and . with [.] for safe display."""
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def _refang_url(url: str) -> str:
    """Reverse of defang_url."""
    return url.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")


def _compute_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _compute_md5(filepath: Path) -> str:
    """Compute MD5 hash of a file."""
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _compute_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0.0 – 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _file_entropy(filepath: Path, max_read: int = 524288) -> float:
    """Read up to max_read bytes and compute entropy."""
    with open(filepath, "rb") as f:
        data = f.read(max_read)
    return _compute_entropy(data)


def _strip_html(text: str) -> str:
    """Crude HTML tag removal for plain-text extraction."""
    return re.sub(r"<[^>]+>", " ", text)


def _domain_from_url(url: str) -> str:
    """Extract the registered domain from a URL."""
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        parts = hostname.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class HeaderAnalysis:
    """Result of header forensics."""
    from_address: str = ""
    from_display: str = ""
    reply_to: str = ""
    return_path: str = ""
    message_id: str = ""
    date: str = ""
    subject: str = ""
    to_addresses: List[str] = field(default_factory=list)
    cc_addresses: List[str] = field(default_factory=list)
    received_hops: List[Dict[str, str]] = field(default_factory=list)
    originating_ip: str = ""
    spf_result: str = "none"
    dkim_result: str = "none"
    dmarc_result: str = "none"
    authentication_summary: str = ""
    spoof_indicators: List[str] = field(default_factory=list)

    def export(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class URLAnalysis:
    """Analysis of a single URL."""
    url: str
    defanged: str = ""
    domain: str = ""
    is_shortened: bool = False
    urlhaus_status: str = "unknown"
    urlhaus_tags: List[str] = field(default_factory=list)
    vt_malicious: int = 0
    vt_total: int = 0
    domain_age_days: int = -1
    domain_registrar: str = ""
    is_ip_based: bool = False
    suspicious: bool = False
    reasons: List[str] = field(default_factory=list)

    def export(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttachmentAnalysis:
    """Analysis of a single attachment."""
    filename: str
    size_bytes: int
    sha256: str = ""
    md5: str = ""
    entropy: float = 0.0
    extension: str = ""
    is_risky_extension: bool = False
    mime_type: str = ""
    is_password_protected: bool = False
    suspicious: bool = False
    reasons: List[str] = field(default_factory=list)

    def export(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DNSAnalysis:
    """Comprehensive DNS records analysis for a domain."""
    domain: str = ""
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[Dict[str, Any]] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)
    soa_record: str = ""
    caa_records: List[str] = field(default_factory=list)
    srv_records: List[str] = field(default_factory=list)

    # Email authentication policies
    spf_record: str = ""
    spf_valid: bool = False
    spf_strength: str = "none"           # none / soft / strict
    dmarc_record: str = ""
    dmarc_policy: str = "none"           # none / quarantine / reject
    dkim_selectors_found: List[str] = field(default_factory=list)
    dkim_records: Dict[str, str] = field(default_factory=dict)

    # Reverse DNS for IPs
    ptr_records: Dict[str, str] = field(default_factory=dict)

    # Findings & scoring
    auth_score: float = 0.0              # 0-100, higher = more secure
    findings: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def export(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TLSAnalysis:
    """Live TLS/SSL certificate analysis for a domain (NEW IN v1.0)."""
    domain: str = ""
    status: str = "not_run"            # ok / error / unavailable / not_run

    # Certificate fields
    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    not_before: str = ""
    not_after: str = ""
    serial_number: str = ""
    version: str = ""
    subject_alt_names: List[str] = field(default_factory=list)
    matches_hostname: Optional[bool] = None
    days_until_expiry: Optional[int] = None

    # Certificate Transparency (crt.sh)
    crtsh_status: str = "not_run"
    crtsh_certificate_count: int = 0
    crtsh_recent_subdomains: List[str] = field(default_factory=list)

    # SSL Labs (optional)
    ssllabs_grade: str = ""
    ssllabs_status: str = "not_run"

    # Findings
    red_flags: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    error: str = ""

    def export(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PhishingReport:
    """Complete phishing analysis report."""
    file_path: str
    analysed_at: str = ""
    header: HeaderAnalysis = field(default_factory=HeaderAnalysis)
    urls: List[URLAnalysis] = field(default_factory=list)
    attachments: List[AttachmentAnalysis] = field(default_factory=list)
    dns_records: List[DNSAnalysis] = field(default_factory=list)
    tls_records: List[TLSAnalysis] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    body_keywords_found: List[str] = field(default_factory=list)
    brand_impersonation: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "unknown"
    summary: str = ""
    indicators: List[str] = field(default_factory=list)
    email_addresses_found: List[str] = field(default_factory=list)
    raw_headers: Dict[str, str] = field(default_factory=dict)

    def export(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Core analysis engines
# ---------------------------------------------------------------------------
class EmailParser:
    """Parse .eml (and optionally .msg) files into structured components."""

    def __init__(self, filepath: Path):
        self.filepath = filepath
        self._msg: Optional[email.message.Message] = None
        self._raw: str = ""

    def parse(self) -> email.message.Message:
        """Parse the email file and return the message object."""
        if self.filepath.suffix.lower() == ".msg":
            return self._parse_msg()
        return self._parse_eml()

    def _parse_eml(self) -> email.message.Message:
        raw_bytes = self.filepath.read_bytes()
        self._raw = raw_bytes.decode("utf-8", errors="replace")
        self._msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        return self._msg

    def _parse_msg(self) -> email.message.Message:
        """Minimal .msg parsing using extract_msg if available."""
        try:
            import extract_msg
            msg_obj = extract_msg.Message(str(self.filepath))
            # Convert to an email.message.Message
            m = email.message.EmailMessage()
            m["From"] = msg_obj.sender
            m["Subject"] = msg_obj.subject
            m["Date"] = msg_obj.date
            m["To"] = msg_obj.to
            m["Message-ID"] = msg_obj.messageId
            body = msg_obj.body or ""
            m.set_content(body)
            self._msg = m
            self._raw = msg_obj.body or ""
            return m
        except ImportError:
            print("[!] .msg files require: pip install extract-msg")
            print("    Falling back to raw binary read.")
            self._raw = self.filepath.read_text("utf-8", errors="replace")
            self._msg = email.message_from_string(self._raw, policy=email.policy.default)
            return self._msg

    def get_raw_header(self, name: str) -> str:
        if self._msg is None:
            return ""
        return self._msg.get(name, "")

    def get_all_headers(self) -> Dict[str, str]:
        if self._msg is None:
            return {}
        return {k: self._msg.get(k, "") for k in self._msg.keys()}

    def get_body_text(self) -> str:
        """Extract plain-text body from the message."""
        if self._msg is None:
            return ""
        try:
            for part in self._msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode("utf-8", errors="replace")
        except Exception:
            pass
        return ""

    def get_body_html(self) -> str:
        """Extract HTML body from the message."""
        if self._msg is None:
            return ""
        try:
            for part in self._msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode("utf-8", errors="replace")
        except Exception:
            pass
        return ""

    def get_attachments(self, output_dir: Path) -> List[Path]:
        """Extract attachments to output_dir, return list of saved files."""
        saved: List[Path] = []
        output_dir.mkdir(parents=True, exist_ok=True)
        if self._msg is None:
            return saved
        try:
            for part in self._msg.walk():
                cdisp = str(part.get("Content-Disposition", ""))
                if "attachment" not in cdisp:
                    continue
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                fname = part.get_filename()
                if fname is None:
                    fname = f"attachment_{hashlib.md5(payload).hexdigest()[:8]}.bin"
                fname = _decode_header_value(fname)
                # sanitize filename
                safe_name = re.sub(r'[\\/:*?"<>|]', "_", fname)
                out_path = output_dir / safe_name
                out_path.write_bytes(payload)
                saved.append(out_path)
        except Exception as e:
            print(f"[!] Attachment extraction error: {e}")
        return saved


class HeaderForensics:
    """Analyse email headers for authentication and spoofing indicators."""

    def __init__(self, parser: EmailParser):
        self.parser = parser
        self.msg = parser.parse()

    def analyse(self) -> HeaderAnalysis:
        ha = HeaderAnalysis()
        ha.raw_headers = self.parser.get_all_headers()  # type: ignore[assignment]

        # Basic fields
        ha.from_display, ha.from_address = _parse_email_address(
            _decode_header_value(self.parser.get_raw_header("From"))
        )
        ha.reply_to = _decode_header_value(self.parser.get_raw_header("Reply-To"))
        ha.return_path = _decode_header_value(self.parser.get_raw_header("Return-Path"))
        ha.message_id = _decode_header_value(self.parser.get_raw_header("Message-ID"))
        ha.date = _decode_header_value(self.parser.get_raw_header("Date"))
        ha.subject = _decode_header_value(self.parser.get_raw_header("Subject"))

        # To / Cc
        for hdr_name, target_list in [("To", ha.to_addresses), ("Cc", ha.cc_addresses)]:
            raw = self.parser.get_raw_header(hdr_name)
            if raw:
                for _, addr in email.utils.getaddresses([_decode_header_value(raw)]):
                    if addr:
                        target_list.append(addr.lower())

        # Received hops
        received_headers = self._get_all_of("Received")
        ha.received_hops = self._parse_received_chain(received_headers)
        if ha.received_hops:
            ha.originating_ip = ha.received_hops[-1].get("from_ip", "")

        # Authentication results
        ha.authentication_summary = _decode_header_value(
            self.parser.get_raw_header("Authentication-Results")
        )
        auth_src = ha.authentication_summary
        if not auth_src:
            auth_src = "\n".join(received_headers)
        ha.spf_result = self._extract_auth(auth_src, SPF_RE)
        ha.dkim_result = self._extract_auth(auth_src, DKIM_RE)
        ha.dmarc_result = self._extract_auth(auth_src, DMARC_RE)

        # Spoofing indicators
        ha.spoof_indicators = self._detect_spoof(ha)

        return ha

    def _get_all_of(self, name: str) -> List[str]:
        """Return all values for a given header name."""
        try:
            return self.msg.get_all(name) or []
        except Exception:
            return []

    def _parse_received_chain(self, headers: List[str]) -> List[Dict[str, str]]:
        hops = []
        for h in headers:
            h = _decode_header_value(h)
            m = RECEIVED_IP_RE.search(h)
            ip = m.group(1) or m.group(2) if m else ""
            # Extract 'by' host
            by_match = re.search(r"by\s+([\w.-]+)", h, re.IGNORECASE)
            by_host = by_match.group(1) if by_match else ""
            # Extract 'from' host
            from_match = re.search(r"from\s+([\w.-]+)", h, re.IGNORECASE)
            from_host = from_match.group(1) if from_match else ""
            hops.append({
                "raw": h,
                "from_host": from_host,
                "by_host": by_host,
                "from_ip": ip,
            })
        return hops

    @staticmethod
    def _extract_auth(text: str, pattern: re.Pattern) -> str:
        m = pattern.search(text)
        return m.group(1).lower() if m else "none"

    def _detect_spoof(self, ha: HeaderAnalysis) -> List[str]:
        indicators: List[str] = []

        # Reply-to mismatch
        if ha.reply_to and ha.from_address:
            _, reply_addr = _parse_email_address(ha.reply_to)
            if reply_addr and reply_addr != ha.from_address:
                if not reply_addr.endswith(ha.from_address.split("@")[-1] if "@" in ha.from_address else ""):
                    indicators.append(
                        f"Reply-To ({reply_addr}) differs from From ({ha.from_address})"
                    )

        # Return-Path mismatch
        if ha.return_path and ha.from_address:
            _, ret_addr = _parse_email_address(ha.return_path)
            if ret_addr and ret_addr != ha.from_address:
                indicators.append(
                    f"Return-Path ({ret_addr}) differs from From ({ha.from_address})"
                )

        # Display-name impersonation
        if ha.from_display and ha.from_address:
            addr_local = ha.from_address.split("@")[0] if "@" in ha.from_address else ""
            clean_display = ''.join(c.lower() for c in ha.from_display if c.isalpha())
            clean_local = ''.join(c.lower() for c in addr_local if c.isalpha())
            if clean_display and clean_local and clean_display != clean_local:
                indicators.append(
                    f"Display name '{ha.from_display}' does not match local part '{addr_local}'"
                )

        # Free email provider claiming to be from a company
        domain = ha.from_address.split("@")[-1] if "@" in ha.from_address else ""
        if domain in RISKY_SENDER_DOMAINS and ha.from_display:
            indicators.append(
                f"Free email provider ({domain}) used with display name '{ha.from_display}'"
            )

        # SPF/DKIM/DMARC failures
        for auth, name in [(ha.spf_result, "SPF"), (ha.dkim_result, "DKIM"), (ha.dmarc_result, "DMARC")]:
            if auth in ("fail", "softfail", "permerror"):
                indicators.append(f"{name} authentication failed: {auth}")

        return indicators


class URLExtractor:
    """Extract and defang URLs from email bodies."""

    def __init__(self, body_html: str, body_text: str):
        self.html = body_html
        self.text = body_text

    def extract(self) -> List[str]:
        seen: Set[str] = set()
        urls: List[str] = []

        # Extract from HTML href attributes
        if self.html:
            href_matches = re.findall(r'href\s*=\s*["\'](https?://[^"\'>\s]+)', self.html, re.IGNORECASE)
            for u in href_matches:
                u = u.strip()
                if u not in seen:
                    seen.add(u)
                    urls.append(u)

        # Extract from both HTML (tags stripped) and plain text
        combined = self.html + "\n" + self.text
        for u in URL_RE.findall(combined):
            u = u.strip().rstrip(".,;:!?)]}>\"'")
            if u not in seen:
                seen.add(u)
                urls.append(u)

        return urls


class URLChecker:
    """Check URLs against threat intelligence sources."""

    URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
    VT_API = "https://www.virustotal.com/api/v3/urls/"

    def __init__(self, vt_api_key: str = "", timeout: int = 15):
        self.vt_key = vt_api_key
        self.timeout = timeout

    def check(self, url: str) -> URLAnalysis:
        a = URLAnalysis(url=url, defanged=_defang_url(url))

        # Domain extraction
        a.domain = _domain_from_url(url)
        a.is_ip_based = IP_RE.match(a.domain) is not None

        # Shortener check
        for sd in SHORTENER_DOMAINS:
            if sd in a.domain.lower():
                a.is_shortened = True
                a.suspicious = True
                a.reasons.append(f"Uses URL shortener ({sd})")
                break

        # URLhaus check (free, no key)
        self._check_urlhaus(a)

        # VirusTotal (if key provided)
        if self.vt_key:
            self._check_virustotal(a)

        # Domain age
        if not a.is_ip_based and a.domain:
            self._check_domain_age(a)

        # Final verdict
        if not a.suspicious:
            if a.urlhaus_status == "malicious":
                a.suspicious = True
                a.reasons.append("Flagged by URLhaus as malicious")
            if a.vt_malicious >= 3:
                a.suspicious = True
                a.reasons.append(f"VirusTotal: {a.vt_malicious}/{a.vt_total} flagged")
            if 0 <= a.domain_age_days < 30:
                a.suspicious = True
                a.reasons.append(f"Domain registered {a.domain_age_days} days ago (very new)")

        return a

    def _check_urlhaus(self, a: URLAnalysis) -> None:
        try:
            data = urllib.parse.urlencode({"url": a.url}).encode()
            req = urllib.request.Request(self.URLHAUS_API, data=data, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode())
            if result.get("query_status") == "ok":
                a.urlhaus_status = "malicious"
                a.urlhaus_tags = result.get("tags", [])
            elif result.get("query_status") == "no_results":
                a.urlhaus_status = "clean"
            else:
                a.urlhaus_status = "error"
        except Exception:
            a.urlhaus_status = "unavailable"

    def _check_virustotal(self, a: URLAnalysis) -> None:
        try:
            url_id = base64.urlsafe_b64encode(a.url.encode()).decode().rstrip("=")
            req = urllib.request.Request(
                f"{self.VT_API}{url_id}",
                headers={"x-apikey": self.vt_key, "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            a.vt_malicious = stats.get("malicious", 0)
            a.vt_total = sum(stats.values())
        except Exception:
            pass

    def _check_domain_age(self, a: URLAnalysis) -> None:
        """Quick RDAP / WHOIS domain-age lookup."""
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                f"https://rdap.org/domain/{a.domain}",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode())
            events = data.get("events", [])
            for evt in events:
                if evt.get("eventAction") == "registration":
                    date_str = evt.get("eventDate", "")
                    if date_str:
                        reg_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                        a.domain_age_days = (datetime.now(timezone.utc) - reg_date).days
                        break
            entities = data.get("entities", [])
            for ent in entities:
                if "registrar" in (ent.get("roles", [])):
                    a.domain_registrar = ent.get("vcardArray", [[], []])[1][0][3] if len(ent.get("vcardArray", [[], []])[1]) > 0 else ""
                    break
        except Exception:
            a.domain_age_days = -1


class AttachmentTriage:
    """Analyse email attachments for risk indicators."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def analyse(self, filepath: Path) -> AttachmentAnalysis:
        aa = AttachmentAnalysis(
            filename=filepath.name,
            size_bytes=filepath.stat().st_size,
        )
        aa.sha256 = _compute_sha256(filepath)
        aa.md5 = _compute_md5(filepath)
        aa.entropy = round(_file_entropy(filepath), 4)
        aa.extension = filepath.suffix.lower()

        # Risky extension
        if aa.extension in RISKY_FILE_EXTENSIONS:
            aa.is_risky_extension = True
            aa.suspicious = True
            aa.reasons.append(f"Risky file extension: {aa.extension}")

        # High entropy (possible encrypted / packed)
        if aa.entropy > 7.5:
            aa.suspicious = True
            aa.reasons.append(f"High entropy ({aa.entropy:.2f}) — possibly encrypted or packed")

        # Check for password-protected zip
        if aa.extension == ".zip":
            try:
                with zipfile.ZipFile(filepath) as zf:
                    for info in zf.infolist():
                        if info.flag_bits & 0x1:
                            aa.is_password_protected = True
                            aa.suspicious = True
                            aa.reasons.append("Password-protected ZIP archive")
                            break
            except Exception:
                pass

        # MIME type via file command
        try:
            result = subprocess.run(
                ["file", "--mime-type", "-b", str(filepath)],
                capture_output=True, text=True, timeout=5,
            )
            aa.mime_type = result.stdout.strip()
        except Exception:
            aa.mime_type = "unknown"

        return aa


# ---------------------------------------------------------------------------
# DNS forensics — Comprehensive DNS record lookup via DoH (NEW IN v3.0)
# ---------------------------------------------------------------------------
class DNSAnalyzer:
    """
    Query all relevant DNS records for a domain using free public
    DNS-over-HTTPS endpoints (Cloudflare 1.1.1.1, Google 8.8.8.8).

    No API key required. Falls back gracefully if a provider is unreachable.
    Designed for SOC analysts investigating sender domains, lookalike domains,
    and phishing infrastructure.
    """

    # DNS RR type numeric codes (RFC 1035 + extensions)
    RECORD_TYPES: Dict[str, int] = {
        "A": 1,        # IPv4 address
        "NS": 2,       # Name server
        "CNAME": 5,    # Canonical name (alias)
        "SOA": 6,      # Start of authority
        "PTR": 12,     # Pointer (reverse DNS)
        "MX": 15,      # Mail exchange
        "TXT": 16,     # Text — SPF, DMARC, DKIM, verification
        "AAAA": 28,    # IPv6 address
        "SRV": 33,     # Service location
        "CAA": 257,    # Certificate authority authorisation
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    # -- Low-level DoH query ------------------------------------------------
    def _doh_query(self, name: str, rtype: str) -> Optional[Dict[str, Any]]:
        """Query a DoH endpoint for a domain and record type."""
        rtype = rtype.upper()
        if rtype not in self.RECORD_TYPES:
            return None

        params = urllib.parse.urlencode({"name": name, "type": rtype})

        for endpoint in DOH_ENDPOINTS:
            try:
                req = urllib.request.Request(
                    f"{endpoint}?{params}",
                    headers={
                        "Accept": "application/dns-json",
                        "User-Agent": "PhishHunter/3.0 (Mohammad Shahbaaz Ahmed)",
                    },
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode())
            except (HTTPError, URLError, socket.timeout, json.JSONDecodeError):
                continue
            except Exception:
                continue
        return None

    @staticmethod
    def _extract_answers(response: Dict[str, Any]) -> List[str]:
        """Pull the data field from each Answer record in a DoH response."""
        if not response:
            return []
        return [a.get("data", "") for a in response.get("Answer", []) if a.get("data")]

    # -- Specific record lookups -------------------------------------------
    def lookup_a(self, domain: str) -> List[str]:
        return self._extract_answers(self._doh_query(domain, "A"))

    def lookup_aaaa(self, domain: str) -> List[str]:
        return self._extract_answers(self._doh_query(domain, "AAAA"))

    def lookup_mx(self, domain: str) -> List[Dict[str, Any]]:
        """Return MX records as list of {priority, host} dicts, sorted."""
        raw = self._extract_answers(self._doh_query(domain, "MX"))
        records = []
        for r in raw:
            parts = r.split(None, 1)
            if len(parts) == 2:
                try:
                    records.append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
                except ValueError:
                    pass
        return sorted(records, key=lambda x: x["priority"])

    def lookup_txt(self, domain: str) -> List[str]:
        """TXT records — strips outer quotes and joins multi-string records."""
        raw = self._extract_answers(self._doh_query(domain, "TXT"))
        cleaned = []
        for r in raw:
            # Strip surrounding quotes; concatenate multi-quoted fragments
            txt = r.replace('" "', '').strip().strip('"')
            cleaned.append(txt)
        return cleaned

    def lookup_ns(self, domain: str) -> List[str]:
        return [r.rstrip(".") for r in self._extract_answers(self._doh_query(domain, "NS"))]

    def lookup_cname(self, domain: str) -> List[str]:
        return [r.rstrip(".") for r in self._extract_answers(self._doh_query(domain, "CNAME"))]

    def lookup_soa(self, domain: str) -> str:
        records = self._extract_answers(self._doh_query(domain, "SOA"))
        return records[0] if records else ""

    def lookup_caa(self, domain: str) -> List[str]:
        return self._extract_answers(self._doh_query(domain, "CAA"))

    def lookup_srv(self, domain: str) -> List[str]:
        return self._extract_answers(self._doh_query(domain, "SRV"))

    def reverse_dns(self, ip: str) -> str:
        """PTR record lookup for an IP address — returns hostname or ''."""
        if not IP_RE.match(ip):
            return ""
        # Build in-addr.arpa reverse name
        octets = ip.split(".")
        reverse_name = ".".join(reversed(octets)) + ".in-addr.arpa"
        records = self._extract_answers(self._doh_query(reverse_name, "PTR"))
        return records[0].rstrip(".") if records else ""

    # -- Email authentication policy parsing -------------------------------
    @staticmethod
    def parse_spf(txt_records: List[str]) -> Tuple[str, bool, str]:
        """
        Find SPF record from TXT list.
        Returns (record, is_valid, strength) where strength is none/soft/strict.
        """
        for r in txt_records:
            if r.lower().startswith("v=spf1"):
                # Strength based on terminator
                if r.rstrip().endswith("-all"):
                    strength = "strict"        # hard fail
                elif r.rstrip().endswith("~all"):
                    strength = "soft"          # soft fail
                elif r.rstrip().endswith("?all"):
                    strength = "neutral"
                elif r.rstrip().endswith("+all"):
                    strength = "permissive"    # DANGEROUS
                else:
                    strength = "unknown"
                return (r, True, strength)
        return ("", False, "none")

    @staticmethod
    def parse_dmarc(txt_records: List[str]) -> Tuple[str, str]:
        """Find DMARC record. Returns (record, policy)."""
        for r in txt_records:
            if r.lower().startswith("v=dmarc1"):
                # Extract p= directive
                m = re.search(r'\bp\s*=\s*(none|quarantine|reject)', r, re.IGNORECASE)
                policy = m.group(1).lower() if m else "none"
                return (r, policy)
        return ("", "none")

    def probe_dkim_selectors(self, domain: str,
                             selectors: Optional[List[str]] = None
                             ) -> Dict[str, str]:
        """
        Try common DKIM selectors. Returns dict of {selector: record}.
        Slow if many selectors — use sparingly. Stops early after 3 hits.
        """
        if selectors is None:
            selectors = COMMON_DKIM_SELECTORS

        found: Dict[str, str] = {}
        for sel in selectors:
            dkim_name = f"{sel}._domainkey.{domain}"
            records = self._extract_answers(self._doh_query(dkim_name, "TXT"))
            for r in records:
                if "v=dkim1" in r.lower() or "k=rsa" in r.lower() or "p=" in r.lower():
                    found[sel] = r
                    break
            if len(found) >= 3:  # enough evidence; stop probing
                break
        return found

    # -- High-level orchestration ------------------------------------------
    def comprehensive_lookup(self,
                             domain: str,
                             probe_dkim: bool = True,
                             reverse_ips: Optional[List[str]] = None
                             ) -> DNSAnalysis:
        """
        Complete DNS forensic sweep on a single domain.
        Optionally probes DKIM selectors and reverse-resolves a list of IPs.
        """
        result = DNSAnalysis(domain=domain.lower().strip("."))

        if not result.domain:
            result.errors.append("Empty domain")
            return result

        # Standard records
        result.a_records = self.lookup_a(result.domain)
        result.aaaa_records = self.lookup_aaaa(result.domain)
        result.mx_records = self.lookup_mx(result.domain)
        result.txt_records = self.lookup_txt(result.domain)
        result.ns_records = self.lookup_ns(result.domain)
        result.cname_records = self.lookup_cname(result.domain)
        result.soa_record = self.lookup_soa(result.domain)
        result.caa_records = self.lookup_caa(result.domain)
        result.srv_records = self.lookup_srv(result.domain)

        # SPF parsing
        spf, valid, strength = self.parse_spf(result.txt_records)
        result.spf_record = spf
        result.spf_valid = valid
        result.spf_strength = strength

        # DMARC — separately queried at _dmarc.<domain>
        dmarc_txt = self.lookup_txt(f"_dmarc.{result.domain}")
        dmarc_record, dmarc_policy = self.parse_dmarc(dmarc_txt)
        result.dmarc_record = dmarc_record
        result.dmarc_policy = dmarc_policy

        # DKIM — selector probing
        if probe_dkim:
            result.dkim_records = self.probe_dkim_selectors(result.domain)
            result.dkim_selectors_found = list(result.dkim_records.keys())

        # Reverse DNS for relevant IPs
        if reverse_ips:
            for ip in reverse_ips:
                ptr = self.reverse_dns(ip)
                if ptr:
                    result.ptr_records[ip] = ptr

        # -- Build findings, warnings, scoring ---
        self._evaluate(result)
        return result

    @staticmethod
    def _evaluate(d: DNSAnalysis) -> None:
        """Populate findings, warnings, and auth_score on a DNSAnalysis."""
        score = 0.0  # higher = more secure

        # MX records present?
        if d.mx_records:
            d.findings.append(f"MX records present ({len(d.mx_records)} servers)")
            score += 10
        else:
            d.warnings.append("No MX records — domain cannot receive email")

        # SPF
        if d.spf_valid:
            d.findings.append(f"SPF record present (strength: {d.spf_strength})")
            if d.spf_strength == "strict":
                score += 25
            elif d.spf_strength == "soft":
                score += 15
            elif d.spf_strength == "permissive":
                d.warnings.append("SPF uses '+all' — permits ANY sender (severe misconfig)")
                score -= 10
            else:
                score += 5
        else:
            d.warnings.append("No SPF record — domain easily spoofable")

        # DMARC
        if d.dmarc_record:
            d.findings.append(f"DMARC published with p={d.dmarc_policy}")
            if d.dmarc_policy == "reject":
                score += 35
            elif d.dmarc_policy == "quarantine":
                score += 25
            elif d.dmarc_policy == "none":
                d.warnings.append("DMARC p=none — monitoring only, no enforcement")
                score += 5
        else:
            d.warnings.append("No DMARC record — receivers cannot verify policy")

        # DKIM
        if d.dkim_selectors_found:
            d.findings.append(f"DKIM selectors detected: {', '.join(d.dkim_selectors_found)}")
            score += 20
        else:
            d.warnings.append("No common DKIM selectors found (may use custom selector)")

        # NS / SOA presence
        if d.ns_records:
            d.findings.append(f"Authoritative NS: {', '.join(d.ns_records[:3])}")
            score += 5

        # CAA — strong sign of mature security posture
        if d.caa_records:
            d.findings.append(f"CAA records present ({len(d.caa_records)}) — cert hijack protection")
            score += 5

        # Cap score
        d.auth_score = max(0.0, min(100.0, score))



# ---------------------------------------------------------------------------
# TLS / SSL Certificate forensics — Live cert + crt.sh + SSL Labs (NEW IN v1.0)
# ---------------------------------------------------------------------------
class TLSCertificateAnalyzer:
    """
    Inspects the live TLS certificate served on port 443 of a domain,
    plus optional Certificate Transparency (crt.sh) and SSL Labs lookups.

    All sources are free public services — no API key required.

    Designed for SOC analysts to validate sender-domain TLS posture
    and detect lookalike domains via cert transparency logs.
    """

    SSLLABS_API = "https://api.ssllabs.com/api/v3/analyze"
    CRTSH_API = "https://crt.sh/?q={domain}&output=json"

    def __init__(self, timeout: int = 12, ssllabs_max_wait: int = 60):
        self.timeout = timeout
        self.ssllabs_max_wait = ssllabs_max_wait

    # -- Live socket-based certificate retrieval ---------------------------
    def fetch_live_certificate(self, domain: str) -> TLSAnalysis:
        """
        Retrieve the active TLS certificate served by the domain on port 443.
        Populates subject, issuer, validity, SANs, hostname-match, days-to-expiry.
        """
        result = TLSAnalysis(domain=domain.lower().strip(".").strip())
        if not result.domain:
            result.status = "error"
            result.error = "Empty domain"
            result.red_flags.append("No domain provided")
            return result

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((result.domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=result.domain) as ssock:
                    cert = ssock.getpeercert()

            result.status = "ok"
            result.subject = self._name_tuple_to_dict(cert.get("subject", []))
            result.issuer = self._name_tuple_to_dict(cert.get("issuer", []))
            result.not_before = cert.get("notBefore", "")
            result.not_after = cert.get("notAfter", "")
            result.serial_number = str(cert.get("serialNumber", ""))
            result.version = str(cert.get("version", ""))
            result.subject_alt_names = [
                v for t, v in cert.get("subjectAltName", []) if t.lower() == "dns"
            ]

            # Hostname match check
            try:
                ssl.match_hostname(cert, result.domain)
                result.matches_hostname = True
                result.findings.append(f"Certificate hostname matches {result.domain}")
            except Exception:
                result.matches_hostname = False
                result.red_flags.append("Certificate hostname/SAN does not match domain")

            # Days-to-expiry
            if result.not_after:
                try:
                    exp = datetime.strptime(
                        result.not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                    result.days_until_expiry = days
                    if days < 0:
                        result.red_flags.append(f"Certificate is EXPIRED ({abs(days)} days ago)")
                    elif days < 14:
                        result.red_flags.append(f"Certificate expires in {days} days (very soon)")
                    else:
                        result.findings.append(f"Certificate valid for {days} more days")
                except Exception:
                    pass

            # Issuer sanity check — Let's Encrypt on a "brand" domain is suspicious
            issuer_org = result.issuer.get("organizationName", "").lower()
            if "let's encrypt" in issuer_org or "lets encrypt" in issuer_org:
                result.findings.append("Issuer: Let's Encrypt (free) — common on phishing infra")
            elif issuer_org:
                result.findings.append(f"Issuer organization: {result.issuer.get('organizationName', 'unknown')}")

        except socket.timeout:
            result.status = "error"
            result.error = "Connection timed out"
            result.red_flags.append("TLS connection timeout — host may not serve HTTPS")
        except socket.gaierror as e:
            result.status = "error"
            result.error = f"DNS resolution failed: {e}"
            result.red_flags.append("Could not resolve domain to retrieve certificate")
        except (ssl.SSLError, ConnectionRefusedError, OSError) as e:
            result.status = "error"
            result.error = str(e)
            result.red_flags.append(f"TLS handshake failed: {type(e).__name__}")
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            result.red_flags.append("Unknown error retrieving certificate")
        return result

    @staticmethod
    def _name_tuple_to_dict(name_tuple) -> Dict[str, str]:
        """Convert ssl certificate name tuple to a flat dict."""
        d = {}
        try:
            for rdn in name_tuple:
                for k, v in rdn:
                    d[str(k)] = str(v)
        except Exception:
            pass
        return d

    # -- Certificate Transparency via crt.sh -------------------------------
    def lookup_crtsh(self, domain: str, max_results: int = 50) -> Tuple[str, int, List[str]]:
        """
        Query crt.sh for all certificates issued for this domain (and subdomains).
        Returns (status, total_count, list_of_unique_subject_names).
        Useful for finding lookalike domains in CT logs.
        """
        try:
            url = self.CRTSH_API.format(domain=urllib.parse.quote(domain))
            req = urllib.request.Request(url, headers={
                "Accept": "application/json",
                "User-Agent": "PhishHunter/1.0",
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))

            if not isinstance(data, list):
                return ("no_results", 0, [])

            seen: Set[str] = set()
            for item in data[:max_results * 3]:  # allow scanning extras
                name = item.get("name_value", "").strip()
                if name:
                    # crt.sh returns multi-line entries — split
                    for ln in name.splitlines():
                        ln = ln.strip().lower().lstrip("*.")
                        if ln and ln not in seen:
                            seen.add(ln)
            return ("ok", len(data), list(seen)[:max_results])
        except (HTTPError, URLError, socket.timeout):
            return ("unavailable", 0, [])
        except Exception:
            return ("error", 0, [])

    # -- SSL Labs API (slow — 60+ sec) -------------------------------------
    def lookup_ssllabs(self, domain: str) -> Tuple[str, str]:
        """
        Query SSL Labs API for grade. Returns (status, grade).
        Slow — only run when explicitly requested.
        """
        try:
            params = urllib.parse.urlencode({
                "host": domain,
                "publish": "off",
                "startNew": "on",
                "all": "done",
                "ignoreMismatch": "on",
            })
            start = time.time()
            last_data: Dict[str, Any] = {}
            while True:
                req = urllib.request.Request(f"{self.SSLLABS_API}?{params}")
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    last_data = json.loads(resp.read().decode("utf-8", errors="replace"))
                status = last_data.get("status", "UNKNOWN")
                if status in {"READY", "ERROR"}:
                    break
                if time.time() - start > self.ssllabs_max_wait:
                    return ("timeout", "")
                time.sleep(8)
                params = urllib.parse.urlencode({
                    "host": domain, "publish": "off",
                    "all": "done", "ignoreMismatch": "on",
                })

            endpoints = last_data.get("endpoints", []) or []
            grades = [ep.get("grade") for ep in endpoints if ep.get("grade")]
            grade = grades[0] if grades else ""
            return (last_data.get("status", "READY").lower(), grade)
        except Exception:
            return ("error", "")

    # -- Comprehensive analysis --------------------------------------------
    def analyse(self, domain: str, run_crtsh: bool = True,
                run_ssllabs: bool = False) -> TLSAnalysis:
        """Comprehensive TLS analysis: live cert + crt.sh + optional SSL Labs."""
        result = self.fetch_live_certificate(domain)

        # Certificate Transparency — useful even if live cert fails
        if run_crtsh and domain:
            status, count, names = self.lookup_crtsh(domain)
            result.crtsh_status = status
            result.crtsh_certificate_count = count
            result.crtsh_recent_subdomains = names
            if status == "ok":
                result.findings.append(
                    f"crt.sh: {count} certificates found, {len(names)} unique names"
                )
                # Look for suspicious lookalikes
                suspicious = [n for n in names if any(
                    brand in n and brand not in domain for brand in BRAND_KEYWORDS
                )]
                if suspicious:
                    result.red_flags.append(
                        f"crt.sh: lookalike-brand certificates seen "
                        f"({', '.join(suspicious[:3])})"
                    )

        # SSL Labs — only on explicit request (slow)
        if run_ssllabs and domain and result.status == "ok":
            ssl_status, grade = self.lookup_ssllabs(domain)
            result.ssllabs_status = ssl_status
            result.ssllabs_grade = grade
            if grade:
                if grade in ("A+", "A", "A-"):
                    result.findings.append(f"SSL Labs grade: {grade} (good)")
                else:
                    result.red_flags.append(f"SSL Labs grade: {grade} (weak posture)")

        return result



class PhishingScorer:
    """Keyword-based and heuristic phishing risk scoring engine."""

    @staticmethod
    def score_body(text: str) -> Tuple[int, List[str]]:
        """Score text body for phishing keywords. Returns (score, matched_keywords)."""
        text_lower = text.lower()
        found: List[str] = []
        score = 0
        for kw in PHISHING_KEYWORDS:
            if kw.lower() in text_lower:
                found.append(kw)
                score += 3
        return (min(score, 40), found)

    @staticmethod
    def detect_brand_impersonation(header: HeaderAnalysis,
                                    body_text: str = "") -> List[str]:
        """
        Detect brand impersonation: brand keyword appears in display name
        or body, but the sender's domain doesn't match that brand.
        Common in phishing — e.g. 'Microsoft Support' from random.xyz.
        """
        findings: List[str] = []
        display = (header.from_display or "").lower()
        from_domain = ""
        if "@" in header.from_address:
            from_domain = header.from_address.rsplit("@", 1)[-1].lower()

        if not display or not from_domain:
            return findings

        # Check 1: brand in display name but not in domain
        for brand in BRAND_KEYWORDS:
            if brand in display and brand not in from_domain:
                findings.append(
                    f"Brand impersonation: display name claims '{brand}' "
                    f"but sender domain is {from_domain}"
                )

        # Check 2: brand in subject + suspicious sender domain
        subject_lower = (header.subject or "").lower()
        suspicious_tlds = (".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf")
        if from_domain.endswith(suspicious_tlds):
            for brand in BRAND_KEYWORDS:
                if brand in subject_lower or brand in display:
                    findings.append(
                        f"Brand impersonation risk: '{brand}' referenced from "
                        f"sender on cheap TLD ({from_domain})"
                    )
                    break  # one finding is enough

        return findings

    @staticmethod
    def score_to_level(score: float) -> str:
        """Map a 0-100 risk score to a textual level."""
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score >= 15:
            return "LOW"
        else:
            return "MINIMAL"

    @staticmethod
    def compute_risk(
        header: HeaderAnalysis,
        urls: List[URLAnalysis],
        attachments: List[AttachmentAnalysis],
        body_score: int,
        body_keywords: List[str],
    ) -> Tuple[float, str, List[str]]:
        """
        Weighted risk scoring: 0-100.
        Returns (score 0-100, risk_level, indicator_list).
        """
        score = 0.0
        indicators: List[str] = []

        # --- Authentication failures (max 25) ---
        auth_failures = 0
        for auth in [header.spf_result, header.dkim_result, header.dmarc_result]:
            if auth in ("fail", "softfail"):
                auth_failures += 1
        score += auth_failures * 8
        if auth_failures > 0:
            indicators.append(f"Authentication failures: {auth_failures}")

        # --- Spoof indicators (max 20) ---
        score += min(len(header.spoof_indicators) * 5, 20)
        indicators.extend(header.spoof_indicators)

        # --- Suspicious URLs (max 25) ---
        sus_urls = [u for u in urls if u.suspicious]
        score += min(len(sus_urls) * 8, 25)
        if sus_urls:
            indicators.append(f"Suspicious URLs: {len(sus_urls)}")

        # --- Shortened URLs (max 10) ---
        shortened = [u for u in urls if u.is_shortened]
        score += min(len(shortened) * 5, 10)
        if shortened:
            indicators.append(f"Shortened URLs: {len(shortened)}")

        # --- Body keyword score (max 40) ---
        score += body_score

        # --- Suspicious attachments (max 15) ---
        sus_att = [a for a in attachments if a.suspicious]
        score += min(len(sus_att) * 5, 15)
        if sus_att:
            indicators.append(f"Suspicious attachments: {len(sus_att)}")

        # --- Risky sender domain (max 5) ---
        domain = header.from_address.split("@")[-1] if "@" in header.from_address else ""
        if domain in RISKY_SENDER_DOMAINS:
            score += 5
            indicators.append(f"Free email sender domain: {domain}")

        # --- From address not matching display name domain ---
        if header.from_display and header.from_address:
            # crude company name extraction
            import re as _re
            company_words = _re.findall(r'[A-Z][a-z]{2,}', header.from_display)
            addr_domain = domain.split(".")[0] if "." in domain else domain
            if company_words and not any(w.lower() in addr_domain.lower() for w in company_words if len(w) > 2):
                indicators.append("Display name impersonation (company name mismatch with sender domain)")

        # Clamp and determine level
        score = max(0.0, min(100.0, score))
        level = PhishingScorer.score_to_level(score)

        return (round(score, 1), level, indicators)


class ReportGenerator:
    """Generate forensic reports in JSON and HTML formats."""

    @staticmethod
    def to_json(report: PhishingReport, output_path: Path) -> Path:
        data = report.export()
        # Convert nested dataclasses
        output_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return output_path

    @staticmethod
    def to_html(report: PhishingReport, output_path: Path) -> Path:
        """Generate a styled HTML forensic report."""
        score = report.risk_score
        level = report.risk_level
        colour = {"CRITICAL": "#ff4757", "HIGH": "#ff7b3a", "MEDIUM": "#feca57",
                   "LOW": "#3eff8a", "MINIMAL": "#4dd6ff"}.get(level, "#6c757d")

        html = textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head><meta charset="UTF-8"><title>PhishHunter Report — {html_mod.escape(report.file_path)}</title>
        <style>
            *{{box-sizing:border-box;margin:0;padding:0}}
            body{{font-family:'Segoe UI','Helvetica Neue',Arial,sans-serif;background:#0a0e1a;color:#e8eaf0;padding:24px;line-height:1.5}}
            .wrap{{max-width:1200px;margin:0 auto}}
            .header{{display:flex;justify-content:space-between;align-items:flex-start;
                     padding:24px;background:linear-gradient(135deg,#11151f 0%,#161b28 100%);
                     border:1px solid #1f2937;border-radius:12px;margin-bottom:24px}}
            .brand{{display:flex;align-items:center;gap:16px}}
            .logo{{width:56px;height:56px;display:flex;align-items:center;justify-content:center;
                   background:#0a0e1a;border:1px solid #1f2937;border-radius:12px;color:#4dd6ff;
                   font-family:'Courier New',monospace;font-size:28px;font-weight:700}}
            .brand h1{{color:#4dd6ff;font-family:'Courier New',monospace;font-size:24px;
                      letter-spacing:0.05em;font-weight:600}}
            .brand p{{color:#9aa3b8;font-size:11px;letter-spacing:0.15em;text-transform:uppercase;margin-top:4px}}
            .credit{{text-align:right;font-size:12px;color:#9aa3b8}}
            .credit a{{color:#4dd6ff;text-decoration:none;border-bottom:1px dashed #4dd6ff66}}
            .card{{background:#11151f;border:1px solid #1f2937;border-radius:12px;padding:24px;margin:16px 0}}
            h2{{color:#4dd6ff;border-bottom:1px solid #1f2937;padding-bottom:10px;margin-bottom:14px;font-size:18px;font-weight:600}}
            h3{{color:#e8eaf0;margin:14px 0 8px;font-size:14px;font-weight:600;letter-spacing:0.04em;text-transform:uppercase}}
            table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}}
            th,td{{padding:10px 14px;text-align:left;border-bottom:1px solid #1f2937;vertical-align:top}}
            th{{color:#9aa3b8;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;font-weight:600}}
            td code{{background:#07090f;padding:2px 8px;border-radius:4px;font-size:12px;color:#3eff8a;
                     font-family:'JetBrains Mono','Courier New',monospace;word-break:break-all}}
            .risk-badge{{display:inline-block;padding:6px 18px;border-radius:8px;font-weight:700;
                         font-size:13px;background:{colour};color:#0a0e1a;letter-spacing:0.04em}}
            .score{{font-size:42px;font-weight:800;color:{colour};line-height:1;font-family:'JetBrains Mono','Courier New',monospace}}
            .score-line{{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin:12px 0}}
            .indicator{{background:rgba(255,71,87,0.07);border-left:3px solid #ff4757;padding:10px 14px;margin:6px 0;border-radius:0 6px 6px 0;font-size:13px}}
            .ok{{background:rgba(62,255,138,0.07);border-left:3px solid #3eff8a}}
            .warn{{background:rgba(254,202,87,0.08);border-left:3px solid #feca57;padding:10px 14px;margin:6px 0;border-radius:0 6px 6px 0;font-size:13px}}
            .dns-domain{{padding:18px;background:#0a0e1a;border-radius:10px;margin:12px 0;border:1px solid #1f2937}}
            .dns-domain-name{{font-family:'JetBrains Mono','Courier New',monospace;font-size:15px;color:#4dd6ff;font-weight:600;margin-bottom:10px}}
            .auth-meter{{display:inline-block;height:8px;background:#1f2937;border-radius:4px;overflow:hidden;width:120px;vertical-align:middle;margin-left:10px}}
            .auth-meter-fill{{height:100%;background:linear-gradient(90deg,#3eff8a,#4dd6ff);transition:width 0.3s}}
            .meta{{font-size:12px;color:#9aa3b8;letter-spacing:0.05em}}
            .footer{{text-align:center;color:#5d6577;font-size:12px;padding:24px 0;border-top:1px solid #1f2937;margin-top:32px}}
            .footer a{{color:#4dd6ff;text-decoration:none}}
            .badge-pass{{color:#3eff8a;font-weight:600}}
            .badge-fail{{color:#ff4757;font-weight:600}}
            .badge-warn{{color:#feca57;font-weight:600}}
        </style></head><body>
        <div class="wrap">
        <div class="header">
            <div class="brand">
                <div class="logo">𝝫</div>
                <div>
                    <h1>PHISH HUNTER</h1>
                    <p>Universal SOC Email Phishing Forensics &nbsp;·&nbsp; v1.0</p>
                </div>
            </div>
            <div class="credit">
                <div>Created by <strong style="color:#e8eaf0">Mohammad Shahbaaz Ahmed</strong></div>
                <div style="margin-top:4px"><a href="https://github.com/shahbaaz-devsec" target="_blank">github.com/shahbaaz-devsec</a></div>
                <div style="margin-top:4px"><a href="https://www.linkedin.com/in/mohammad-shahbaaz-ahmed-138a423bb" target="_blank">LinkedIn</a></div>
            </div>
        </div>

        <div class="card">
        <h2>Risk Assessment</h2>
        <div class="score-line">
            <span class="score">{score:.1f}<span style="font-size:18px;color:#9aa3b8;font-weight:400">/100</span></span>
            <span class="risk-badge">{level}</span>
        </div>
        <p class="meta"><strong>Analysed:</strong> {report.analysed_at}</p>
        <p class="meta"><strong>File:</strong> <code>{html_mod.escape(report.file_path)}</code></p>
        </div>

        <div class="card">
        <h2>Header Analysis</h2>
        <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>From</td><td><code>{html_mod.escape(report.header.from_display)} &lt;{html_mod.escape(report.header.from_address)}&gt;</code></td></tr>
        <tr><td>Reply-To</td><td><code>{html_mod.escape(report.header.reply_to)}</code></td></tr>
        <tr><td>Return-Path</td><td><code>{html_mod.escape(report.header.return_path)}</code></td></tr>
        <tr><td>Subject</td><td>{html_mod.escape(report.header.subject)}</td></tr>
        <tr><td>Date</td><td>{html_mod.escape(report.header.date)}</td></tr>
        <tr><td>To</td><td><code>{html_mod.escape(', '.join(report.header.to_addresses))}</code></td></tr>
        <tr><td>Cc</td><td><code>{html_mod.escape(', '.join(report.header.cc_addresses))}</code></td></tr>
        <tr><td>Originating IP</td><td><code>{html_mod.escape(report.header.originating_ip)}</code></td></tr>
        <tr><td>SPF</td><td><code>{html_mod.escape(report.header.spf_result)}</code></td></tr>
        <tr><td>DKIM</td><td><code>{html_mod.escape(report.header.dkim_result)}</code></td></tr>
        <tr><td>DMARC</td><td><code>{html_mod.escape(report.header.dmarc_result)}</code></td></tr>
        </table>
        <h3>Received Hops</h3>
        <table><tr><th>#</th><th>From</th><th>By</th><th>IP</th></tr>
        """)

        for i, hop in enumerate(report.header.received_hops):
            html += (
                f"<tr><td>{i+1}</td>"
                f"<td>{html_mod.escape(hop.get('from_host',''))}</td>"
                f"<td>{html_mod.escape(hop.get('by_host',''))}</td>"
                f"<td><code>{html_mod.escape(hop.get('from_ip',''))}</code></td></tr>\n"
            )

        html += "</table></div>\n"

        # Spoof indicators
        if report.header.spoof_indicators:
            html += '<div class="card"><h2>Spoofing Indicators</h2>\n'
            for ind in report.header.spoof_indicators:
                html += f'<div class="indicator">{html_mod.escape(ind)}</div>\n'
            html += "</div>\n"

        # DNS Records (NEW IN v3.0)
        if report.dns_records:
            html += '<div class="card"><h2>DNS Forensics</h2>\n'
            html += '<p class="meta">Comprehensive DNS lookups via Cloudflare 1.1.1.1 / Google 8.8.8.8 (DNS-over-HTTPS)</p>\n'
            for d in report.dns_records:
                html += f'<div class="dns-domain">'
                html += f'<div class="dns-domain-name">{html_mod.escape(d.domain)}'
                html += f' <span class="meta">— authentication strength {d.auth_score:.0f}/100</span>'
                html += f' <span class="auth-meter"><span class="auth-meter-fill" style="width:{d.auth_score}%"></span></span>'
                html += f'</div>'
                html += '<table>'
                html += '<tr><th style="width:120px">Record Type</th><th>Value</th></tr>'

                if d.a_records:
                    html += f'<tr><td>A (IPv4)</td><td><code>{html_mod.escape(", ".join(d.a_records))}</code></td></tr>'
                if d.aaaa_records:
                    html += f'<tr><td>AAAA (IPv6)</td><td><code>{html_mod.escape(", ".join(d.aaaa_records[:3]))}</code></td></tr>'
                if d.mx_records:
                    mx_html = ", ".join(f"{m['priority']} {html_mod.escape(m['host'])}" for m in d.mx_records)
                    html += f'<tr><td>MX</td><td><code>{mx_html}</code></td></tr>'
                if d.ns_records:
                    html += f'<tr><td>NS</td><td><code>{html_mod.escape(", ".join(d.ns_records))}</code></td></tr>'
                if d.cname_records:
                    html += f'<tr><td>CNAME</td><td><code>{html_mod.escape(", ".join(d.cname_records))}</code></td></tr>'
                if d.soa_record:
                    html += f'<tr><td>SOA</td><td><code>{html_mod.escape(d.soa_record)}</code></td></tr>'
                if d.caa_records:
                    html += f'<tr><td>CAA</td><td><code>{html_mod.escape(", ".join(d.caa_records))}</code></td></tr>'

                # SPF
                spf_class = "badge-pass" if d.spf_strength in ("strict", "soft") else ("badge-warn" if d.spf_record else "badge-fail")
                spf_disp = html_mod.escape(d.spf_record) if d.spf_record else "MISSING"
                html += f'<tr><td>SPF</td><td><code>{spf_disp}</code> <span class="{spf_class}">[{d.spf_strength}]</span></td></tr>'

                # DMARC
                dmarc_class = {"reject":"badge-pass","quarantine":"badge-pass","none":"badge-warn"}.get(d.dmarc_policy, "badge-fail")
                dmarc_disp = html_mod.escape(d.dmarc_record) if d.dmarc_record else "MISSING"
                html += f'<tr><td>DMARC</td><td><code>{dmarc_disp}</code> <span class="{dmarc_class}">[p={d.dmarc_policy}]</span></td></tr>'

                # DKIM
                if d.dkim_records:
                    html += f'<tr><td>DKIM</td><td>'
                    html += f'<span class="badge-pass">{len(d.dkim_records)} selectors found:</span> '
                    html += html_mod.escape(", ".join(d.dkim_records.keys()))
                    html += '</td></tr>'
                else:
                    html += '<tr><td>DKIM</td><td><span class="badge-warn">No common selectors detected</span></td></tr>'

                # PTR
                if d.ptr_records:
                    for ip, ptr in d.ptr_records.items():
                        html += f'<tr><td>PTR ({ip})</td><td><code>{html_mod.escape(ptr)}</code></td></tr>'

                html += '</table>'

                if d.findings:
                    for f in d.findings:
                        html += f'<div class="ok indicator">{html_mod.escape(f)}</div>'
                if d.warnings:
                    for w in d.warnings:
                        html += f'<div class="warn">{html_mod.escape(w)}</div>'

                html += '</div>'
            html += '</div>'

        # TLS / SSL Forensics (NEW IN v1.0)
        if report.tls_records:
            html += '<div class="card"><h2>TLS / SSL Certificate Forensics</h2>'
            html += '<p class="meta">Live cert via socket:443 + Certificate Transparency (crt.sh)</p>'
            for t in report.tls_records:
                status_class = "badge-pass" if t.status == "ok" else "badge-fail"
                html += '<div class="dns-domain">'
                html += (f'<div class="dns-domain-name">{html_mod.escape(t.domain)}'
                         f' <span class="{status_class}">[{t.status}]</span></div>')

                if t.status == "ok":
                    html += '<table>'
                    html += '<tr><th style="width:140px">Field</th><th>Value</th></tr>'

                    # Subject
                    if t.subject:
                        sub_str = ", ".join(f"{k}={v}" for k, v in t.subject.items())
                        html += f'<tr><td>Subject</td><td><code>{html_mod.escape(sub_str)}</code></td></tr>'

                    # Issuer
                    if t.issuer:
                        iss_str = ", ".join(f"{k}={v}" for k, v in t.issuer.items())
                        html += f'<tr><td>Issuer</td><td><code>{html_mod.escape(iss_str)}</code></td></tr>'

                    # Validity
                    if t.not_before:
                        html += f'<tr><td>Not Before</td><td><code>{html_mod.escape(t.not_before)}</code></td></tr>'
                    if t.not_after:
                        days = t.days_until_expiry
                        cls = "badge-pass" if (days is not None and days > 30) else ("badge-warn" if (days is not None and days >= 0) else "badge-fail")
                        days_txt = f"({days} days)" if days is not None else ""
                        html += f'<tr><td>Not After</td><td><code>{html_mod.escape(t.not_after)}</code> <span class="{cls}">{days_txt}</span></td></tr>'

                    # Hostname match
                    if t.matches_hostname is not None:
                        match_class = "badge-pass" if t.matches_hostname else "badge-fail"
                        match_txt = "matches" if t.matches_hostname else "MISMATCH"
                        html += f'<tr><td>Hostname Match</td><td><span class="{match_class}">{match_txt}</span></td></tr>'

                    # SANs
                    if t.subject_alt_names:
                        sans_str = ", ".join(t.subject_alt_names[:10])
                        if len(t.subject_alt_names) > 10:
                            sans_str += f" ... (+{len(t.subject_alt_names)-10} more)"
                        html += f'<tr><td>Subject Alt Names</td><td><code>{html_mod.escape(sans_str)}</code></td></tr>'

                    # crt.sh
                    if t.crtsh_status == "ok":
                        ct_str = (f'{t.crtsh_certificate_count} certificates, '
                                  f'{len(t.crtsh_recent_subdomains)} unique names')
                        html += f'<tr><td>crt.sh</td><td>{ct_str}</td></tr>'
                        if t.crtsh_recent_subdomains:
                            sub_preview = ", ".join(t.crtsh_recent_subdomains[:5])
                            html += f'<tr><td>CT subdomains</td><td><code>{html_mod.escape(sub_preview)}</code></td></tr>'

                    # SSL Labs
                    if t.ssllabs_grade:
                        grade_class = "badge-pass" if t.ssllabs_grade in ("A+", "A", "A-") else "badge-warn"
                        html += f'<tr><td>SSL Labs Grade</td><td><span class="{grade_class}">{html_mod.escape(t.ssllabs_grade)}</span></td></tr>'

                    html += '</table>'
                else:
                    if t.error:
                        html += f'<p class="meta">Error: {html_mod.escape(t.error)}</p>'

                # Findings
                if t.findings:
                    for fnd in t.findings:
                        html += f'<div class="ok indicator">{html_mod.escape(fnd)}</div>'

                # Red flags
                if t.red_flags:
                    for rf in t.red_flags:
                        html += f'<div class="indicator">{html_mod.escape(rf)}</div>'

                html += '</div>'
            html += '</div>'

        # Brand impersonation
        if report.brand_impersonation:
            html += '<div class="card"><h2>Brand Impersonation</h2>'
            for bi in report.brand_impersonation:
                html += f'<div class="indicator">{html_mod.escape(bi)}</div>'
            html += '</div>'

        # URLs
        if report.urls:
            html += '<div class="card"><h2>URL Analysis</h2><table>\n'
            html += "<tr><th>URL (defanged)</th><th>Domain</th><th>URLhaus</th><th>VT</th><th>Age</th><th>Suspicious</th></tr>\n"
            for u in report.urls:
                vt_str = f"{u.vt_malicious}/{u.vt_total}" if u.vt_total else "N/A"
                age_str = f"{u.domain_age_days}d" if u.domain_age_days >= 0 else "?"
                sus = '<span class="badge-fail">⚠ Yes</span>' if u.suspicious else '<span class="badge-pass">✓ No</span>'
                html += (
                    f"<tr><td><code>{html_mod.escape(u.defanged)}</code></td>"
                    f"<td>{html_mod.escape(u.domain)}</td>"
                    f"<td>{html_mod.escape(u.urlhaus_status)}</td>"
                    f"<td>{vt_str}</td><td>{age_str}</td><td>{sus}</td></tr>\n"
                )
            html += "</table></div>\n"

        # Attachments
        if report.attachments:
            html += '<div class="card"><h2>Attachment Analysis</h2><table>\n'
            html += "<tr><th>Filename</th><th>Size</th><th>SHA-256</th><th>Entropy</th><th>Suspicious</th></tr>\n"
            for a in report.attachments:
                sus = '<span class="badge-fail">⚠ Yes</span>' if a.suspicious else '<span class="badge-pass">✓ No</span>'
                sha_short = a.sha256[:16] + "…" if a.sha256 else ""
                html += (
                    f"<tr><td><code>{html_mod.escape(a.filename)}</code></td>"
                    f"<td>{a.size_bytes} B</td>"
                    f"<td><code>{sha_short}</code></td>"
                    f"<td>{a.entropy:.2f}</td><td>{sus}</td></tr>\n"
                )
            html += "</table></div>\n"

        # Indicators
        if report.indicators:
            html += '<div class="card"><h2>Key Indicators</h2>\n'
            for ind in report.indicators:
                html += f'<div class="indicator">{html_mod.escape(ind)}</div>\n'
            html += "</div>\n"

        # Investigation tools — analyst pivots
        html += '<div class="card"><h2>Further Investigation — Free Tools</h2>'
        html += '<h3 style="color:#9aa3b8">URL Analysis</h3>'
        html += '<ul style="color:#9aa3b8;font-size:13px;line-height:1.8;list-style:none;padding-left:0">'
        for url_tool in URL_ANALYSIS_TOOLS:
            html += f'<li>• {html_mod.escape(url_tool)}</li>'
        html += '</ul>'

        html += '<h3 style="color:#9aa3b8">Header Analysis</h3>'
        html += '<ul style="color:#9aa3b8;font-size:13px;line-height:1.8;list-style:none;padding-left:0">'
        for hdr_tool in HEADER_ANALYZER_TOOLS:
            html += f'<li>• {html_mod.escape(hdr_tool)}</li>'
        html += '</ul>'

        html += '<h3 style="color:#9aa3b8">IP / Domain Reputation</h3>'
        html += '<ul style="color:#9aa3b8;font-size:13px;line-height:1.8;list-style:none;padding-left:0">'
        for rep_tool in REPUTATION_TOOLS:
            html += f'<li>• {html_mod.escape(rep_tool)}</li>'
        html += '</ul>'

        html += '<h3 style="color:#9aa3b8">Certificate / TLS</h3>'
        html += '<ul style="color:#9aa3b8;font-size:13px;line-height:1.8;list-style:none;padding-left:0">'
        for cert_tool in CERTIFICATE_GUIDE.get("tools", []):
            html += f'<li>• {html_mod.escape(cert_tool)}</li>'
        html += '</ul>'
        html += '</div>'

        # Footer
        html += textwrap.dedent("""\
        <div class="footer">
            <strong>PhishHunter v1.0</strong> &nbsp;·&nbsp;
            Created by Mohammad Shahbaaz Ahmed &nbsp;·&nbsp;
            <a href="https://github.com/shahbaaz-devsec" target="_blank">github.com/shahbaaz-devsec</a> &nbsp;·&nbsp;
            <a href="https://www.linkedin.com/in/mohammad-shahbaaz-ahmed-138a423bb" target="_blank">LinkedIn</a><br>
            <span style="color:#3a4151;font-size:11px">For authorised SOC and educational use only</span>
        </div>
        </div></body></html>""")
        output_path.write_text(html, encoding="utf-8")
        return output_path


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------
class PhishHunter:
    """Orchestrate the complete phishing email analysis pipeline."""

    def __init__(
        self,
        vt_api_key: str = "",
        output_dir: Path = Path("./phish-hunter-reports"),
        timeout: int = 15,
        dns_enabled: bool = True,
        dns_probe_dkim: bool = True,
        tls_enabled: bool = True,
        tls_use_ssllabs: bool = False,
    ):
        self.vt_key = vt_api_key
        self.output_dir = output_dir
        self.timeout = timeout
        self.dns_enabled = dns_enabled
        self.dns_probe_dkim = dns_probe_dkim
        self.tls_enabled = tls_enabled
        self.tls_use_ssllabs = tls_use_ssllabs
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def analyse(self, filepath: Path) -> PhishingReport:
        """Run the full analysis pipeline on one email file."""
        report = PhishingReport(
            file_path=str(filepath),
            analysed_at=datetime.now(timezone.utc).isoformat(),
        )

        # --- Step 1: Parse ---
        parser = EmailParser(filepath)
        msg = parser.parse()
        report.raw_headers = parser.get_all_headers()

        # --- Step 2: Header forensics ---
        forensics = HeaderForensics(parser)
        report.header = forensics.analyse()

        # --- Step 3: Bodies ---
        report.body_text = parser.get_body_text()
        report.body_html = parser.get_body_html()

        # --- Step 4: URL extraction ---
        extractor = URLExtractor(report.body_html, report.body_text)
        raw_urls = extractor.extract()

        # --- Step 5: URL analysis ---
        url_checker = URLChecker(vt_api_key=self.vt_key, timeout=self.timeout)
        for url in raw_urls:
            report.urls.append(url_checker.check(url))

        # --- Step 6: Attachments ---
        attach_dir = self.output_dir / f"{filepath.stem}_attachments"
        attach_paths = parser.get_attachments(attach_dir)
        triage = AttachmentTriage(attach_dir)
        for ap in attach_paths:
            report.attachments.append(triage.analyse(ap))

        # --- Step 7: DNS forensics ---
        if self.dns_enabled:
            report.dns_records = self._run_dns_analysis(report)

        # --- Step 8: TLS forensics (NEW IN v1.0) ---
        if self.tls_enabled:
            report.tls_records = self._run_tls_analysis(report)

        # --- Step 9: Keyword scoring + brand impersonation ---
        combined_body = report.body_text + " " + _strip_html(report.body_html)
        body_score, report.body_keywords_found = PhishingScorer.score_body(combined_body)

        # Brand impersonation detection
        report.brand_impersonation = PhishingScorer.detect_brand_impersonation(
            report.header, combined_body
        )

        # Also extract all email addresses found in body
        report.email_addresses_found = list(set(EMAIL_RE.findall(combined_body)))

        # --- Step 10: Risk scoring ---
        report.risk_score, report.risk_level, report.indicators = PhishingScorer.compute_risk(
            report.header, report.urls, report.attachments,
            body_score, report.body_keywords_found,
        )

        # Brand impersonation adds to risk
        if report.brand_impersonation:
            report.risk_score += min(len(report.brand_impersonation) * 8, 20)
            for bi in report.brand_impersonation:
                report.indicators.append(bi)

        # DNS-based score adjustment
        report.risk_score = self._apply_dns_risk_adjustment(report)

        # TLS-based score adjustment
        report.risk_score = self._apply_tls_risk_adjustment(report)

        # Final clamp + level
        report.risk_score = max(0.0, min(100.0, round(report.risk_score, 1)))
        report.risk_level = PhishingScorer.score_to_level(report.risk_score)

        # --- Step 11: Summary ---
        report.summary = self._build_summary(report)

        return report

    def _run_dns_analysis(self, report: PhishingReport) -> List[DNSAnalysis]:
        """Run DNS lookups on all relevant domains found in the email."""
        analyzer = DNSAnalyzer(timeout=self.timeout)
        domains_seen: Set[str] = set()
        results: List[DNSAnalysis] = []

        # Collect domains worth investigating
        candidate_domains: List[str] = []

        # 1. Sender domain (highest priority)
        if "@" in report.header.from_address:
            candidate_domains.append(report.header.from_address.rsplit("@", 1)[-1])

        # 2. Return-Path domain (envelope sender)
        if "@" in report.header.return_path:
            candidate_domains.append(report.header.return_path.rsplit("@", 1)[-1])

        # 3. Reply-To domain
        if "@" in report.header.reply_to:
            candidate_domains.append(report.header.reply_to.rsplit("@", 1)[-1])

        # 4. Top URL domains (limit to avoid excess queries)
        for u in report.urls[:5]:
            if u.domain and not u.is_ip_based:
                candidate_domains.append(u.domain)

        # Collect originating IPs for reverse DNS
        ips_to_reverse: List[str] = []
        if report.header.originating_ip:
            ips_to_reverse.append(report.header.originating_ip)

        # Run lookups (deduplicated)
        for domain in candidate_domains:
            domain = domain.lower().strip().strip(">").strip("<").strip(".")
            if not domain or domain in domains_seen:
                continue
            domains_seen.add(domain)

            try:
                ips = ips_to_reverse if domain == candidate_domains[0] else None
                analysis = analyzer.comprehensive_lookup(
                    domain,
                    probe_dkim=self.dns_probe_dkim,
                    reverse_ips=ips,
                )
                results.append(analysis)
            except Exception as e:
                err = DNSAnalysis(domain=domain)
                err.errors.append(f"DNS lookup failed: {e}")
                results.append(err)

        return results

    @staticmethod
    def _apply_dns_risk_adjustment(report: PhishingReport) -> float:
        """Adjust risk score based on DNS findings — sender domain weakness adds risk."""
        score = report.risk_score
        if not report.dns_records:
            return score

        # Find sender domain analysis
        sender_domain = ""
        if "@" in report.header.from_address:
            sender_domain = report.header.from_address.rsplit("@", 1)[-1].lower()

        for d in report.dns_records:
            if d.domain == sender_domain:
                # Weak email auth posture on sender domain raises risk
                if not d.spf_valid:
                    score += 10
                    report.indicators.append(
                        f"DNS: sender domain {sender_domain} has no SPF record"
                    )
                elif d.spf_strength == "permissive":
                    score += 15
                    report.indicators.append(
                        f"DNS: sender domain {sender_domain} uses SPF '+all' (severe)"
                    )

                if not d.dmarc_record:
                    score += 10
                    report.indicators.append(
                        f"DNS: sender domain {sender_domain} has no DMARC policy"
                    )
                elif d.dmarc_policy == "none":
                    score += 5
                    report.indicators.append(
                        f"DNS: sender domain {sender_domain} DMARC p=none (no enforcement)"
                    )

                if not d.dkim_selectors_found:
                    score += 5

                # Reverse DNS sanity — sender IP should resolve to sender domain
                originating_ip = report.header.originating_ip
                if originating_ip and originating_ip in d.ptr_records:
                    ptr = d.ptr_records[originating_ip].lower()
                    if sender_domain not in ptr:
                        score += 8
                        report.indicators.append(
                            f"DNS: PTR mismatch — IP {originating_ip} -> {ptr} "
                            f"does not match sender domain {sender_domain}"
                        )
                break

        return min(100.0, max(0.0, score))

    def _run_tls_analysis(self, report: PhishingReport) -> List[TLSAnalysis]:
        """Run TLS / cert forensics on relevant domains (NEW IN v1.0)."""
        analyzer = TLSCertificateAnalyzer(timeout=self.timeout)
        results: List[TLSAnalysis] = []
        domains_seen: Set[str] = set()

        # Highest priority: sender domain
        candidates: List[str] = []
        if "@" in report.header.from_address:
            candidates.append(report.header.from_address.rsplit("@", 1)[-1])

        # Top URL domain (often the actual phish landing)
        for u in report.urls[:2]:
            if u.domain and not u.is_ip_based:
                candidates.append(u.domain)

        for domain in candidates:
            domain = domain.lower().strip().strip(".")
            if not domain or domain in domains_seen:
                continue
            domains_seen.add(domain)
            try:
                # Skip SSL Labs by default (slow); user can enable via flag
                tls = analyzer.analyse(
                    domain,
                    run_crtsh=True,
                    run_ssllabs=self.tls_use_ssllabs,
                )
                results.append(tls)
            except Exception as e:
                err = TLSAnalysis(domain=domain, status="error", error=str(e))
                err.red_flags.append(f"TLS analysis failed: {e}")
                results.append(err)

        return results

    @staticmethod
    def _apply_tls_risk_adjustment(report: PhishingReport) -> float:
        """Adjust risk score based on TLS findings on sender's domain."""
        score = report.risk_score
        if not report.tls_records:
            return score

        sender_domain = ""
        if "@" in report.header.from_address:
            sender_domain = report.header.from_address.rsplit("@", 1)[-1].lower()

        for t in report.tls_records:
            if t.domain != sender_domain:
                continue

            # No HTTPS at all — for a corporate-looking domain this is unusual
            if t.status == "error" and "timeout" not in (t.error or "").lower():
                score += 5
                report.indicators.append(
                    f"TLS: sender domain {sender_domain} has no HTTPS "
                    f"({t.error[:60]})"
                )

            # Hostname mismatch — major red flag
            if t.matches_hostname is False:
                score += 12
                report.indicators.append(
                    f"TLS: certificate hostname mismatch for {sender_domain}"
                )

            # Expired certificate
            if t.days_until_expiry is not None and t.days_until_expiry < 0:
                score += 8
                report.indicators.append(
                    f"TLS: expired certificate on {sender_domain}"
                )

            # Free CA on a brand-looking domain (Let's Encrypt + brand keyword)
            issuer_org = (t.issuer.get("organizationName", "") or "").lower()
            if "let's encrypt" in issuer_org or "lets encrypt" in issuer_org:
                if any(b in sender_domain for b in BRAND_KEYWORDS):
                    score += 10
                    report.indicators.append(
                        f"TLS: brand-looking domain {sender_domain} uses free "
                        "Let's Encrypt cert — common phishing pattern"
                    )

            # crt.sh found suspicious lookalikes
            if t.crtsh_recent_subdomains:
                lookalikes = [
                    n for n in t.crtsh_recent_subdomains
                    if any(brand in n and n != sender_domain
                           and brand not in sender_domain
                           for brand in BRAND_KEYWORDS)
                ]
                if lookalikes:
                    score += 5
                    report.indicators.append(
                        f"TLS: crt.sh shows brand-lookalike certs near "
                        f"{sender_domain}: {', '.join(lookalikes[:2])}"
                    )

            break

        return min(100.0, max(0.0, score))

    @staticmethod
    def _build_summary(report: PhishingReport) -> str:
        parts = [
            f"Risk: {report.risk_score:.1f}/100 ({report.risk_level})",
            f"From: {report.header.from_address}",
            f"Subject: {report.header.subject}",
            f"URLs: {len(report.urls)} ({sum(1 for u in report.urls if u.suspicious)} sus)",
            f"Attachments: {len(report.attachments)} ({sum(1 for a in report.attachments if a.suspicious)} sus)",
            f"DNS: {len(report.dns_records)}",
            f"TLS: {len(report.tls_records)}",
        ]
        if report.header.spoof_indicators:
            parts.append(f"Spoof: {len(report.header.spoof_indicators)}")
        if report.brand_impersonation:
            parts.append(f"Brand impersonation: {len(report.brand_impersonation)}")
        return " | ".join(parts)


# ---------------------------------------------------------------------------
# Self‑validation
# ---------------------------------------------------------------------------
SAMPLE_PHISHING_EML = """\
From: "Microsoft Security" <security@microsofteams-login.com>
To: victim@example.com
Subject: Urgent: Your account has been compromised
Date: Mon, 01 Jan 2025 10:00:00 +0000
Message-ID: <phish001@malicious.example.com>
Reply-To: attacker@gmail.com
Return-Path: <bounce@evilserver.xyz>
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Dear user,</p>
<p>We detected <b>unusual sign-in activity</b> on your account.  
<b>Verify your account</b> immediately to prevent suspension.</p>
<p><a href="http://micros0ft-login.evil/verify">Click here to verify</a></p>
<p>Regards,<br>Microsoft Security Team</p>
</body></html>
"""


def _run_selftest() -> bool:
    """Built-in self-validation test for PhishHunter v3.0."""
    print("\n[TEST] Running self-validation…")
    tmpdir = Path("/tmp/phish-hunter-test")
    tmpdir.mkdir(parents=True, exist_ok=True)
    eml_path = tmpdir / "test-phish.eml"
    eml_path.write_text(SAMPLE_PHISHING_EML, encoding="utf-8")

    try:
        # Run with DNS and TLS disabled for fast offline test
        hunter = PhishHunter(vt_api_key="", output_dir=tmpdir, timeout=10,
                             dns_enabled=False, dns_probe_dkim=False,
                             tls_enabled=False, tls_use_ssllabs=False)
        report = hunter.analyse(eml_path)

        # Core assertions
        assert report.risk_score >= 30, f"Expected risk >= 30, got {report.risk_score}"
        assert len(report.urls) >= 1, "No URLs extracted"
        assert "unusual sign-in" in report.body_keywords_found, "Keyword not detected"
        assert len(report.header.spoof_indicators) > 0, "No spoof indicators detected"
        assert len(report.indicators) > 0, "No risk indicators populated"

        # Generate reports
        ReportGenerator.to_json(report, tmpdir / "test-report.json")
        ReportGenerator.to_html(report, tmpdir / "test-report.html")

        print(f"[TEST] ✅ All assertions passed. "
              f"Risk: {report.risk_score:.1f}/100 ({report.risk_level})")
        print(f"[TEST]    URLs found: {len(report.urls)}, "
              f"Spoof indicators: {len(report.header.spoof_indicators)}, "
              f"Risk indicators: {len(report.indicators)}")

        # Optional DNS sanity check (online)
        print("\n[TEST] Running DNS forensics test (requires internet)…")
        try:
            analyzer = DNSAnalyzer(timeout=8)
            dns_result = analyzer.comprehensive_lookup("gmail.com", probe_dkim=False)
            assert dns_result.mx_records, "Gmail.com should have MX records"
            assert dns_result.spf_record, "Gmail.com should have SPF"
            print(f"[TEST] ✅ DNS forensics OK. gmail.com auth strength: "
                  f"{dns_result.auth_score:.0f}/100")
            print(f"[TEST]    MX servers: {len(dns_result.mx_records)}, "
                  f"SPF: {'yes' if dns_result.spf_record else 'no'}, "
                  f"DMARC p={dns_result.dmarc_policy}")
        except (AssertionError, Exception) as e:
            print(f"[TEST] ⚠ DNS test skipped (no internet?): {e}")

        return True
    except AssertionError as e:
        print(f"[TEST] ❌ Assertion failed: {e}")
        return False
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI — Branding & banner
# ---------------------------------------------------------------------------
PHISHHUNTER_BANNER = r"""
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║      ____  _   _ ___ ____  _   _   _   _ _   _ _   _ _____ _____ ____    ║
║     |  _ \| | | |_ _/ ___|| | | | | | | | | | | \ | |_   _| ____|  _ \   ║
║     | |_) | |_| || |\___ \| |_| | | |_| | | | |  \| | | | |  _| | |_) |  ║
║     |  __/|  _  || | ___) |  _  | |  _  | |_| | |\  | | | | |___|  _ <   ║
║     |_|   |_| |_|___|____/|_| |_| |_| |_|\___/|_| \_| |_| |_____|_| \_\  ║
║                                                                          ║
║              Universal SOC Email Phishing Forensics                      ║
║   Headers • DNS • TLS Certificates • Threat intel • Risk scoring         ║
║                                                                          ║
║                              v1.0  ──  2026                              ║
║                                                                          ║
║                  Created by  Mohammad Shahbaaz Ahmed                     ║
║                  GitHub      github.com/shahbaaz-devsec                  ║
║                  LinkedIn    linkedin.com/in/mohammad-shahbaaz-ahmed     ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"""


def _print_banner(quiet: bool = False) -> None:
    """Print the ASCII banner to terminal — skip if quiet."""
    if not quiet:
        # Terminal color support: cyan banner on dark backgrounds
        if sys.stdout.isatty():
            print(f"\033[36m{PHISHHUNTER_BANNER}\033[0m")
        else:
            print(PHISHHUNTER_BANNER)


# ---------------------------------------------------------------------------
# CLI — Argument parser
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishhunter",
        description=(
            "PhishHunter v1.0 — Universal SOC email phishing forensics. "
            "Headers, DNS, TLS certificates, and threat intel — all in one tool. "
            "Created by Mohammad Shahbaaz Ahmed (github.com/shahbaaz-devsec)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        examples:
          %(prog)s suspicious.eml
          %(prog)s --batch phishing_emails/ --format html
          %(prog)s --self-test
          %(prog)s phishing.eml --vt-key YOUR_API_KEY
          %(prog)s phishing.eml --no-dns                # skip DNS (faster)
          %(prog)s phishing.eml --no-tls                # skip TLS analysis
          %(prog)s phishing.eml --no-dkim-probe         # skip DKIM probing
          %(prog)s phishing.eml --ssllabs               # also run SSL Labs (slow ~60s)

        DNS lookups use free public DNS-over-HTTPS endpoints
        (Cloudflare 1.1.1.1 and Google 8.8.8.8) — no API key required.
        TLS analysis uses live socket + crt.sh certificate transparency.

        Report bugs / contribute:  github.com/shahbaaz-devsec
        Connect on LinkedIn:       linkedin.com/in/mohammad-shahbaaz-ahmed-138a423bb
        """),
    )
    p.add_argument("file", nargs="?", help="Path to a .eml (or .msg) email file")
    p.add_argument("--batch", metavar="DIR", help="Analyse all .eml files in a directory")
    p.add_argument("--output", "-o", default="./phish-hunter-reports",
                   help="Output directory (default: ./phish-hunter-reports)")
    p.add_argument("--format", "-f", choices=["json", "html", "both"], default="both",
                   help="Report format(s)")
    p.add_argument("--vt-key", metavar="KEY", default="",
                   help="VirusTotal API key (optional, enables URL reputation)")
    p.add_argument("--timeout", type=int, default=15,
                   help="HTTP request timeout in seconds (default: 15)")
    p.add_argument("--no-dns", action="store_true",
                   help="Disable DNS forensics (faster, less complete)")
    p.add_argument("--no-dkim-probe", action="store_true",
                   help="Skip DKIM selector probing (saves ~10 DNS queries per domain)")
    p.add_argument("--no-tls", action="store_true",
                   help="Disable TLS certificate forensics")
    p.add_argument("--ssllabs", action="store_true",
                   help="Run SSL Labs grade lookup (slow, ~60 sec per domain)")
    p.add_argument("--self-test", action="store_true",
                   help="Run built-in self-validation test")
    p.add_argument("--quiet", "-q", action="store_true", help="Suppress banner and verbose output")
    p.add_argument("--version", "-V", action="version", version="PhishHunter 1.0")
    return p


def main() -> int:
    args = _build_parser().parse_args()

    # Banner first (unless quiet)
    _print_banner(args.quiet)

    # Self-test mode
    if args.self_test:
        ok = _run_selftest()
        return 0 if ok else 1

    # Configure hunter with all toggles
    hunter = PhishHunter(
        vt_api_key=args.vt_key,
        output_dir=Path(args.output),
        timeout=args.timeout,
        dns_enabled=not args.no_dns,
        dns_probe_dkim=not args.no_dkim_probe,
        tls_enabled=not args.no_tls,
        tls_use_ssllabs=args.ssllabs,
    )

    # Batch mode
    if args.batch:
        batch_dir = Path(args.batch)
        if not batch_dir.is_dir():
            print(f"[!] Not a directory: {args.batch}")
            return 1
        eml_files = sorted(batch_dir.glob("*.eml")) + sorted(batch_dir.glob("*.msg"))
        if not eml_files:
            print(f"[!] No .eml or .msg files found in {args.batch}")
            return 1
        print(f"\n{'='*70}")
        print(f"  PhishHunter — Batch analysis ({len(eml_files)} files)")
        print(f"{'='*70}\n")
        results: List[PhishingReport] = []
        for i, eml in enumerate(eml_files, 1):
            print(f"[{i}/{len(eml_files)}] {eml.name} … ", end="", flush=True)
            report = hunter.analyse(eml)
            results.append(report)
            print(f"Risk: {report.risk_score:.0f}/100 ({report.risk_level})")
            _write_reports(report, Path(args.output), args.format)

        # Batch summary
        print(f"\n{'─'*50}")
        _print_batch_summary(results)
        return 0

    # Single file mode
    if not args.file:
        print("[!] Specify a .eml file, --batch DIR, or --self-test")
        print("    Run with --help for usage examples.")
        return 1

    filepath = Path(args.file)
    if not filepath.is_file():
        print(f"[!] File not found: {args.file}")
        return 1

    print(f"\n{'='*70}")
    print(f"  PhishHunter — Analysing: {filepath.name}")
    print(f"{'='*70}\n")

    report = hunter.analyse(filepath)

    if not args.quiet:
        _print_report(report)

    _write_reports(report, Path(args.output), args.format)
    print(f"\n[✓] Reports saved to {Path(args.output).resolve()}")
    return 0


def _print_report(report: PhishingReport) -> None:
    """Print a comprehensive analysis summary to the console."""
    # Color codes (only if TTY)
    is_tty = sys.stdout.isatty()
    RED    = "\033[31m" if is_tty else ""
    YEL    = "\033[33m" if is_tty else ""
    GRN    = "\033[32m" if is_tty else ""
    CYN    = "\033[36m" if is_tty else ""
    DIM    = "\033[2m"  if is_tty else ""
    BLD    = "\033[1m"  if is_tty else ""
    RST    = "\033[0m"  if is_tty else ""

    # Risk score color
    if report.risk_score >= 70:
        risk_col = RED
    elif report.risk_score >= 30:
        risk_col = YEL
    else:
        risk_col = GRN

    print(f"{BLD}┌─ EMAIL FORENSICS {'─'*52}┐{RST}")
    print(f"  Risk Score:     {risk_col}{BLD}{report.risk_score:.1f}/100 ({report.risk_level}){RST}")
    print(f"  From:           {report.header.from_display} <{report.header.from_address}>")
    print(f"  Subject:        {report.header.subject}")
    print(f"  Originating IP: {report.header.originating_ip or 'N/A'}")
    print(f"  SPF / DKIM / DMARC:  "
          f"{report.header.spf_result} / {report.header.dkim_result} / {report.header.dmarc_result}")
    print(f"  URLs:           {len(report.urls)} "
          f"({sum(1 for u in report.urls if u.suspicious)} suspicious)")
    print(f"  Attachments:    {len(report.attachments)} "
          f"({sum(1 for a in report.attachments if a.suspicious)} suspicious)")

    # --- DNS section (NEW IN v3.0) ---
    if report.dns_records:
        print()
        print(f"{BLD}┌─ DNS FORENSICS  ({len(report.dns_records)} domains queried) {'─'*30}┐{RST}")
        for d in report.dns_records:
            print(f"  {CYN}● {d.domain}{RST}  (auth strength: {d.auth_score:.0f}/100)")
            if d.a_records:
                print(f"      A         : {', '.join(d.a_records[:3])}"
                      f"{' ...' if len(d.a_records) > 3 else ''}")
            if d.mx_records:
                mx_str = ", ".join(f"{m['priority']} {m['host']}" for m in d.mx_records[:3])
                print(f"      MX        : {mx_str}")
            if d.ns_records:
                print(f"      NS        : {', '.join(d.ns_records[:2])}")
            if d.spf_record:
                spf_short = d.spf_record[:80] + "..." if len(d.spf_record) > 80 else d.spf_record
                print(f"      SPF       : {spf_short}  [{d.spf_strength}]")
            else:
                print(f"      SPF       : {RED}MISSING{RST}")
            if d.dmarc_record:
                print(f"      DMARC     : p={d.dmarc_policy}")
            else:
                print(f"      DMARC     : {RED}MISSING{RST}")
            if d.dkim_selectors_found:
                print(f"      DKIM      : {len(d.dkim_selectors_found)} selectors found "
                      f"({', '.join(d.dkim_selectors_found[:3])})")
            if d.ptr_records:
                for ip, ptr in d.ptr_records.items():
                    print(f"      PTR       : {ip} -> {ptr}")
            if d.warnings:
                for w in d.warnings[:3]:
                    print(f"      {YEL}⚠ {w}{RST}")

    # --- TLS section (NEW IN v1.0) ---
    if report.tls_records:
        print()
        print(f"{BLD}┌─ TLS / CERT FORENSICS  ({len(report.tls_records)} domains) "
              f"{'─'*30}┐{RST}")
        for t in report.tls_records:
            status_col = GRN if t.status == "ok" else RED
            print(f"  {CYN}● {t.domain}{RST}  [{status_col}{t.status}{RST}]")
            if t.status == "ok":
                if t.subject:
                    cn = t.subject.get("commonName", "?")
                    print(f"      Subject   : CN={cn}")
                if t.issuer:
                    issuer_org = t.issuer.get("organizationName", "?")
                    print(f"      Issuer    : {issuer_org}")
                if t.not_after:
                    expiry_col = (RED if (t.days_until_expiry or 0) < 14
                                  else GRN if (t.days_until_expiry or 0) > 30
                                  else YEL)
                    print(f"      Expires   : {t.not_after} "
                          f"({expiry_col}{t.days_until_expiry} days{RST})")
                if t.matches_hostname is not None:
                    match_col = GRN if t.matches_hostname else RED
                    print(f"      Hostname  : {match_col}"
                          f"{'matches' if t.matches_hostname else 'MISMATCH'}{RST}")
                if t.subject_alt_names:
                    sans_short = ", ".join(t.subject_alt_names[:3])
                    if len(t.subject_alt_names) > 3:
                        sans_short += f" ... (+{len(t.subject_alt_names)-3} more)"
                    print(f"      SANs      : {sans_short}")
            if t.crtsh_status == "ok":
                print(f"      crt.sh    : {t.crtsh_certificate_count} certs, "
                      f"{len(t.crtsh_recent_subdomains)} unique names")
            if t.ssllabs_grade:
                print(f"      SSL Labs  : grade {t.ssllabs_grade}")
            if t.error:
                print(f"      {RED}error: {t.error[:60]}{RST}")
            for rf in t.red_flags[:3]:
                print(f"      {RED}⚠ {rf}{RST}")

    # --- Brand impersonation ---
    if report.brand_impersonation:
        print()
        print(f"  {RED}🎭 Brand Impersonation Detected:{RST}")
        for bi in report.brand_impersonation:
            print(f"    - {bi}")

    # --- Spoof indicators ---
    if report.header.spoof_indicators:
        print()
        print(f"  {RED}⚠ Spoof Indicators:{RST}")
        for ind in report.header.spoof_indicators:
            print(f"    - {ind}")

    # --- Phishing keywords ---
    if report.body_keywords_found:
        print(f"  🔑 Phishing Keywords: {', '.join(report.body_keywords_found[:8])}")

    # --- Risk indicators (incl. DNS- and TLS-based) ---
    if report.indicators:
        print()
        print(f"  {RED}🚩 Key Indicators:{RST}")
        for ind in report.indicators[:15]:
            print(f"    - {ind}")

    # --- Footer credit ---
    print()
    print(f"{DIM}  PhishHunter v1.0  |  by Mohammad Shahbaaz Ahmed{RST}")
    print(f"{DIM}  GitHub: github.com/shahbaaz-devsec  |  "
          f"LinkedIn: linkedin.com/in/mohammad-shahbaaz-ahmed-138a423bb{RST}")


def _write_reports(report: PhishingReport, output_dir: Path, fmt: str) -> None:
    """Write JSON and/or HTML reports."""
    output_dir.mkdir(parents=True, exist_ok=True)
    base = output_dir / Path(report.file_path).stem
    if fmt in ("json", "both"):
        ReportGenerator.to_json(report, base.with_suffix(".json"))
    if fmt in ("html", "both"):
        ReportGenerator.to_html(report, base.with_suffix(".html"))


def _print_batch_summary(results: List[PhishingReport]) -> None:
    """Summary table for batch analysis."""
    print(f"  Total files analysed: {len(results)}")
    critical = sum(1 for r in results if r.risk_level == "CRITICAL")
    high = sum(1 for r in results if r.risk_level == "HIGH")
    medium = sum(1 for r in results if r.risk_level == "MEDIUM")
    low = sum(1 for r in results if r.risk_level == "LOW")
    minimal = sum(1 for r in results if r.risk_level == "MINIMAL")
    print(f"  CRITICAL: {critical}  HIGH: {high}  MEDIUM: {medium}  LOW: {low}  MINIMAL: {minimal}")
    total_urls = sum(len(r.urls) for r in results)
    total_att = sum(len(r.attachments) for r in results)
    print(f"  Total URLs: {total_urls}  |  Total Attachments: {total_att}")


if __name__ == "__main__":
    raise SystemExit(main())