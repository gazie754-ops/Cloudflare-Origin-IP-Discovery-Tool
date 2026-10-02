#!/usr/bin/env python3
"""
cf-origin-hunter.py — Cloudflare Origin IP Discovery Tool
Author: Security Research Tool
Version: 1.0.0
License: MIT

WARNING: This tool is for AUTHORIZED security research ONLY.
Use only on domains you own or have explicit written permission to test.
Unauthorized scanning is illegal and unethical.
"""

import argparse
import ipaddress
import json
import random
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

# Third-party imports
try:
    import dns.resolver
    import dns.exception
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Install with: pip install dnspython requests[socks]")
    sys.exit(1)

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPV6_URL = "https://www.cloudflare.com/ips-v6"

# Free passive DNS / historical record sources
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
RAPIDDNS_URL = "https://rapiddns.io/subdomain/{domain}?full=1"

# Common subdomain wordlist (short built-in fallback)
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
    "web", "media", "email", "images", "img", "www1", "intranet", "portal",
    "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3",
    "dns", "search", "staging", "server", "mx1", "chat", "wap", "my", "svn",
    "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2",
    "lyncdiscover", "info", "apps", "download", "remote", "db", "forums",
    "store", "relay", "files", "newsletter", "app", "live", "owa", "en",
    "start", "sms", "office", "exchange", "ipv4", "help", "blogs", "upload",
    "downloads", "login", "signup", "register", "account", "dashboard",
    "panel", "manage", "control", "system", "status", "health", "monitor",
    "metrics", "logs", "debug", "trace", "internal", "corp", "private",
    "secret", "hidden", "legacy", "archive", "backup", "temp", "tmp",
    "sandbox", "qa", "uat", "preprod", "prod", "production", "development",
    "origin", "direct", "real", "backend", "upstream", "pool", "cluster",
    "node", "edge", "gateway", "router", "switch", "firewall", "waf",
]

# Common prefixes used in decoy requests
DECOY_PREFIXES = [
    "decoy-", "scan-", "test-", "probe-", "check-", "verify-", "audit-",
    "recon-", "x-", "tmp-", "fake-", "dummy-", "noise-", "shadow-",
]


# ──────────────────────────────────────────────
# Data Classes
# ──────────────────────────────────────────────

@dataclass
class Finding:
    """Represents a discovered IP candidate."""
    ip: str
    source: str
    confidence: str = "low"  # low, medium, high
    detail: str = ""


@dataclass
class ScanResult:
    """Aggregated results from all phases."""
    domain: str
    cloudflare_ips: set = field(default_factory=set)
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    decoy_count: int = 0


# ──────────────────────────────────────────────
# HTTP Session Builder (with optional Tor)
# ──────────────────────────────────────────────

def build_session(use_tor: bool = False, tor_port: int = 9050) -> requests.Session:
    """
    Build a requests session with optional Tor SOCKS5 routing.
    Uses socks5h to force DNS resolution through Tor as well.
    """
    session = requests.Session()

    # Retry adapter for transient failures
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    if use_tor:
        proxy = f"socks5h://127.0.0.1:{tor_port}"
        session.proxies = {
            "http": proxy,
            "https": proxy,
        }
        print(f"[*] Tor routing enabled via {proxy}")

    # Realistic user-agent
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    })

    return session


def check_tor_connectivity(session: requests.Session) -> bool:
    """Verify Tor is actually working by checking the exit IP."""
    try:
        resp = session.get("https://check.torproject.org/api/ip", timeout=15)
        data = resp.json()
        if data.get("IsTor"):
            print(f"[+] Tor active — exit node: {data.get('IP', 'unknown')}")
            return True
        else:
            print("[!] Tor check says traffic is NOT routed through Tor.")
            return False
    except Exception as e:
        print(f"[!] Tor connectivity check failed: {e}")
        return False


# ──────────────────────────────────────────────
# Cloudflare IP Range Handling
# ──────────────────────────────────────────────

def fetch_cloudflare_ranges(session: requests.Session) -> set:
    """
    Fetch current Cloudflare IP ranges (IPv4 + IPv6).
    Returns a set of ipaddress network objects.
    """
    ranges = set()
    for url in [CLOUDFLARE_IPV4_URL, CLOUDFLARE_IPV6_URL]:
        try:
            resp = session.get(url, timeout=20)
            if resp.status_code == 200:
                for line in resp.text.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ranges.add(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        continue
        except Exception as e:
            print(f"[!] Failed to fetch Cloudflare ranges from {url}: {e}")

    if ranges:
        print(f"[+] Loaded {len(ranges)} Cloudflare CIDR ranges.")
    else:
        print("[!] Could not fetch Cloudflare ranges. Proceeding without filtering.")
    return ranges


def is_cloudflare_ip(ip: str, ranges: set) -> bool:
    """Check if an IP belongs to Cloudflare's published ranges."""
    if not ranges:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        for net in ranges:
            if addr in net:
                return True
    except ValueError:
        pass
    return False


# ──────────────────────────────────────────────
# Phase 1: Misconfigured DNS Checks
# ──────────────────────────────────────────────

def check_dns_misconfig(domain: str, session: requests.Session,
                        cf_ranges: set) -> list:
    """
    Phase 1: Look for misconfigured DNS records that might leak the origin.
    Checks: SPF, MX, TXT, CNAME, NS, and subdomain CNAMEs.
    """
    findings = []
    print("\n" + "=" * 60)
    print("[PHASE 1] Misconfigured DNS & Record Analysis")
    print("=" * 60)

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            for answer in answers:
                text = answer.to_text()

                # Check for non-Cloudflare IPs in A/AAAA records
                if rtype in ("A", "AAAA"):
                    ip = text.strip()
                    if not is_cloudflare_ip(ip, cf_ranges):
                        findings.append(Finding(
                            ip=ip,
                            source="DNS-A/AAAA",
                            confidence="high",
                            detail=f"Direct {rtype} record for {domain} (not Cloudflare)"
                        ))
                        print(f"  [+] Non-CF {rtype} record: {ip}")

                # Extract IPs from SPF records
                if rtype == "TXT" and "v=spf1" in text.lower():
                    ips = re.findall(r"ip4:([0-9.]+)|ip6:([0-9a-fA-F:]+)", text)
                    for ip4, ip6 in ips:
                        ip = ip4 or ip6
                        if ip and not is_cloudflare_ip(ip, cf_ranges):
                            findings.append(Finding(
                                ip=ip,
                                source="SPF",
                                confidence="medium",
                                detail=f"IP in SPF record: {text[:80]}"
                            ))
                            print(f"  [+] SPF-leaked IP: {ip}")

                # MX records that point to non-CF IPs
                if rtype == "MX":
                    mx_host = text.split()[-1].rstrip(".")
                    try:
                        mx_answers = resolver.resolve(mx_host, "A")
                        for mx_ans in mx_answers:
                            ip = mx_ans.to_text().strip()
                            if not is_cloudflare_ip(ip, cf_ranges):
                                findings.append(Finding(
                                    ip=ip,
                                    source="MX",
                                    confidence="medium",
                                    detail=f"MX host {mx_host} resolves to {ip}"
                                ))
                                print(f"  [+] MX-leaked IP: {ip} (via {mx_host})")
                    except Exception:
                        pass

        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            print(f"  [!] {domain} does not exist (NXDOMAIN).")
            break
        except dns.exception.Timeout:
            print(f"  [!] Timeout resolving {rtype} for {domain}.")
        except Exception as e:
            print(f"  [!] Error resolving {rtype}: {e}")

    if not findings:
        print("  [-] No misconfigured DNS records found.")

    return findings


# ──────────────────────────────────────────────
# Phase 2: Historical Database Records
# ──────────────────────────────────────────────

def query_crtsh(domain: str, session: requests.Session) -> list:
    """Query crt.sh for certificate transparency subdomains."""
    findings = []
    url = CRTSH_URL.format(domain=domain)
    try:
        resp = session.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            seen = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub and sub not in seen and "*" not in sub:
                        seen.add(sub)
            print(f"  [+] crt.sh returned {len(seen)} unique names.")
            return list(seen)
    except Exception as e:
        print(f"  [!] crt.sh query failed: {e}")
    return findings


def query_hackertarget(domain: str, session: requests.Session) -> list:
    """Query HackerTarget free host search API."""
    findings = []
    url = HACKERTARGET_URL.format(domain=domain)
    try:
        resp = session.get(url, timeout=20)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.strip().splitlines():
                parts = line.split(",")
                if len(parts) >= 2:
                    host, ip = parts[0].strip(), parts[1].strip()
                    if ip and not ip.startswith("0."):
                        findings.append((host, ip))
            print(f"  [+] HackerTarget returned {len(findings)} host/IP pairs.")
        else:
            print(f"  [!] HackerTarget returned no data or rate limit.")
    except Exception as e:
        print(f"  [!] HackerTarget query failed: {e}")
    return findings


def query_rapiddns(domain: str, session: requests.Session) -> list:
    """Scrape RapidDNS for subdomain enumeration."""
    findings = []
    url = RAPIDDNS_URL.format(domain=domain)
    try:
        resp = session.get(url, timeout=25)
        if resp.status_code == 200:
            # Simple regex extraction from HTML table
            matches = re.findall(
                r"<td>([a-zA-Z0-9._-]+\.?" + re.escape(domain) + r")</td>\s*<td>([0-9a-fA-F.:]+)</td>",
                resp.text
            )
            for host, ip in matches:
                findings.append((host.strip(), ip.strip()))
            print(f"  [+] RapidDNS returned {len(findings)} entries.")
        else:
            print(f"  [!] RapidDNS returned HTTP {resp.status_code}.")
    except Exception as e:
        print(f"  [!] RapidDNS query failed: {e}")
    return findings


def check_historical_records(domain: str, session: requests.Session,
                             cf_ranges: set) -> list:
    """
    Phase 2: Query historical/passive DNS databases for past IP resolutions.
    Free sources: crt.sh, HackerTarget, RapidDNS.
    """
    findings = []
    print("\n" + "=" * 60)
    print("[PHASE 2] Historical & Passive DNS Records")
    print("=" * 60)

    # Collect candidate hostnames from all sources
    all_hosts = set()

    # crt.sh
    ct_names = query_crtsh(domain, session)
    all_hosts.update(ct_names)

    # HackerTarget
    ht_results = query_hackertarget(domain, session)
    for host, ip in ht_results:
        all_hosts.add(host)
        if not is_cloudflare_ip(ip, cf_ranges):
            findings.append(Finding(
                ip=ip,
                source="HackerTarget",
                confidence="medium",
                detail=f"Passive DNS: {host} -> {ip}"
            ))
            print(f"  [+] Historical IP: {ip} (from {host})")

    # RapidDNS
    rd_results = query_rapiddns(domain, session)
    for host, ip in rd_results:
        all_hosts.add(host)
        if not is_cloudflare_ip(ip, cf_ranges):
            findings.append(Finding(
                ip=ip,
                source="RapidDNS",
                confidence="medium",
                detail=f"Passive DNS: {host} -> {ip}"
            ))
            print(f"  [+] Historical IP: {ip} (from {host})")

    print(f"  [*] Total unique hostnames gathered: {len(all_hosts)}")

    # Resolve all gathered hostnames to find non-CF IPs
    print("  [*] Resolving gathered hostnames...")
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    for host in sorted(all_hosts):
        try:
            answers = resolver.resolve(host, "A")
            for ans in answers:
                ip = ans.to_text().strip()
                if not is_cloudflare_ip(ip, cf_ranges):
                    findings.append(Finding(
                        ip=ip,
                        source="Historical-Resolve",
                        confidence="low",
                        detail=f"Resolved {host} -> {ip}"
                    ))
                    print(f"  [+] Non-CF resolve: {host} -> {ip}")
        except Exception:
            continue

    if not findings:
        print("  [-] No historical IPs found from free sources.")

    return findings


# ──────────────────────────────────────────────
# Phase 3: Subdomain Brute Force
# ──────────────────────────────────────────────

def load_wordlist(path: Optional[str]) -> list:
    """Load a wordlist from file, or use the built-in default."""
    if path:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            print(f"[+] Loaded {len(words)} words from {path}")
            return words
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {path}. Using built-in list.")
    return DEFAULT_WORDLIST


def brute_force_subdomains(domain: str, wordlist: list, session: requests.Session,
                           cf_ranges: set, threads: int = 20) -> list:
    """
    Phase 3: Brute force subdomains and resolve them.
    Filters out Cloudflare IPs and detects wildcard DNS.
    """
    findings = []
    print("\n" + "=" * 60)
    print("[PHASE 3] Subdomain Brute Force")
    print("=" * 60)

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    # Wildcard detection
    wildcard_ips = set()
    try:
        random_label = f"thisdoesnotexist{random.randint(10000, 99999)}.{domain}"
        wildcard_answers = resolver.resolve(random_label, "A")
        for ans in wildcard_answers:
            wildcard_ips.add(ans.to_text().strip())
        if wildcard_ips:
            print(f"  [!] Wildcard DNS detected: {', '.join(wildcard_ips)}")
    except Exception:
        pass

    def resolve_candidate(word: str) -> Optional[tuple]:
        fqdn = f"{word}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            ips = [ans.to_text().strip() for ans in answers]
            return (fqdn, ips)
        except Exception:
            return None

    print(f"  [*] Testing {len(wordlist)} candidates with {threads} threads...")
    found_count = 0
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {executor.submit(resolve_candidate, word): word for word in wordlist}
        for future in as_completed(future_map):
            result = future.result()
            if result:
                fqdn, ips = result
                for ip in ips:
                    if ip in wildcard_ips:
                        continue
                    if not is_cloudflare_ip(ip, cf_ranges):
                        findings.append(Finding(
                            ip=ip,
                            source="BruteForce",
                            confidence="medium",
                            detail=f"Subdomain {fqdn} -> {ip}"
                        ))
                        print(f"  [+] Found: {fqdn} -> {ip}")
                        found_count += 1

    if found_count == 0:
        print("  [-] No non-Cloudflare subdomains found via brute force.")

    return findings


# ──────────────────────────────────────────────
# Decoy Technique
# ──────────────────────────────────────────────

def generate_decoy_traffic(domain: str, session: requests.Session,
                           count: int = 20) -> int:
    """
    Send decoy DNS queries for plausible but non-existent subdomains.
    This floods passive DNS databases and defenders' logs with noise,
    making it harder to distinguish real reconnaissance from background noise.
    """
    print("\n" + "=" * 60)
    print("[DECOY] Generating Obfuscation Traffic")
    print("=" * 60)

    sent = 0
    for i in range(count):
        prefix = random.choice(DECOY_PREFIXES)
        suffix = random.choice(["cdn", "api", "edge", "node", "proxy", "gw", "svc", "app"])
        decoy_host = f"{prefix}{suffix}-{random.randint(1000, 9999)}.{domain}"

        try:
            # Perform a DNS query (creates a record in passive DNS)
            socket.getaddrinfo(decoy_host, None, socket.AF_INET)
        except socket.gaierror:
            pass  # Expected — the domain doesn't exist

        # Also send an HTTP request to the main domain with a decoy Host header
        if i % 3 == 0:
            try:
                session.get(
                    f"http://{domain}/",
                    headers={"Host": decoy_host},
                    timeout=5,
                    allow_redirects=False,
                )
            except Exception:
                pass

        sent += 1
        # Small delay to avoid triggering rate limits too obviously
        time.sleep(random.uniform(0.1, 0.4))

    print(f"  [+] Sent {sent} decoy queries/requests.")
    return sent


# ──────────────────────────────────────────────
# Verification Helper
# ──────────────────────────────────────────────

def verify_candidate(ip: str, domain: str, session: requests.Session) -> bool:
    """
    Verify a candidate IP by sending a request with the target Host header.
    Returns True if the response looks like the target site.
    """
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{ip}/"
            resp = session.get(
                url,
                headers={"Host": domain},
                timeout=8,
                allow_redirects=False,
                verify=False,
            )
            # Look for signs of a real web server
            if resp.status_code in (200, 301, 302, 403):
                body = resp.text[:2000].lower()
                if domain.lower() in body or "cloudflare" not in body:
                    return True
        except Exception:
            continue
    return False


def verify_findings(findings: list, domain: str, session: requests.Session) -> list:
    """Verify each unique candidate IP and upgrade confidence."""
    verified = []
    seen_ips = set()

    print("\n" + "=" * 60)
    print("[VERIFY] Validating Candidate IPs")
    print("=" * 60)

    for finding in findings:
        if finding.ip in seen_ips:
            continue
        seen_ips.add(finding.ip)

        # Skip obviously invalid IPs
        try:
            ipaddress.ip_address(finding.ip)
        except ValueError:
            continue

        print(f"  [*] Testing {finding.ip} ...", end=" ", flush=True)
        if verify_candidate(finding.ip, domain, session):
            finding.confidence = "high"
            finding.detail += " [VERIFIED via Host header]"
            verified.append(finding)
            print("VERIFIED")
        else:
            finding.confidence = "low"
            verified.append(finding)
            print("no response")

    return verified


# ──────────────────────────────────────────────
# Output Formatting
# ──────────────────────────────────────────────

def print_summary(result: ScanResult):
    """Print a clear, readable summary of all findings."""
    print("\n" + "=" * 60)
    print(" SCAN SUMMARY")
    print("=" * 60)
    print(f"  Target:            {result.domain}")
    print(f"  Cloudflare ranges: {len(result.cloudflare_ips)} loaded")
    print(f"  Decoy queries:     {result.decoy_count}")
    print(f"  Total findings:    {len(result.findings)}")

    if result.errors:
        print(f"  Errors:            {len(result.errors)}")

    print("-" * 60)

    # Group by confidence
    for level in ["high", "medium", "low"]:
        grouped = [f for f in result.findings if f.confidence == level]
        if not grouped:
            continue
        print(f"\n  [{level.upper()} CONFIDENCE] ({len(grouped)} IPs)")
        for f in grouped:
            print(f"    • {f.ip}")
            print(f"      Source: {f.source}")
            print(f"      Detail: {f.detail[:120]}")

    if not result.findings:
        print("\n  [-] No origin IP candidates were found.")
        print("  [*] Try a larger wordlist, paid API keys, or manual analysis.")

    print("\n" + "=" * 60)
    print("  WARNING: Verify all results before acting on them.")
    print("  This tool is for AUTHORIZED security research only.")
    print("=" * 60)


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Cloudflare Origin IP Discovery Tool — for authorized security research only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com
  %(prog)s -d example.com --tor
  %(prog)s -d example.com -w /path/to/wordlist.txt -t 50
  %(prog)s -d example.com --decoy --decoy-count 50
  %(prog)s -d example.com --skip-brute --skip-verify
        """,
    )

    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist (one word per line)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Thread count for brute force (default: 20)")
    parser.add_argument("--tor", action="store_true", help="Route all HTTP traffic through Tor (SOCKS5 port 9050)")
    parser.add_argument("--tor-port", type=int, default=9050, help="Tor SOCKS5 port (default: 9050)")
    parser.add_argument("--decoy", action="store_true", help="Enable decoy traffic generation")
    parser.add_argument("--decoy-count", type=int, default=20, help="Number of decoy queries (default: 20)")
    parser.add_argument("--skip-dns", action="store_true", help="Skip Phase 1 (DNS misconfig checks)")
    parser.add_argument("--skip-history", action="store_true", help="Skip Phase 2 (historical records)")
    parser.add_argument("--skip-brute", action="store_true", help="Skip Phase 3 (subdomain brute force)")
    parser.add_argument("--skip-verify", action="store_true", help="Skip IP verification step")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    # Normalize domain
    domain = args.domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain).rstrip("/")

    # Banner
    print("\n" + "=" * 60)
    print(" Cloudflare Origin IP Discovery Tool")
    print(" Version 1.0.0 — Authorized Research Only")
    print("=" * 60)
    print(f"  Target: {domain}")
    print(f"  Tor:    {'enabled' if args.tor else 'disabled'}")
    print(f"  Decoy:  {'enabled' if args.decoy else 'disabled'}")
    print("=" * 60)

    # Build session
    session = build_session(use_tor=args.tor, tor_port=args.tor_port)

    if args.tor:
        if not check_tor_connectivity(session):
            print("[!] Tor is not working correctly. Continuing without Tor.")
            session = build_session(use_tor=False)

    # Disable SSL warnings for verification (we're testing untrusted IPs)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Initialize result
    result = ScanResult(domain=domain)

    # Fetch Cloudflare ranges
    print("\n[*] Fetching Cloudflare IP ranges...")
    result.cloudflare_ips = fetch_cloudflare_ranges(session)

    # Phase 1: DNS misconfig
    if not args.skip_dns:
        findings = check_dns_misconfig(domain, session, result.cloudflare_ips)
        result.findings.extend(findings)
    else:
        print("\n[*] Phase 1 (DNS misconfig) skipped.")

    # Phase 2: Historical records
    if not args.skip_history:
        findings = check_historical_records(domain, session, result.cloudflare_ips)
        result.findings.extend(findings)
    else:
        print("\n[*] Phase 2 (historical records) skipped.")

    # Phase 3: Brute force
    if not args.skip_brute:
        wordlist = load_wordlist(args.wordlist)
        findings = brute_force_subdomains(
            domain, wordlist, session, result.cloudflare_ips, threads=args.threads
        )
        result.findings.extend(findings)
    else:
        print("\n[*] Phase 3 (brute force) skipped.")

    # Decoy traffic
    if args.decoy:
        result.decoy_count = generate_decoy_traffic(
            domain, session, count=args.decoy_count
        )

    # Deduplicate findings by IP, keeping the highest confidence
    deduped = {}
    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    for f in result.findings:
        if f.ip not in deduped:
            deduped[f.ip] = f
        else:
            existing = deduped[f.ip]
            if confidence_rank.get(f.confidence, 0) > confidence_rank.get(existing.confidence, 0):
                deduped[f.ip] = f
            elif existing.detail and f.detail not in existing.detail:
                existing.detail += f" | {f.detail}"
    result.findings = list(deduped.values())

    # Verification
    if not args.skip_verify and result.findings:
        result.findings = verify_findings(result.findings, domain, session)

    # Output
    if args.json:
        output = {
            "domain": result.domain,
            "cloudflare_ranges_loaded": len(result.cloudflare_ips),
            "decoy_queries_sent": result.decoy_count,
            "findings": [
                {
                    "ip": f.ip,
                    "source": f.source,
                    "confidence": f.confidence,
                    "detail": f.detail,
                }
                for f in result.findings
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        print_summary(result)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)