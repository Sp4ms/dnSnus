#!/usr/bin/env python3

# Install dnspython and requests
#  python -m pip install dnspython requests

import argparse
import csv
import ipaddress
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Optional

import dns.exception
import dns.name
import dns.query
import dns.resolver
import dns.reversename
import dns.rdatatype
import dns.zone
import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_SRV_FILE = "srvs.txt"
DEFAULT_SELECTOR_FILE = "selectors.txt"

# Create (FREE) MXToolbox API Key - https://mxtoolbox.com/api/api-reference
DEFAULT_MXTOOLBOX_API_KEY = ""

DEFAULT_TIMEOUT = 5.0
DEFAULT_LIFETIME = 8.0

BASE_RECORD_TYPES = (
    "A",
    "AAAA",
    "CAA",
    "CNAME",
    "DS",
    "DNSKEY",
    "HTTPS",
    "MX",
    "NS",
    "PTR",
    "SOA",
    "SRV",
    "TXT",
)

MXTOOLBOX_BASE_URL = "https://mxtoolbox.com/api/v1/lookup"

# Matches IPv4 and reasonably conventional textual IPv6 candidates.
IP_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])"
    r"(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"[0-9A-Fa-f]*:[0-9A-Fa-f:.]+"
    r")"
    r"(?![0-9A-Fa-f:.])"
)

# SPF ip4 mechanism.
SPF_IP4_RE = re.compile(
    r"(?i)(?:^|\s)ip4:([0-9.]+(?:/\d{1,2})?)(?=\s|$)"
)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("dns_audit")


def configure_logging(debug_file: Optional[str], verbose: bool) -> None:
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    if verbose:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(
            logging.Formatter("[%(levelname)s] %(message)s")
        )
        logger.addHandler(console_handler)

    if debug_file:
        debug_handler = logging.FileHandler(
            debug_file,
            mode="w",
            encoding="utf-8",
        )
        debug_handler.setLevel(logging.DEBUG)
        debug_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        logger.addHandler(debug_handler)

    # Prevent Python's "lastResort" handler from unexpectedly writing
    # DEBUG messages when neither --verbose nor --debug-file is enabled.
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def normalize_domain(domain: str) -> str:
    domain = domain.strip().rstrip(".").lower()

    if not domain:
        raise ValueError("Domain cannot be empty.")

    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid domain: {domain}") from exc

    try:
        dns.name.from_text(ascii_domain)
    except Exception as exc:
        raise ValueError(f"Invalid DNS name: {domain}") from exc

    return ascii_domain


def read_wordlist(path: Optional[str]) -> list[str]:
    if not path:
        return []

    file_path = Path(path)

    if not file_path.exists():
        logger.warning("Wordlist does not exist: %s", file_path)
        return []

    values: list[str] = []

    with file_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            value = line.strip()

            if not value:
                continue

            if value.startswith("#"):
                continue

            # Permit comments following whitespace.
            value = value.split("#", 1)[0].strip()

            if value:
                values.append(value)

    return values


def unique_preserve_order(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def clean_rdata_text(record_type: str, text: str) -> str:
    """
    Convert dnspython's presentation format into a CSV-friendly representation.

    TXT records retain their contents but have presentation-format quote
    boundaries removed so SPF/DMARC/DKIM parsing is easier.
    """
    text = text.strip()

    if record_type == "TXT":
        quoted_parts = re.findall(r'"((?:\\.|[^"])*)"', text)

        if quoted_parts:
            return "".join(quoted_parts)

    return text


def is_internal_address(address: ipaddress._BaseAddress) -> bool:
    """
    Define addresses that should not normally appear as publicly routable
    infrastructure addresses.

    IPv4:
      RFC1918, loopback, link-local

    IPv6:
      ULA fc00::/7, loopback, link-local
    """
    if isinstance(address, ipaddress.IPv4Address):
        internal_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
        )
    else:
        internal_networks = (
            ipaddress.ip_network("fc00::/7"),
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("fe80::/10"),
        )

    return any(address in network for network in internal_networks)


def extract_ip_addresses(text: str) -> list[ipaddress._BaseAddress]:
    addresses: list[ipaddress._BaseAddress] = []

    for candidate in IP_CANDIDATE_RE.findall(text):
        candidate = candidate.strip("[](){}<>,;'\"")

        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue

        addresses.append(address)

    return addresses


def report_internal_ips(
    owner: str,
    record_type: str,
    result: str,
) -> None:
    for address in extract_ip_addresses(result):
        if is_internal_address(address):
            print(
                f"[WARNING] Internal/non-public IP exposed in DNS: "
                f"{owner} {record_type} -> {address}"
            )


# ---------------------------------------------------------------------------
# DNS resolver
# ---------------------------------------------------------------------------

def build_resolver(
    resolver_file: Optional[str],
    timeout: float,
    lifetime: float,
) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)

    resolver.timeout = timeout
    resolver.lifetime = lifetime

    if resolver_file:
        nameservers = read_wordlist(resolver_file)

        if not nameservers:
            raise ValueError(
                f"No resolvers were found in {resolver_file}"
            )

        valid_nameservers: list[str] = []

        for server in nameservers:
            try:
                ipaddress.ip_address(server)
            except ValueError:
                raise ValueError(
                    f"Resolver must be an IPv4 or IPv6 address: {server}"
                )

            valid_nameservers.append(server)

        resolver.nameservers = valid_nameservers

        logger.debug(
            "Using custom DNS resolvers: %s",
            ", ".join(valid_nameservers),
        )
    else:
        logger.debug(
            "Using system DNS resolvers: %s",
            ", ".join(str(x) for x in resolver.nameservers),
        )

    return resolver


def dns_lookup(
    resolver: dns.resolver.Resolver,
    owner: str,
    record_type: str,
) -> list[str]:
    logger.debug("DNS QUERY owner=%s type=%s", owner, record_type)

    try:
        answer = resolver.resolve(
            owner,
            record_type,
            raise_on_no_answer=False,
            search=False,
        )

        if answer.rrset is None:
            logger.debug(
                "DNS RESPONSE owner=%s type=%s result=NOANSWER",
                owner,
                record_type,
            )
            return []

        results: list[str] = []

        for rdata in answer:
            value = clean_rdata_text(
                record_type,
                rdata.to_text(),
            )

            results.append(value)

            logger.debug(
                "DNS RESULT owner=%s type=%s value=%s",
                owner,
                record_type,
                value,
            )

        return unique_preserve_order(results)

    except dns.resolver.NXDOMAIN:
        logger.debug(
            "DNS RESPONSE owner=%s type=%s result=NXDOMAIN",
            owner,
            record_type,
        )

    except dns.resolver.NoAnswer:
        logger.debug(
            "DNS RESPONSE owner=%s type=%s result=NOANSWER",
            owner,
            record_type,
        )

    except dns.resolver.NoNameservers as exc:
        logger.debug(
            "DNS RESPONSE owner=%s type=%s result=NO_NAMESERVERS error=%s",
            owner,
            record_type,
            exc,
        )

    except dns.exception.Timeout as exc:
        logger.debug(
            "DNS RESPONSE owner=%s type=%s result=TIMEOUT error=%s",
            owner,
            record_type,
            exc,
        )

    except dns.exception.DNSException as exc:
        logger.debug(
            "DNS RESPONSE owner=%s type=%s result=DNS_ERROR error=%s",
            owner,
            record_type,
            exc,
        )

    except Exception as exc:
        logger.exception(
            "Unexpected DNS error owner=%s type=%s: %s",
            owner,
            record_type,
            exc,
        )

    return []


# ---------------------------------------------------------------------------
# Result storage
# ---------------------------------------------------------------------------

class ResultStore:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []
        self.seen: set[tuple[str, str, str]] = set()

    def add(
        self,
        owner: str,
        record_type: str,
        result: str,
    ) -> None:
        row = (
            owner.rstrip("."),
            record_type.upper(),
            result,
        )

        if row in self.seen:
            return

        self.seen.add(row)
        self.rows.append(row)

        report_internal_ips(*row)

    def add_many(
        self,
        owner: str,
        record_type: str,
        results: Iterable[str],
    ) -> None:
        for result in results:
            self.add(owner, record_type, result)

    def write_csv(self, path: str) -> None:
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                ["domain", "record_type", "result"]
            )

            for row in self.rows:
                writer.writerow(row)


# ---------------------------------------------------------------------------
# SPF analysis
# ---------------------------------------------------------------------------

def find_spf_records(txt_records: Iterable[str]) -> list[str]:
    return [
        record
        for record in txt_records
        if record.strip().lower().startswith("v=spf1")
    ]


def analyze_spf_network_ranges(
    domain: str,
    spf_records: Iterable[str],
) -> None:
    """
    Warn when a directly specified SPF ip4 mechanism permits a network
    broader than /24.

    Examples:
        ip4:203.0.113.0/24   -> not warned
        ip4:203.0.112.0/23   -> warning
        ip4:10.0.0.0/8       -> warning
    """
    for spf in spf_records:
        for network_text in SPF_IP4_RE.findall(spf):
            try:
                network = ipaddress.ip_network(
                    network_text,
                    strict=False,
                )
            except ValueError:
                continue

            if (
                isinstance(network, ipaddress.IPv4Network)
                and network.prefixlen < 24
            ):
                print(
                    f"[WARNING] SPF for {domain} contains a network "
                    f"broader than /24: {network} "
                    f"(from {network_text})"
                )


# ---------------------------------------------------------------------------
# MXToolbox
# ---------------------------------------------------------------------------

def collect_mxtoolbox_diagnostics(
    obj: Any,
    path: str = "$",
) -> list[str]:
    """
    MXToolbox response structures can differ between lookup types.

    Recursively identify fields whose names indicate warnings, failures,
    errors, or problems without binding the scanner to a single response
    schema.
    """
    diagnostics: list[str] = []

    diagnostic_keys = {
        "warning",
        "warnings",
        "failed",
        "failure",
        "failures",
        "error",
        "errors",
        "problem",
        "problems",
    }

    if isinstance(obj, dict):
        for key, value in obj.items():
            current_path = f"{path}.{key}"

            if key.lower() in diagnostic_keys:
                if value not in (
                    None,
                    "",
                    [],
                    {},
                    False,
                    0,
                ):
                    try:
                        rendered = json.dumps(
                            value,
                            ensure_ascii=False,
                            sort_keys=True,
                        )
                    except TypeError:
                        rendered = str(value)

                    diagnostics.append(
                        f"{current_path}: {rendered}"
                    )

            diagnostics.extend(
                collect_mxtoolbox_diagnostics(
                    value,
                    current_path,
                )
            )

    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            diagnostics.extend(
                collect_mxtoolbox_diagnostics(
                    value,
                    f"{path}[{index}]",
                )
            )

    return unique_preserve_order(diagnostics)


def mxtoolbox_lookup(
    session: requests.Session,
    api_key: str,
    lookup_type: str,
    target: str,
    timeout: float,
    argument: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Query the MXToolbox API.

    SPF/DMARC:
        /api/v1/lookup/spf/example.com
        /api/v1/lookup/dmarc/example.com

    DKIM:
        /api/v1/lookup/dkim/example.com
            ?argument=example.com:selector1
    """
    url = f"{MXTOOLBOX_BASE_URL}/{lookup_type}/{target}"

    params = {}

    if argument is not None:
        params["argument"] = argument

    logger.debug(
        "MXTOOLBOX REQUEST type=%s target=%s url=%s params=%s",
        lookup_type,
        target,
        url,
        params,
    )

    try:
        response = session.get(
            url,
            params=params,
            headers={
                "Authorization": api_key,
                "Accept": "application/json",
                "User-Agent": "dns-audit/1.0",
            },
            timeout=timeout,
        )

        logger.debug(
            "MXTOOLBOX RESPONSE type=%s target=%s "
            "request_url=%s status=%d body=%s",
            lookup_type,
            target,
            response.url,
            response.status_code,
            response.text,
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict):
            logger.warning(
                "Unexpected MXToolbox JSON structure for %s/%s",
                lookup_type,
                target,
            )
            return None

        diagnostics = collect_mxtoolbox_diagnostics(data)

        for diagnostic in diagnostics:
            print(
                f"[WARNING] MXToolbox {lookup_type.upper()} "
                f"{target}: {diagnostic}"
            )

        return data

    except requests.Timeout:
        print(
            f"[WARNING] MXToolbox request timed out: "
            f"{lookup_type}/{target}"
        )

    except requests.HTTPError as exc:
        status = (
            exc.response.status_code
            if exc.response is not None
            else "unknown"
        )

        print(
            f"[WARNING] MXToolbox request failed: "
            f"{lookup_type}/{target} HTTP {status}"
        )

    except requests.RequestException as exc:
        print(
            f"[WARNING] MXToolbox request failed: "
            f"{lookup_type}/{target}: {exc}"
        )

    except ValueError:
        print(
            f"[WARNING] MXToolbox returned invalid JSON: "
            f"{lookup_type}/{target}"
        )

    return None

# ---------------------------------------------------------------------------
# PTR enumeration
# ---------------------------------------------------------------------------

def reverse_ptr_lookup(
    resolver: dns.resolver.Resolver,
    address_text: str,
    store: ResultStore,
) -> None:
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError:
        return

    reverse_name = dns.reversename.from_address(str(address)).to_text()

    ptr_records = dns_lookup(
        resolver,
        reverse_name,
        "PTR",
    )

    store.add_many(
        reverse_name.rstrip("."),
        "PTR",
        ptr_records,
    )


# ---------------------------------------------------------------------------
# AXFR
# ---------------------------------------------------------------------------

def resolve_nameserver_addresses(
    resolver: dns.resolver.Resolver,
    nameserver: str,
) -> list[str]:
    addresses: list[str] = []

    for record_type in ("A", "AAAA"):
        addresses.extend(
            dns_lookup(
                resolver,
                nameserver.rstrip("."),
                record_type,
            )
        )

    valid: list[str] = []

    for value in addresses:
        try:
            valid.append(str(ipaddress.ip_address(value)))
        except ValueError:
            continue

    return unique_preserve_order(valid)


def safe_filename(value: str) -> str:
    return re.sub(
        r"[^A-Za-z0-9_.-]",
        "_",
        value,
    )


def attempt_axfr(
    domain: str,
    nameservers: Iterable[str],
    resolver: dns.resolver.Resolver,
    output_directory: str,
    timeout: float,
) -> None:
    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)

    for nameserver in nameservers:
        ns = nameserver.rstrip(".")

        addresses = resolve_nameserver_addresses(
            resolver,
            ns,
        )

        if not addresses:
            print(
                f"[AXFR] {ns}: unable to resolve nameserver address"
            )
            continue

        success = False

        for address in addresses:
            logger.debug(
                "AXFR REQUEST domain=%s nameserver=%s address=%s",
                domain,
                ns,
                address,
            )

            try:
                transfer = dns.query.xfr(
                    where=address,
                    zone=domain,
                    timeout=timeout,
                    lifetime=timeout,
                )

                zone = dns.zone.from_xfr(
                    transfer,
                    relativize=False,
                )

                zone_filename = (
                    f"{safe_filename(domain)}_"
                    f"{safe_filename(ns)}_"
                    f"{safe_filename(address)}.zone"
                )

                zone_file = output_path / zone_filename

                with zone_file.open(
                    "w",
                    encoding="utf-8",
                ) as handle:
                    zone.to_file(handle, relativize=False)

                print(
                    f"[AXFR] SUCCESS: {domain} via "
                    f"{ns} ({address}) -> {zone_file}"
                )

                logger.debug(
                    "AXFR SUCCESS domain=%s nameserver=%s "
                    "address=%s file=%s",
                    domain,
                    ns,
                    address,
                    zone_file,
                )

                success = True
                break

            except (
                dns.exception.FormError,
                dns.exception.Timeout,
                dns.exception.DNSException,
                EOFError,
                OSError,
                ValueError,
            ) as exc:
                logger.debug(
                    "AXFR FAILED domain=%s nameserver=%s "
                    "address=%s error=%s",
                    domain,
                    ns,
                    address,
                    exc,
                )

        if not success:
            print(
                f"[AXFR] FAILED: {domain} via {ns}"
            )


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

def enumerate_base_records(
    domain: str,
    resolver: dns.resolver.Resolver,
    store: ResultStore,
) -> dict[str, list[str]]:
    discovered: dict[str, list[str]] = {}

    for record_type in BASE_RECORD_TYPES:
        records = dns_lookup(
            resolver,
            domain,
            record_type,
        )

        discovered[record_type] = records

        store.add_many(
            domain,
            record_type,
            records,
        )

    return discovered


def enumerate_reverse_ptrs(
    resolver: dns.resolver.Resolver,
    store: ResultStore,
    discovered: dict[str, list[str]],
) -> None:
    addresses = (
        discovered.get("A", [])
        + discovered.get("AAAA", [])
    )

    for address in unique_preserve_order(addresses):
        reverse_ptr_lookup(
            resolver,
            address,
            store,
        )


def enumerate_srv_records(
    domain: str,
    resolver: dns.resolver.Resolver,
    store: ResultStore,
    srv_entries: Iterable[str],
) -> None:
    for entry in srv_entries:
        prefix = entry.strip().rstrip(".")

        if not prefix:
            continue

        # Accept either:
        #   _sip._tcp
        # or:
        #   _sip._tcp.example.com
        if prefix.lower().endswith(
            f".{domain.lower()}"
        ):
            owner = prefix
        else:
            owner = f"{prefix}.{domain}"

        records = dns_lookup(
            resolver,
            owner,
            "SRV",
        )

        store.add_many(
            owner,
            "SRV",
            records,
        )

        if records:
            print(
                f"[SRV] Valid SRV record discovered: {owner}"
            )

            for record in records:
                print(
                    f"[SRV] {owner} -> {record}"
                )

def enumerate_dmarc(
    domain: str,
    resolver: dns.resolver.Resolver,
    store: ResultStore,
) -> list[str]:
    owner = f"_dmarc.{domain}"

    records = dns_lookup(
        resolver,
        owner,
        "TXT",
    )

    store.add_many(
        owner,
        "TXT",
        records,
    )

    return records


def enumerate_dkim(
    domain: str,
    resolver: dns.resolver.Resolver,
    store: ResultStore,
    selectors: Iterable[str],
) -> dict[str, dict[str, list[str]]]:
    discovered: dict[str, dict[str, list[str]]] = {}

    for selector in selectors:
        selector = selector.strip().rstrip(".")

        if not selector:
            continue

        owner = f"{selector}._domainkey.{domain}"

        txt_records = dns_lookup(
            resolver,
            owner,
            "TXT",
        )

        cname_records = dns_lookup(
            resolver,
            owner,
            "CNAME",
        )

        if txt_records:
            store.add_many(
                owner,
                "TXT",
                txt_records,
            )

        if cname_records:
            store.add_many(
                owner,
                "CNAME",
                cname_records,
            )

        if txt_records or cname_records:
            discovered[selector] = {
                "TXT": txt_records,
                "CNAME": cname_records,
            }

            print(
                f"[DKIM] Valid selector discovered: "
                f"{selector} ({owner})"
            )

    return discovered


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Enumerate DNS records, inspect SPF/DKIM/DMARC, "
            "query MXToolbox, identify internal IP disclosures, "
            "and test authoritative nameservers for AXFR."
        )
    )

    parser.add_argument(
        "domain",
        help="Domain to enumerate, for example example.com",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="CSV output path",
    )

    parser.add_argument(
        "--srvs",
        default=DEFAULT_SRV_FILE,
        help=(
            "Path to SRV prefix wordlist "
            f"(default: {DEFAULT_SRV_FILE})"
        ),
    )

    parser.add_argument(
        "--selectors",
        default=DEFAULT_SELECTOR_FILE,
        help=(
            "Path to DKIM selector wordlist "
            f"(default: {DEFAULT_SELECTOR_FILE})"
        ),
    )

    parser.add_argument(
        "--resolvers",
        help=(
            "Optional path containing DNS resolver IP addresses, "
            "one per line"
        ),
    )

    parser.add_argument(
        "--mxtoolbox-api-key",
        default=DEFAULT_MXTOOLBOX_API_KEY,
        help=(
            "MXToolbox API key. If omitted, MXToolbox checks "
            "are skipped."
        ),
    )

    parser.add_argument(
        "--debug-file",
        help=(
            "Write DNS/API queries, responses, and results "
            "to this text file"
        ),
    )

    parser.add_argument(
        "--zone-dir",
        default="zones",
        help="Directory for successful AXFR zone files (default: zones)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Per-operation timeout (default: {DEFAULT_TIMEOUT})",
    )

    parser.add_argument(
        "--lifetime",
        type=float,
        default=DEFAULT_LIFETIME,
        help=(
            "DNS query lifetime "
            f"(default: {DEFAULT_LIFETIME})"
        ),
    )

    parser.add_argument(
        "--skip-axfr",
        action="store_true",
        help="Do not attempt DNS zone transfers",
    )

    parser.add_argument(
        "--skip-mxtoolbox",
        action="store_true",
        help="Do not query the MXToolbox API",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print detailed diagnostic logging to stderr",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = parse_arguments()

    configure_logging(
        args.debug_file,
        args.verbose,
    )

    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    output_file = (
        args.output
        if args.output
        else f"{safe_filename(domain)}_dns.csv"
    )

    try:
        resolver = build_resolver(
            args.resolvers,
            args.timeout,
            args.lifetime,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    store = ResultStore()

    print(f"[*] Enumerating DNS for {domain}")

    # ------------------------------------------------------------------
    # Standard DNS records
    # ------------------------------------------------------------------

    discovered = enumerate_base_records(
        domain,
        resolver,
        store,
    )

    # ------------------------------------------------------------------
    # Reverse PTR records for discovered addresses
    # ------------------------------------------------------------------

    enumerate_reverse_ptrs(
        resolver,
        store,
        discovered,
    )

    # ------------------------------------------------------------------
    # SPF
    # ------------------------------------------------------------------

    spf_records = find_spf_records(
        discovered.get("TXT", [])
    )

    for spf in spf_records:
        print(f"[SPF] {domain}: {spf}")

    analyze_spf_network_ranges(
        domain,
        spf_records,
    )

    # ------------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------------

    dmarc_records = enumerate_dmarc(
        domain,
        resolver,
        store,
    )

    for dmarc in dmarc_records:
        print(f"[DMARC] {domain}: {dmarc}")

    # ------------------------------------------------------------------
    # SRV
    # ------------------------------------------------------------------

    srv_entries = read_wordlist(args.srvs)

    if srv_entries:
        enumerate_srv_records(
            domain,
            resolver,
            store,
            srv_entries,
        )
    else:
        logger.debug(
            "No SRV entries loaded from %s",
            args.srvs,
        )

    # ------------------------------------------------------------------
    # DKIM
    # ------------------------------------------------------------------

    selectors = read_wordlist(args.selectors)

    dkim_records = enumerate_dkim(
        domain,
        resolver,
        store,
        selectors,
    )

    # ------------------------------------------------------------------
    # MXToolbox
    # ------------------------------------------------------------------

    if (
        not args.skip_mxtoolbox
        and args.mxtoolbox_api_key
    ):
        session = requests.Session()

        if spf_records:
            mxtoolbox_lookup(
                session,
                args.mxtoolbox_api_key,
                "spf",
                domain,
                args.timeout,
            )

        if dmarc_records:
            mxtoolbox_lookup(
                session,
                args.mxtoolbox_api_key,
                "dmarc",
                domain,
                args.timeout,
            )

        for selector in dkim_records:
            mxtoolbox_lookup(
                session,
                args.mxtoolbox_api_key,
                "dkim",
                domain,
                args.timeout,
                argument=f"{domain}:{selector}",
            )

        session.close()

    elif not args.skip_mxtoolbox:
        logger.debug(
            "MXToolbox checks skipped because no API key "
            "was supplied."
        )

    # ------------------------------------------------------------------
    # AXFR
    # ------------------------------------------------------------------

    if not args.skip_axfr:
        nameservers = discovered.get("NS", [])

        if nameservers:
            print(
                f"[*] Attempting AXFR against "
                f"{len(nameservers)} nameserver(s)"
            )

            attempt_axfr(
                domain,
                nameservers,
                resolver,
                args.zone_dir,
                args.timeout,
            )
        else:
            print(
                "[AXFR] No authoritative NS records discovered; "
                "AXFR testing skipped."
            )

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------

    store.write_csv(output_file)

    print(
        f"[*] Saved {len(store.rows)} DNS records to "
        f"{output_file}"
    )

    if args.debug_file:
        print(
            f"[*] Debug information written to "
            f"{args.debug_file}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
