#  dnSnus
<p align="center">
<img width="656" height="599" alt="dnSnus Can" src="https://github.com/user-attachments/assets/fbee3716-e808-4db3-a27d-1a4020ed0263" />
</p>

A Python-based DNS enumeration and security auditing tool designed to discover DNS records, analyze email authentication configurations, identify potentially sensitive network information, and test DNS servers for zone transfer vulnerabilities.

DNS Audit combines standard DNS reconnaissance with targeted security checks, including **SPF, DKIM, and DMARC validation through the MXToolbox API**, detection of internal IP addresses in DNS records, and DNS zone transfer (AXFR) testing.

Designed for security professionals, penetration testers, bug bounty hunters, system administrators, and anyone looking to better understand their organization's DNS security posture.

## Features

- **DNS Record Enumeration** — Query 14 DNS record types: `A`, `AAAA`, `CAA`, `CNAME`, `DS`, `DNSKEY`, `HTTPS`, `MX`, `NS`, `PTR`, `SOA`, `SRV`, and `TXT`.
- **SRV Record Discovery** — Enumerate service records using a customizable wordlist.
- **DKIM Selector Discovery** — Identify DKIM selectors by querying TXT and CNAME records using a customizable selector wordlist.
- **Email Security Analysis** — Discover SPF, DKIM, and DMARC records and identify configuration issues using the MXToolbox API.
- **SPF Network Analysis** — Flag explicitly configured IPv4 SPF ranges broader than `/24`.
- **Internal IP Detection** — Identify RFC1918, loopback, link-local, and IPv6 Unique Local Addresses exposed in DNS record values.
- **DNS Zone Transfer Testing** — Attempt AXFR against discovered authoritative nameservers and save successful transfers.
- **Reverse DNS Lookups** — Perform PTR lookups for discovered IPv4 and IPv6 addresses.
- **Custom DNS Resolvers** — Optionally use a user-provided list of DNS resolvers.
- **CSV Export** — Save all discovered DNS records in a structured, deduplicated CSV file.
- **Debug Logging** — Optionally log DNS queries, responses, API results, and errors to a text file.

## Requirements

- Python 3.9 or newer (Python 3.10+ recommended)
- Internet connectivity for public DNS enumeration and MXToolbox API requests
- Access to DNS services, typically UDP/TCP port 53
- Optional: MXToolbox API key for email authentication diagnostics

### Python Dependencies

| Package | Purpose |
|---|---|
| `dnspython` | DNS resolution, DNS record parsing, reverse DNS lookups, and AXFR |
| `requests` | HTTP requests to the MXToolbox API |

All other Python modules used by the tool are included in the Python standard library.

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Sp4ms/dnSnus.git
cd dnSnus
```
Alternatively, download the repository as a ZIP file and extract it.

### 2. Create a Python Virtual Environment (Recommended)

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```bash
python -m pip install dnspython requests
```

### 4. Verify Installation

```bash
python dns_audit.py --help
```

## Quick Start

Run a basic DNS enumeration:

```bash
python dns_audit.py example.com
```

This will:

1. Query the supported DNS record types.
2. Perform reverse PTR lookups for discovered A and AAAA records.
3. Analyze discovered SPF records for broad IPv4 ranges.
4. Check for a DMARC TXT record.
5. Attempt SRV enumeration using `srvs.txt`, if available.
6. Attempt DKIM selector enumeration using `selectors.txt`, if available.
7. Attempt AXFR against discovered nameservers.
8. Export discovered DNS records to `example.com_dns.csv`.

MXToolbox API lookups are skipped unless an API key is provided.

### Full Example

```bash
python dns_audit.py example.com \
    --srvs srvs.txt \
    --selectors selectors.txt \
    --resolvers resolvers.txt \
    --mxtoolbox-api-key "YOUR_API_KEY" \
    --output example.com_dns.csv \
    --debug-file example.com_debug.txt \
    --zone-dir zones \
    --verbose
```

## Command-Line Arguments

| Argument | Description | Default |
|---|---|---|
| `domain` | Target domain to enumerate (required) | — |
| `-o`, `--output` | CSV output file path | `<domain>_dns.csv` |
| `--srvs` | SRV record wordlist path | `srvs.txt` |
| `--selectors` | DKIM selector wordlist path | `selectors.txt` |
| `--resolvers` | Custom DNS resolver list | System DNS |
| `--mxtoolbox-api-key` | MXToolbox API key | Disabled |
| `--debug-file` | Save diagnostic logs to a text file | Disabled |
| `--zone-dir` | Directory for successful AXFR exports | `zones/` |
| `--timeout` | Per-operation timeout in seconds | `5.0` |
| `--lifetime` | Overall DNS query lifetime in seconds | `8.0` |
| `--skip-axfr` | Disable AXFR testing | False |
| `--skip-mxtoolbox` | Disable MXToolbox API requests | False |
| `-v`, `--verbose` | Print detailed diagnostic logs to stderr | False |

## How It Works

### 1. DNS Record Enumeration

DNS Audit queries the specified domain for the following record types:

| Record | Description | Security Relevance |
|---|---|---|
| A | IPv4 address mapping | Identifies public-facing and potentially exposed infrastructure |
| AAAA | IPv6 address mapping | Identifies IPv6 infrastructure and addressing |
| CAA | Certificate Authority Authorization | Identifies which CAs are authorized to issue certificates |
| CNAME | Canonical name alias | Identifies external services, aliases, and potentially abandoned service mappings |
| DS | Delegation Signer | Provides information about DNSSEC delegation |
| DNSKEY | DNSSEC public key | Provides information about DNSSEC key configuration |
| HTTPS | HTTPS service binding | Identifies HTTPS service parameters and endpoint hints |
| MX | Mail exchange servers | Identifies email infrastructure |
| NS | Authoritative nameservers | Identifies DNS infrastructure and AXFR targets |
| PTR | Reverse DNS mapping | Associates IP addresses with hostnames |
| SOA | Start of Authority | Identifies zone authority and administrative parameters |
| SRV | Service locator | Discovers services, protocols, ports, and targets |
| TXT | Text records | Discovers SPF, verification records, and other configuration data |

The tool uses the `dnspython` library to query each record type and collect successful responses.

**Why it matters:** DNS records can reveal information about an organization's infrastructure, service providers, email security, and exposed services. Understanding these records is an important part of attack surface management and defensive security assessments.

### 2. SRV Record Discovery

SRV records advertise service endpoints, including their hostnames, ports, priorities, and weights.

Rather than querying only the domain's root SRV record, DNS Audit supports a customizable wordlist of service prefixes.

Example `srvs.txt`:

```text
_autodiscover._tcp
_imap._tcp
_imaps._tcp
_ldap._tcp
_sip._tcp
_sip._tls
_smtp._tcp
_submission._tcp
_xmpp-client._tcp
_xmpp-server._tcp
```

For the domain `example.com`, an entry such as `_sip._tcp` results in:

```text
_sip._tcp.example.com
```

Example discovered record:

```text
[SRV] Valid SRV record discovered: _sip._tcp.example.com
[SRV] _sip._tcp.example.com -> 10 60 5060 sip.example.com.
```

The SRV result contains:

```text
priority weight port target
```

**Why it matters:** SRV records may disclose externally accessible services, communications infrastructure, and application endpoints that are not immediately apparent from conventional A or AAAA lookups.

### 3. SPF Analysis

Sender Policy Framework (SPF) is an email authentication mechanism that identifies which systems are authorized to send email on behalf of a domain.

DNS Audit searches the domain's TXT records for entries beginning with:

```text
v=spf1
```

Example:

```text
v=spf1 ip4:198.51.100.0/24 include:_spf.example.net -all
```

The tool performs two checks:

**SPF Network Range Analysis**

Explicit `ip4:` mechanisms containing IPv4 networks broader than `/24` are flagged.

For example:

```text
v=spf1 ip4:10.0.0.0/8 -all
```

Would produce:

```text
[WARNING] SPF for example.com contains a network broader than /24: 10.0.0.0/8 (from 10.0.0.0/8)
```

This is a heuristic for identifying potentially over-permissive SPF configurations, not an automatic indication of a vulnerability. Larger ranges may be legitimate depending on the organization's infrastructure.

**MXToolbox SPF Validation**

When an API key is supplied, the tool sends an HTTP GET request to:

```text
https://mxtoolbox.com/api/v1/lookup/spf/example.com
```

The API response is inspected for diagnostic fields containing warnings, errors, failures, or problems.

**Limitations:** The local SPF analyzer checks explicit `ip4:` mechanisms only. It does not recursively evaluate `include:`, `redirect=`, `a`, or `mx` mechanisms, nor does it calculate the complete effective SPF authorization set.

### 4. DKIM Selector Discovery

DomainKeys Identified Mail (DKIM) allows email receivers to verify that messages were cryptographically signed using a key associated with the sending domain.

DKIM records commonly reside at:

```text
<selector>._domainkey.<domain>
```

DNS Audit uses a customizable wordlist to identify selectors.

Example `selectors.txt`:

```text
default
selector1
selector2
google
google1
google2
k1
k2
mail
dkim
s1
s2
```

For `example.com` and selector `selector1`, the tool queries:

```text
selector1._domainkey.example.com
```

Both TXT and CNAME records are queried to accommodate direct DKIM public keys and hosted email providers that use DNS aliases.

Example output:

```text
[DKIM] Valid selector discovered: selector1 (selector1._domainkey.example.com)
```

**MXToolbox DKIM Validation**

For each discovered selector, the tool requests:

```text
https://mxtoolbox.com/api/v1/lookup/dkim/example.com?argument=example.com:selector1
```

The `argument` query parameter contains the domain and selector separated by a colon. The `requests` library handles URL encoding.

**Why it matters:** DKIM helps protect email integrity and domain authenticity. Identifying DKIM selectors and examining their configuration can help uncover email authentication weaknesses.

**Limitations:** Selector discovery is wordlist-based, not exhaustive. A discovered TXT or CNAME record is treated as a candidate DKIM selector; its existence alone does not guarantee that it contains a valid DKIM public key.

### 5. DMARC Discovery and Validation

Domain-based Message Authentication, Reporting, and Conformance (DMARC) builds on SPF and DKIM to define how receiving mail servers should handle messages that fail authentication and alignment checks.

DNS Audit queries:

```text
_dmarc.example.com
```

Example DMARC record:

```text
v=DMARC1; p=reject; rua=mailto:dmarc@example.com
```

Example output:

```text
[DMARC] example.com: v=DMARC1; p=reject; rua=mailto:dmarc@example.com
```

If an MXToolbox API key is provided, the tool also requests:

```text
https://mxtoolbox.com/api/v1/lookup/dmarc/example.com
```

**Why it matters:** Weak or incorrectly configured DMARC policies can reduce a domain's protection against email spoofing and phishing.

The tool retrieves and displays DMARC TXT records and delegates additional diagnostic checks to MXToolbox. It does not independently perform a full DMARC policy or alignment evaluation.

### 6. MXToolbox API Integration

DNS Audit optionally integrates with the [MXToolbox API](https://mxtoolbox.com/api/api-reference) to provide additional email authentication diagnostics.

An MXToolbox API key is required.

API endpoints:

| Check | Endpoint |
|---|---|
| SPF | `/api/v1/lookup/spf/<domain>` |
| DMARC | `/api/v1/lookup/dmarc/<domain>` |
| DKIM | `/api/v1/lookup/dkim/<domain>?argument=<domain>:<selector>` |

Requests include:

```http
Authorization: YOUR_API_KEY
Accept: application/json
User-Agent: dns-audit/1.0
```

API responses are expected in JSON format. The tool recursively searches response objects for populated fields named `warning`, `warnings`, `failed`, `failure`, `failures`, `error`, `errors`, `problem`, or `problems`.

Matching diagnostics are printed to standard output.

**API key configuration:**

```bash
python dns_audit.py example.com --mxtoolbox-api-key "YOUR_API_KEY"
```

Alternatively, set the `DEFAULT_MXTOOLBOX_API_KEY` variable in the script.

**Security note:** Passing API keys directly as command-line arguments may expose them through shell history or process listings. Avoid committing API keys to source control. The API may also impose authentication, subscription, usage, or rate-limit requirements.

### 7. Internal IP Address Detection

DNS Audit examines collected DNS record values for IP addresses that fall within selected internal or non-public network ranges.

Supported ranges include:

| Network | Classification |
|---|---|
| `10.0.0.0/8` | RFC1918 private IPv4 |
| `172.16.0.0/12` | RFC1918 private IPv4 |
| `192.168.0.0/16` | RFC1918 private IPv4 |
| `127.0.0.0/8` | IPv4 loopback |
| `169.254.0.0/16` | IPv4 link-local |
| `fc00::/7` | IPv6 Unique Local Address |
| `::1/128` | IPv6 loopback |
| `fe80::/10` | IPv6 link-local |

Example DNS record:

```text
internal.example.com A 192.168.1.10
```

When such an address appears in a collected record value, the tool may produce:

```text
[WARNING] Internal/non-public IP exposed in DNS: internal.example.com A -> 192.168.1.10
```

**Why it matters:** Internal addresses published in externally visible DNS may disclose information about network topology, addressing schemes, and internal infrastructure.

**Limitations:** The tool uses pattern-based IP extraction. It does not classify every IANA special-purpose address range, and an internal address in a DNS record is not necessarily a security vulnerability. The example above illustrates detection behavior; the tool does not recursively enumerate arbitrary subdomains.

### 8. DNS Zone Transfer (AXFR) Testing

DNS zone transfers allow DNS servers to replicate zone data between authoritative servers.

If a server permits an unauthorized AXFR request, it may disclose a large portion of its DNS namespace.

DNS Audit:

1. Discovers the domain's NS records.
2. Resolves each nameserver to its IPv4 and IPv6 addresses.
3. Attempts an AXFR request directly against the nameserver.
4. Reports whether the transfer succeeded.
5. Saves successfully transferred zone data to a separate file.

Example output:

```text
[*] Attempting AXFR against 2 nameserver(s)
[AXFR] FAILED: example.com via ns1.example.com
[AXFR] SUCCESS: example.com via ns2.example.com (192.0.2.53) -> zones/example.com_ns2.example.com_192.0.2.53.zone
```

Successful zone transfers are saved in BIND-style zone-file format.

The default output directory is:

```text
zones/
```

To specify another directory:

```bash
python dns_audit.py example.com --zone-dir axfr_results
```

To disable AXFR testing:

```bash
python dns_audit.py example.com --skip-axfr
```

**Important:** A successful zone transfer is not automatically an unauthorized disclosure. AXFR can be intentionally permitted for authorized secondary DNS servers. Additionally, an AXFR failure may result from an explicit refusal, timeout, connection failure, or another DNS error.

### 9. Reverse DNS (PTR) Lookups

DNS Audit performs reverse DNS queries for IPv4 and IPv6 addresses discovered through the domain's A and AAAA records.

For example, an IPv4 address is converted into its reverse DNS representation:

```text
192.0.2.10
```

Becomes:

```text
10.2.0.192.in-addr.arpa
```

The tool then queries the resulting name for PTR records.

**Why it matters:** Reverse DNS can reveal hostname conventions, infrastructure naming patterns, and additional contextual information about identified systems.

### 10. Custom DNS Resolvers

By default, DNS Audit uses the operating system's configured DNS resolvers.

Custom DNS resolvers can be supplied using a text file.

Example `resolvers.txt`:

```text
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
```

Usage:

```bash
python dns_audit.py example.com --resolvers resolvers.txt
```

Each line must contain a valid IPv4 or IPv6 address. Empty lines and comments beginning with `#` are ignored.

**Note:** The resolver list is used for normal DNS lookups. AXFR requests are made directly to discovered nameserver addresses.

## Output Files

### CSV Results

All successfully discovered records are written to a CSV file.

Default filename:

```text
example.com_dns.csv
```

Example:

```csv
domain,record_type,result
example.com,A,192.0.2.10
example.com,MX,10 mail.example.com.
example.com,TXT,v=spf1 ip4:192.0.2.0/24 -all
_dmarc.example.com,TXT,v=DMARC1; p=reject
selector1._domainkey.example.com,CNAME,selector1.provider.example.
_sip._tcp.example.com,SRV,10 60 5060 sip.example.com.
```

CSV fields:

| Field | Description |
|---|---|
| `domain` | DNS owner name associated with the record |
| `record_type` | DNS record type |
| `result` | DNS response value |

Duplicate rows are removed automatically.

The CSV contains records discovered through the normal DNS enumeration routines. Successful AXFR zone data is saved separately rather than automatically merged into the CSV.

### Debug Logs

Enable debug logging with:

```bash
python dns_audit.py example.com --debug-file debug.txt
```

The debug file can contain:

- DNS query names and record types
- DNS response values
- NXDOMAIN and no-answer results
- Resolver errors and timeouts
- MXToolbox request URLs and response bodies
- AXFR attempts, errors, and success messages

To print detailed logging to the terminal:

```bash
python dns_audit.py example.com --verbose
```

Both options can be used simultaneously.

**Note:** Debug logs may contain sensitive DNS data and API response contents. Review them before sharing publicly.

## Example Usage

**Basic DNS enumeration**

```bash
python dns_audit.py example.com
```

**DNS enumeration with custom resolvers**

```bash
python dns_audit.py example.com --resolvers resolvers.txt
```

**Email security analysis using MXToolbox**

```bash
python dns_audit.py example.com --mxtoolbox-api-key "YOUR_API_KEY"
```

**Custom SRV and DKIM selector wordlists**

```bash
python dns_audit.py example.com --srvs custom_srvs.txt --selectors custom_selectors.txt
```

**Save CSV and debug output**

```bash
python dns_audit.py example.com --output results.csv --debug-file debug.txt
```

**DNS enumeration without AXFR or MXToolbox**

```bash
python dns_audit.py example.com --skip-axfr --skip-mxtoolbox
```

**Increase DNS query timeouts**

```bash
python dns_audit.py example.com --timeout 10 --lifetime 15
```

## Troubleshooting

| Issue | Possible Cause / Resolution |
|---|---|
| No DNS records returned | Confirm the domain exists and DNS resolution is available |
| DNS queries time out | Check network connectivity or increase `--timeout` and `--lifetime` |
| No SRV records discovered | Verify `srvs.txt` exists and contains relevant service prefixes |
| No DKIM selectors discovered | Verify `selectors.txt` exists and contains the domain's selector names |
| MXToolbox returns HTTP 401/403 | Check API key validity, permissions, and account access |
| MXToolbox returns HTTP 429 | API rate limits may have been exceeded |
| AXFR fails | The server may reject transfers, be unreachable, or time out |
| Custom resolvers fail | Verify `resolvers.txt` contains valid IP addresses |
| Debug file is empty or missing details | Confirm `--debug-file` is supplied and check whether queries were executed |

For detailed troubleshooting:

```bash
python dns_audit.py example.com --verbose --debug-file debug.txt
```

## Known Limitations

- **Not a comprehensive subdomain enumerator.** The tool queries the supplied domain, wordlist-derived SRV/DKIM names, and reverse DNS names associated with discovered addresses.
- **Wordlist-dependent discovery.** DKIM selectors and SRV service prefixes must be represented in the supplied wordlists.
- **Limited local SPF analysis.** Only explicit `ip4:` mechanisms are checked for CIDR ranges broader than `/24`.
- **MXToolbox diagnostics depend on API responses.** The tool searches selected diagnostic field names and may not recognize every status or result schema.
- **No independent DKIM cryptographic validation.** TXT/CNAME discovery does not verify signatures or key strength.
- **No comprehensive DNSSEC validation.** DS and DNSKEY records are collected, but DNSSEC trust chains are not validated.
- **No recursive CNAME or service-target enumeration.** Additional hostnames are not comprehensively followed and enumerated.
- **No AXFR content merging.** Successful zone transfers are exported separately from the normal CSV.
- **Sequential execution.** DNS queries and API calls are performed sequentially rather than concurrently.

## Security and Responsible Use

DNS Audit is intended for legitimate security assessments, infrastructure auditing, and authorized penetration testing.

Only perform testing against domains and DNS infrastructure you own or are explicitly authorized to assess.

While most DNS lookups are standard operations, AXFR attempts may be logged, filtered, or prohibited by the target organization's security policy.

Users are responsible for complying with applicable laws, service-provider terms, and testing agreements.

## Suggested Repository Structure

```text
dns-audit/
├── dns_audit.py
├── README.md
├── requirements.txt
├── srvs.txt
├── selectors.txt
├── resolvers.txt
├── .gitignore
└── LICENSE
```

The following files and directories are generated during execution and should generally not be committed:

```text
*_dns.csv
*_debug.txt
zones/
.venv/
__pycache__/
```

Suggested `.gitignore`:

```gitignore
# Python
__pycache__/
*.py[cod]
.venv/
venv/

# DNS Audit output
*_dns.csv
*_debug.txt
zones/
*.zone

# Local secrets and configuration
.env
.env.*
```

## Potential Future Enhancements

Possible improvements include:

- Recursive SPF mechanism evaluation and include-chain analysis
- More comprehensive DMARC policy validation
- DKIM key-strength and public-key analysis
- Additional DNSSEC security checks
- Concurrent DNS queries for faster enumeration
- Optional JSON and HTML report generation
- DNS record comparison between scans
- Additional DNS misconfiguration checks
- More detailed MXToolbox result classification
- Automated testing and continuous integration support

## References

- [dnspython Documentation](https://dnspython.readthedocs.io/)
- [Python Requests Documentation](https://requests.readthedocs.io/)
- [MXToolbox API Reference](https://mxtoolbox.com/api/api-reference)
- [RFC 1034 — Domain Names: Concepts and Facilities](https://www.rfc-editor.org/rfc/rfc1034)
- [RFC 1035 — Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 5936 — DNS Zone Transfer Protocol (AXFR)](https://www.rfc-editor.org/rfc/rfc5936)
- [RFC 7208 — Sender Policy Framework (SPF)](https://www.rfc-editor.org/rfc/rfc7208)
- [RFC 6376 — DomainKeys Identified Mail (DKIM)](https://www.rfc-editor.org/rfc/rfc6376)
- [RFC 7489 — DMARC](https://www.rfc-editor.org/rfc/rfc7489)

## License

Add a `LICENSE` file specifying the license under which this project is distributed. An MIT license is a common choice for open-source Python security utilities.
