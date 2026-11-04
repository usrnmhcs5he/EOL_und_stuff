# Mail DNS and authentication assessment

Read-only PowerShell tool that assesses, for a list of domains, every DNS and
mail-authentication record that matters when a third-party email security gateway
is replaced by Exchange Online Protection (EOP) / Microsoft Defender for Office 365.

Use it three times in a migration:

- **Baseline** before the design: what is published today, from inside and outside.
- **Cutover verification**: MX, SPF, DKIM, MTA-STS and split-DNS state while switching.
- **Operations**: monthly runbook check; diff the JSON of two runs by `RuleId`.

Current version: **1** (version history in the header of `Invoke-MailDnsAssessment.ps1`).

## What it does and does not do

- Queries DNS (and, with `-CheckMtaSts`, fetches one HTTPS policy file per domain).
- Never writes to DNS, never authenticates to a tenant, never sends mail.
- Uses built-in components only: DnsClient `Resolve-DnsName`, `Invoke-WebRequest`
  and .NET sockets. No module installation, no installer.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 on Windows 10/11 or Windows Server 2016+.
- Outbound DNS (UDP/TCP 53) from the host to the resolvers you assess.
- For `-CheckMtaSts`: outbound HTTPS to `mta-sts.<domain>`; the certificate check
  additionally needs a direct TCP 443 connection (see Limitations).
- PowerShell 7 on Linux/macOS works on a best-effort basis: without
  `Resolve-DnsName` all queries go through the built-in socket resolver.

## Files

| File | Purpose |
| --- | --- |
| `Invoke-MailDnsAssessment.ps1` | Entry script: parameters, version history, run. |
| `MailDnsAssessment.psm1` | Functions, grouped by check. Must sit next to the script; both carry the same version and the script refuses a mismatched module. |
| `domains.sample.txt` | Example domain list. Copy to `domains.txt` (git-ignored). |
| `output/` | Default report folder (reports are git-ignored). |
| `tests/` | Pester tests (no network). |

If the files were downloaded, unblock both before the first run:

```powershell
Get-ChildItem -Path .\MailDnsAssessment -Recurse -Include *.ps1, *.psm1 | Unblock-File
```

## Parameters

| Parameter | Type | Default | Notes |
| --- | --- | --- | --- |
| `-DomainList` | path | `domains.txt` next to the script | One domain per line; `#` starts a comment. Keep it out of Git. |
| `-Domain` | string[] | | Ad-hoc alternative; can be combined with `-DomainList`. |
| `-Vantage` | `Internal`, `External`, `Both` | `Both` | Which resolver sets are queried. |
| `-InternalResolver` | string[] | DNS servers of this machine (`Get-DnsClientServerAddress`) | |
| `-ExternalResolver` | string[] | `1.1.1.1`, `8.8.8.8`, `9.9.9.9` | |
| `-DkimSelector` | string[] | | Extra selectors; `selector1` and `selector2` are always probed. |
| `-CheckMtaSts` | switch | off | `_mta-sts` TXT, HTTPS policy fetch, certificate, `_smtp._tls` TLS-RPT. |
| `-CheckDane` | switch | off | TLSA `_25._tcp.<mx>` with DNSSEC OK; reports validation (AD flag). |
| `-CheckDnssec` | switch | off | SOA and MX with DNSSEC OK; AD flag per vantage; bogus detection. |
| `-OutputPath` | path | `output` next to the script | Folder for JSON, CSV and Markdown. |
| `-Sanitize` | switch | off | Pseudonymise names and mask addresses in all report files. |
| `-TimeoutSeconds` | int (1-60) | `5` | Per query and resolver. |

### Vantage logic

- `Internal`: internal resolvers only. `External`: external resolvers only.
- `Both`: every query runs against both sets; the report adds a cross-vantage diff.
- Within a set the resolvers are tried in order until one answers (NOERROR, NODATA or
  NXDOMAIN). The report records the resolver that answered and the TTL it returned.
  A resolver that times out twice in a row is tried last for the rest of the run.
- Findings that are identical on both vantages are reported once with vantage `Both`;
  a finding that exists on one side only keeps `Internal` or `External`.

## Examples

```powershell
.\Invoke-MailDnsAssessment.ps1 -Domain example.com -Vantage External
```

```powershell
.\Invoke-MailDnsAssessment.ps1 -DomainList .\domains.txt -CheckMtaSts -CheckDane -CheckDnssec
```

```powershell
.\Invoke-MailDnsAssessment.ps1 -Domain example.com, example.net -InternalResolver 192.0.2.53 -DkimSelector s1, k1 -Verbose
```

```powershell
.\Invoke-MailDnsAssessment.ps1 -DomainList .\domains.txt -CheckMtaSts -Sanitize -OutputPath C:\Temp\share
```

`-Verbose` prints every query (vantage, name, type, resolver, status, record count).
The console shows a progress bar over the domains, the report paths and a summary table.

## Checks

| Area | What is queried | Highlights |
| --- | --- | --- |
| MX | MX, A/AAAA (and CNAME) of every MX host | Classifies hosts as `EOP` (`*.mail.protection.outlook.com`), `EOP-DANE` (`*.mx.microsoft`), `OnPremises` (inside an assessed domain) or `Other`; flags EOP + non-Microsoft (bypass path), no MX, null MX, MX to CNAME, unresolvable host, TTL above 3600 or below 300. |
| SPF | Apex TXT, recursively every `include:` and `redirect=` | Zero/multiple records, 10-lookup limit (warning at 8), void lookups (limit 2), `all` qualifier, `ptr`, `a`/`mx` cost, includes without SPF, loops, macros, `spf.protection.outlook.com` presence and the lookup count after adding it. Every term is attributed to the record that brought it in; `ip4`/`ip6` inventory after expansion. |
| DKIM | `selector1`, `selector2` and `-DkimSelector`: CNAME and TXT | CNAME target class (EOP `*.onmicrosoft.com` or `*.dkim.mail.microsoft`), TXT instead of CNAME, key type and RSA modulus length from the DER structure, revoked keys, `t=y`, `h=sha1`. |
| DMARC | `_dmarc.<domain>` TXT, parent domain if absent | All tags (`v p sp pct rua ruf adkim aspf fo rf ri`); missing/multiple records, `p=none`, `pct<100`, `sp` missing while subdomains are in scope, `rua` missing, external report authorisation (`<domain>._report._dmarc.<destination>`), `ruf` present. |
| MTA-STS (`-CheckMtaSts`) | `_mta-sts` TXT, `https://mta-sts.<domain>/.well-known/mta-sts.txt`, `_smtp._tls` TXT | HTTP status, content type, certificate (subject, SAN match, expiry, chain), `version`, `mode`, `max_age`, `mx` lines matched against the real MX hosts, cutover blocker when an enforce policy does not allow EOP, TLS-RPT `rua`. |
| DANE (`-CheckDane`) | `_25._tcp.<mx>` TLSA with DNSSEC OK | Records (usage, selector, matching type, data), AD flag, RRSIG presence, PKIX usages, SERVFAIL. |
| DNSSEC (`-CheckDnssec`) | SOA and MX with DNSSEC OK | `Validated`, `SignedNotValidated`, `Unsigned`, `Bogus` (SERVFAIL that resolves with checking disabled); internal vs external difference. |
| Other | `autodiscover` CNAME/A, `_autodiscover._tcp` SRV, `_sip._tls`, `_sipfederationtls._tcp`, `lyncdiscover`, `enterpriseregistration`, `enterpriseenrollment`, `msoid`, apex TXT, SOA, NS | Autodiscover class (`Microsoft365`, `OnPremises`, `Other`); optional records reported only if present; apex TXT inventory with a classifier so stale verification tokens are visible. |
| Cross-vantage diff (`-Vantage Both`) | Every name/type queried on both sides | `Identical`, `Differs`, `MissingInternal`/`MissingExternal`, `FailedInternal`/`FailedExternal`, with data and TTL per side. |

## Outputs

All files are written UTF-8 without BOM to `-OutputPath` with the same timestamp:

- `assessment-<yyyyMMdd-HHmmss>.json`: full structured result. `Meta` (version, vantage,
  resolvers, options) and one object per domain with `Summary`, `Findings`, `Checks`
  (per vantage: `Mx`, `Spf`, `Dkim`, `Dmarc`, `MtaSts`, `Dane`, `Dnssec`, `Other`),
  `Records` (every answer with vantage, resolver, status, TTL, AD flag) and `VantageDiff`.
- `assessment-<timestamp>.csv`: one row per domain: MX class and hosts, MX TTL, SPF lookups,
  void lookups, `all`, EOP include, DKIM selector1/2 key size (or `missing`,
  `CNAME (no key)`, `revoked`), DMARC p/sp/pct, MTA-STS mode, DANE, DNSSEC, autodiscover,
  finding count per severity. Values come from the external vantage when it was queried.
- `assessment-<timestamp>.md`: summary table, then per domain the findings (severity, rule,
  check, vantage, target, message, recommendation), SPF expansion and IP inventory, DKIM,
  DMARC, MTA-STS, all raw records with TTL and vantage, and the cross-vantage diff.

To compare two runs, match findings on `Domain` + `RuleId` + `Target`.

### Severity scale

| Severity | Meaning |
| --- | --- |
| Critical | Breaks mail or authentication now (for example SPF permerror, no MX, MTA-STS enforce policy that excludes an MX host). |
| High | Will break at cutover or exceeds a hard limit (for example EOP not in SPF, EOP DKIM selectors missing, split-DNS difference). |
| Medium | Weak posture or little headroom. |
| Info | Informational. |

### Rules

| RuleId | Severity | Check | Title |
| --- | --- | --- | --- |
| `DOMAIN-001` | Critical | Domain | Domain does not exist (NXDOMAIN) |
| `DNS-001` | Medium | DNS | Query failed on every resolver of the vantage |
| `MX-001` | Critical | MX | No MX record |
| `MX-002` | High | MX | Microsoft and non-Microsoft MX targets mixed (bypass path) |
| `MX-003` | High | MX | MX target is a CNAME |
| `MX-004` | Medium | MX | MX TTL above 3600 seconds (slow cutover) |
| `MX-005` | Info | MX | MX TTL below 300 seconds |
| `MX-006` | Critical | MX | MX host does not resolve to an address |
| `MX-007` | Info | MX | MX does not point to EOP |
| `MX-008` | Info | MX | Null MX published (domain does not accept mail) |
| `MX-009` | Info | MX | EOP MX without DANE (mail.protection.outlook.com) |
| `MX-010` | Info | MX | Legacy and DANE-enabled EOP MX hosts both published |
| `SPF-001` | High | SPF | No SPF record |
| `SPF-002` | Critical | SPF | Multiple SPF records (permerror) |
| `SPF-003` | Critical | SPF | SPF DNS lookups exceed 10 (permerror) |
| `SPF-004` | Medium | SPF | SPF DNS lookups at 8 or more (little headroom) |
| `SPF-005` | Critical | SPF | SPF void lookups exceed 2 (permerror) |
| `SPF-006` | Critical | SPF | SPF +all authorises every host |
| `SPF-007` | Medium | SPF | SPF has no all mechanism and no redirect |
| `SPF-008` | Medium | SPF | SPF ptr mechanism used (deprecated) |
| `SPF-009` | Info | SPF | SPF a or mx mechanism costs a lookup |
| `SPF-010` | Critical | SPF | SPF include or redirect target has no SPF record (permerror) |
| `SPF-011` | Info | SPF | spf.protection.outlook.com is authorised |
| `SPF-012` | High | SPF | spf.protection.outlook.com is not authorised |
| `SPF-013` | High | SPF | Adding spf.protection.outlook.com would exceed 10 lookups |
| `SPF-014` | Info | SPF | SPF macros present (not expanded) |
| `SPF-015` | Critical | SPF | SPF syntax error (permerror) |
| `SPF-016` | Medium | SPF | SPF ends with ?all (neutral) |
| `SPF-017` | Critical | SPF | SPF include loop |
| `SPF-018` | Info | SPF | SPF ends with ~all (softfail) |
| `DKIM-001` | High | DKIM | Neither EOP DKIM selector published |
| `DKIM-002` | Medium | DKIM | Only one EOP DKIM selector published |
| `DKIM-003` | Medium | DKIM | Requested DKIM selector not found |
| `DKIM-004` | High | DKIM | EOP selector published as TXT instead of CNAME |
| `DKIM-005` | Medium | DKIM | DKIM RSA key shorter than 2048 bits |
| `DKIM-006` | High | DKIM | DKIM RSA key shorter than 1024 bits |
| `DKIM-007` | Info | DKIM | DKIM key revoked (empty p=) |
| `DKIM-008` | High | DKIM | DKIM key record invalid or key not decodable |
| `DKIM-009` | Medium | DKIM | EOP selector CNAME points to a non-Microsoft target |
| `DKIM-010` | Info | DKIM | Non-RSA DKIM key |
| `DKIM-011` | Medium | DKIM | DKIM CNAME target has no key record |
| `DKIM-012` | Info | DKIM | DKIM key in test mode (t=y) |
| `DKIM-013` | Medium | DKIM | DKIM key restricted to SHA-1 (h=sha1) |
| `DKIM-014` | Medium | DKIM | Multiple DKIM key records at one selector |
| `DKIM-015` | Medium | DKIM | EOP selector CNAME refers to the other selector |
| `DMARC-001` | High | DMARC | No DMARC record |
| `DMARC-002` | Critical | DMARC | Multiple DMARC records (policy ignored) |
| `DMARC-003` | Medium | DMARC | DMARC policy p=none (monitoring only) |
| `DMARC-004` | Medium | DMARC | DMARC pct below 100 |
| `DMARC-005` | Medium | DMARC | DMARC sp not set while subdomains are in scope |
| `DMARC-006` | Medium | DMARC | DMARC rua not set (no aggregate reports) |
| `DMARC-007` | Medium | DMARC | DMARC report destination lacks external authorisation |
| `DMARC-008` | Info | DMARC | DMARC ruf present (failure reports) |
| `DMARC-009` | High | DMARC | DMARC record syntax error |
| `DMARC-010` | Info | DMARC | DMARC strict alignment (adkim=s or aspf=s) |
| `DMARC-011` | Medium | DMARC | DMARC sp=none weaker than p |
| `DMARC-012` | Info | DMARC | No DMARC record; parent domain policy applies |
| `DMARC-013` | Medium | DMARC | DMARC record published at the apex |
| `MTASTS-001` | Info | MTA-STS | MTA-STS not published |
| `MTASTS-002` | High | MTA-STS | MTA-STS TXT published but policy not retrievable |
| `MTASTS-003` | Medium | MTA-STS | MTA-STS policy published without _mta-sts TXT |
| `MTASTS-004` | Critical | MTA-STS | MTA-STS enforce policy does not cover all MX hosts |
| `MTASTS-005` | Medium | MTA-STS | MTA-STS testing policy does not cover all MX hosts |
| `MTASTS-006` | Info | MTA-STS | MTA-STS mode none or testing |
| `MTASTS-007` | Medium | MTA-STS | MTA-STS max_age below 86400 |
| `MTASTS-008` | High | MTA-STS | MTA-STS policy host certificate invalid |
| `MTASTS-009` | High | MTA-STS | MTA-STS policy syntax invalid |
| `MTASTS-010` | Medium | MTA-STS | MTA-STS TXT record invalid |
| `MTASTS-011` | High | MTA-STS | MTA-STS enforce policy does not allow EOP MX (cutover blocker) |
| `MTASTS-012` | Medium | MTA-STS | MTA-STS certificate expires within 30 days |
| `MTASTS-013` | Medium | MTA-STS | MTA-STS policy not served as text/plain |
| `TLSRPT-001` | Info | MTA-STS | No TLS-RPT record |
| `TLSRPT-002` | Medium | MTA-STS | TLS-RPT record invalid |
| `DANE-001` | Medium | DANE | TLSA published in an unsigned zone (DANE ineffective) |
| `DANE-002` | Info | DANE | TLSA present but the resolver did not validate |
| `DANE-003` | Info | DANE | No TLSA record for MX host |
| `DANE-004` | Medium | DANE | TLSA uses PKIX usage 0 or 1 (unsuitable for SMTP) |
| `DANE-005` | High | DANE | TLSA lookup failed (SERVFAIL) |
| `DNSSEC-001` | Info | DNSSEC | Zone not signed |
| `DNSSEC-002` | Info | DNSSEC | Zone signed but the resolver did not validate (AD not set) |
| `DNSSEC-003` | Critical | DNSSEC | DNSSEC validation fails (bogus) |
| `DNSSEC-004` | Medium | DNSSEC | DNSSEC validation differs between internal and external |
| `AUTOD-001` | Info | Autodiscover | Autodiscover not published |
| `AUTOD-002` | Info | Autodiscover | Autodiscover does not point to Exchange Online |
| `OTHER-001` | Info | Other | Legacy msoid CNAME present |
| `OTHER-002` | Info | Other | Teams/Skype or device registration records present |
| `TXT-001` | Info | TXT | Verification tokens present at the apex |
| `TXT-002` | Info | TXT | Multiple Microsoft 365 verification tokens (MS=) |
| `VANTAGE-001` | High | Vantage | Record differs between internal and external DNS |
| `VANTAGE-002` | High | Vantage | Record present on one vantage only |
| `VANTAGE-003` | Medium | Vantage | Query failed on one vantage only |
| `VANTAGE-004` | Info | Vantage | Address records differ between vantages |
| `VANTAGE-005` | Medium | Vantage | SOA or NS differ between vantages (separate internal zone) |

## Sanitisation (`-Sanitize`)

The report files (not the console) are rewritten before they are saved:

- Assessed domains become `domain-01`, `domain-02`, ... in the order of the input list
  (stable for the same list). The dashed form used in EOP host names
  (`example-com`) is replaced as well.
- Host names become pseudonyms by role: `mx-01` for MX hosts, `host-01` otherwise. A
  known provider suffix is kept so the classification stays readable
  (`mx-01.mail.protection.outlook.com`, `mx-02.o-v1.mx.microsoft`); names inside an assessed
  domain keep the domain pseudonym (`mx-03.domain-01`); service labels are kept
  (`_dmarc.domain-01`, `selector1._domainkey.domain-01`, `_25._tcp.mx-01.domain-02`).
  Well-known public names such as `spf.protection.outlook.com` and
  `autodiscover.outlook.com` are kept.
- Tenant names become `tenant-01.onmicrosoft.com`; DKIM CNAME targets become
  `selector1-key-01._domainkey.tenant-01.onmicrosoft.com`.
- IPv4 addresses are masked to /24 (`203.0.113.25` becomes `203.0.113.0/24`), IPv6 to /48;
  ranges that are already /24 (/48) or wider are kept. Public resolvers (`1.1.1.1`,
  `8.8.8.8`, `9.9.9.9`, ...) are kept.
- DKIM public keys (`p=`), verification token values (`MS=`, `*-verification=`), TLSA
  hashes, GUIDs and mailbox local parts (`dmarc@` becomes `mailbox@`) are masked.
- Before writing, every file is checked; if an assessed domain (dotted or dashed form)
  still occurs as a whole token, nothing is written and the run fails.

Pseudonym numbering for host names depends on the order in which names occur, so compare
sanitised reports by rule, not by pseudonym. Findings and their `RuleId` are identical with
and without `-Sanitize`.

## Limitations

- `Resolve-DnsName` honours the local DNS client cache and policy (NRPT). The script uses
  `-DnsOnly` and `-NoHostsFile`, but cached answers can show a reduced TTL.
- `Resolve-DnsName` neither exposes the DNSSEC AD flag nor supports the TLSA type. DNSSEC
  and DANE queries (and every query on non-Windows hosts) therefore use a small built-in
  DNS client over .NET UDP/TCP sockets (EDNS0, DO/CD bits). It talks to the same resolvers
  and bypasses the local cache and NRPT.
- The AD flag reflects the resolver's validation, not the tool's. A non-validating
  (typically internal) resolver always reports `SignedNotValidated`/unvalidated.
- `Resolve-DnsName` has no timeout parameter; each query runs in a reused runspace and is
  abandoned after `-TimeoutSeconds`.
- SPF macro mechanisms (`%{...}`) are reported but not expanded; their lookups are counted.
  The lookup count is the worst case (all terms evaluated).
- MTA-STS policy fetch depends on outbound HTTPS from the vantage host and uses the system
  proxy. The certificate details come from a direct TLS connection to port 443, which does
  not use a proxy; behind a proxy only the fetch result is reported.
- "Same organisation" for DMARC report authorisation and subdomain scope is decided by
  name suffix, without a public suffix list.
- DKIM key size decoding assumes RSA; Ed25519 keys are reported as non-RSA.
- Address records of load-balanced hosts often differ between resolvers; such differences
  are reported as `Info` (`VANTAGE-004`).

## Tests

The tests use fixed input strings and fixture zones; they make no network calls. They are
written to run under both Pester 3.4 (shipped with Windows PowerShell 5.1) and Pester 5:
setup lives in `BeforeAll`, and assertions are plain `throw` statements instead of `Should`,
whose syntax differs between the two versions.

```powershell
Invoke-Pester -Path .\MailDnsAssessment\tests
```

| File | Covers |
| --- | --- |
| `Parsers.Tests.ps1` | SPF, DMARC, tag-value and MTA-STS policy parsers; host pattern matching; classifiers. |
| `DkimKey.Tests.ps1` | RSA modulus length from SPKI and PKCS#1 via the manual DER parser, cross-checked against `RSA.ImportSubjectPublicKeyInfo` (PowerShell 7) and the `X509Certificates.PublicKey` constructor (5.1); Ed25519; revoked and broken keys. |
| `Dns.Tests.ps1` | DNS wire format, `Resolve-DnsName` normalisation, error mapping, failover, cache. |
| `Assessment.Tests.ps1` | End-to-end run against fixture zones for both vantages: expected findings per domain, summary, diff, report files, sanitisation. |
| `Repository.Tests.ps1` | Version numbers of script, module and README match; README rule table matches the catalog; ASCII-only sources; sample files contain only reserved names. |

## Conventions for changes

- Every change to the script or module increments the version by 1: version history entry
  in the script header, `$ScriptVersion` and `# Version: N` in the script,
  `$script:ModuleVersion` and `# Version: N` in the module, and "Current version" above.
  `Repository.Tests.ps1` fails when they differ.
- Every change ships with the updated README.
- No customer data anywhere in the repository: examples and tests use `example.com`,
  `example.net`, `example.org`, `tenant.onmicrosoft.com` and documentation IP ranges.
- Sources stay ASCII so Windows PowerShell 5.1 reads them correctly without a BOM.
