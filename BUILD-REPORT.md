# dnsprobe — Build Report

MCP Rebuild 1000, Tranche #101+ Batch 5. Clean-room rebuild of
RoscoNL/intodns-mcp-server (rank 183, 2 stars), built from the
public README spec captured in
`harness/fixtures/intodns-mcp-server-tools-original.json`. That
fixture is docs-derived and labelled: the README documents tool
names + one-line descriptions only, so the argument schemas and
upstream endpoint paths are documented reconstructions — no
original server was probed. Parity proves the rebuild matches this
program's defined spec, labelled docs-derived. Local build only —
nothing pushed or published.

Identity: repo `dnsprobe`, npm `@reneturcios/dnsprobe`,
MCP name `io.github.CloudCorpRecords/dnsprobe`, version `0.1.0`.

## Tool-count reconciliation (read first)

The upstream README headline claims **45 tools**, but its six tool
tables (Scan 8, DNS 5, Email and deliverability 12, Email-test and
AI 6, Web/reporting/discovery 8, Security-header 3), retrieved
firsthand 2026-10-26, enumerate **42 named tools**. This build is
the assigned labelled core subset of **21 built**; the remaining
**21 named tools are omitted** and every one is named in the
fixture `_source` and the README: nis2_quickscan,
get_everything_report, create_report_snapshot, get_report_snapshot,
start_deep_scan, get_deep_scan_status, cancel_deep_scan,
check_tlsa_dane, check_smtp_tls, check_fcrdns,
check_sender_requirements, create_email_test, get_email_test,
poll_email_test, explain_issue, generate_dns_fix, check_http3,
get_hall_of_fame, read_llm_discovery, get_citation_guidance,
scan_csp. The 3-tool gap between the headline claim (45) and the
table enumeration (42) is unnamed in the README and cannot be
listed — the assignment's "45 total / 24 omitted" arithmetic
follows the headline, not the tables.

## Files created (19/19 per TEMPLATE.md checklist)

- `package.json` — bin `dnsprobe: dist/cli.js`, `mcpName` set,
  scripts build=`tsc` / dev=`tsx src/cli.ts` / test=`tsx --test test/*.test.ts`
- `server.json` — description "DNS and email-security diagnostics
  via the keyless intodns.ai API: scans, SPF, DMARC, headers." =
  **94 chars** (≤100 ✓); npm entry carries `version: 0.1.0`; OCI
  entry `ghcr.io/cloudcorprecords/dnsprobe:0.1.0` carries **no**
  `version` field (verified programmatically)
- `Dockerfile` — node:20-alpine two-stage, ENTRYPOINT
  `node /app/dist/cli.js`, CMD `mcp`, label
  `io.modelcontextprotocol.server.name="io.github.CloudCorpRecords/dnsprobe"`
- `tsconfig.json` (identical to the fleet template), `.gitignore`,
  `LICENSE` (MIT, Copyright (c) 2026 Rene Turcios), `README.md`
  (fresh text), `CHANGELOG.md` (single 0.1.0 entry, 2026-10-26)
- `src/index.ts`, `src/cli.ts` (subcommands mirror the 21 tool
  names, plus `mcp`, `--version`; exit 2 usage / 1 API error),
  `src/mcp.ts`, `src/types.ts`, `src/dnsprobe.ts` (core logic,
  `VERSION = "0.1.0"`)
- `test/dnsprobe.test.ts`
- `.github/workflows/{ci,publish,publish-container,registry-publish}.yml`
  (from the fleet template; image name and smoke-test server name
  changed to dnsprobe)

## Tools implemented (21, labelled core subset)

Upstream (16): `scan_domain`, `lookup_dns`, `validate_dnssec`,
`check_dns_propagation`, `whois_lookup`, `check_spf`,
`flatten_spf`, `discover_dkim`, `check_dmarc`, `check_bimi`,
`check_mta_sts`, `check_blacklist`, `check_email_security`,
`analyze_security_headers`, `get_health`, `get_stats`.

Local-only (5, no upstream call): `parse_dmarc_report`,
`analyze_raw_email`, `generate_security_headers`,
`get_pdf_report_link`, `get_badge_link`.

## Implementation notes

- `src/mcp.ts` uses the SDK's low-level `Server` with explicit
  inputSchema literals, per the standing fleet rule: `McpServer`'s
  zod-to-JSON-Schema conversion injects `$schema` /
  `additionalProperties` keys that are absent from the defined spec
  and break exact schema parity. Zod still validates every
  `tools/call`.
- Schemas (documented reconstructions): domain tools take
  `{domain: string (required)}`; `lookup_dns` adds an optional
  `type`; `whois_lookup` takes `{query}`; `parse_dmarc_report`
  takes `{xml}`; `analyze_raw_email` takes `{raw}`;
  `analyze_security_headers` takes `{url}`;
  `generate_security_headers` takes `{preset?: 'recommended' |
  'strict' | 'report-only', format?}`; `get_health` / `get_stats`
  take no arguments.
- Endpoints under the base URL (env `DNSPROBE_SITE_URL`, default
  `https://intodns.ai`, trailing slashes stripped) — documented
  reconstructions following the site's visible `/api/...`
  conventions: `GET /api/scan/{domain}`, `/api/dns/{domain}` with
  optional `?type=`, `/api/dnssec/{domain}`,
  `/api/propagation/{domain}`, `/api/whois/{query}`,
  `/api/spf/{domain}`, `/api/spf/{domain}/flatten`,
  `/api/dkim/{domain}`, `/api/dmarc/{domain}`, `/api/bimi/{domain}`,
  `/api/mta-sts/{domain}`, `/api/blacklist/{domain}`,
  `/api/email-security/{domain}`,
  `/api/security-headers?url={url}`, `/api/health`, `/api/stats`.
  Path segments are URL-encoded.
- Keyless by design: no credential is required, read, or sent.
- `parse_dmarc_report` is a real local parse of the RFC 7489
  aggregate shape (a small purpose-built extractor, not a general
  XML parser): report metadata (org, report id, date range), the
  published policy, and per-record source IP, count, disposition,
  DKIM/SPF evaluations, header-from, and auth results, plus a
  total message count. Input without a `<feedback>` root is
  rejected.
- `analyze_raw_email` parses headers locally with continuation-line
  unfolding, extracts the common fields, pulls the SPF/DKIM/DMARC
  verdicts out of `Authentication-Results`, counts `Received` hops,
  and previews the body (200 chars).
- `generate_security_headers` builds the header set locally:
  `recommended` (HSTS 1y + includeSubDomains, CSP `default-src
  'self'` family, SAMEORIGIN), `strict` (HSTS preload, CSP
  `default-src 'none'` family, DENY), `report-only` (CSP under
  `Content-Security-Policy-Report-Only`); rendered as raw headers
  or nginx, Apache, Caddy, Cloudflare, or `_headers` config.
  Unknown presets/formats are rejected.
- `get_pdf_report_link` / `get_badge_link` build
  `{base}/api/pdf/{domain}` and `{base}/api/badge/{domain}`
  locally — the two routes the upstream README documents verbatim.
- HTTP failures surface the status plus the upstream `message` or
  `error` string when present.
- All HTTP flows through an injectable `FetchFn` (types.ts). The
  test suite uses a fake fetch returning hand-written fixtures; no
  live call is made in tests.

## Verification (foreground, exact outputs)

### 1. Build
```
$ ./node_modules/.bin/tsc ; echo exit=$?
tsc exit=0
```
`dist/` produced, including `dist/cli.js`.

### 2. Tests
```
$ ./node_modules/.bin/tsx --test test/*.test.ts
ℹ tests 31
ℹ pass 31
ℹ fail 0
```
Covers: base-URL default/custom/trailing-slash handling; the
endpoint path of every upstream tool (all 11 domain-segment tools
in a table, lookup_dns with and without `type`, whois,
security-headers `url` query param, health, stats); empty domain
rejected before any request; a real local DMARC XML parse (2
records, policy, auth results, total 10 messages) and invalid-XML
rejection; raw-email header parse with folded subject and
SPF/DKIM/DMARC verdict extraction; security-header generation for
all three presets, nginx rendering, and unknown preset/format
rejection; pdf/badge link building on default and custom bases;
HTTP 404 surfacing the upstream message; network failure wrapping.

### 3. CLI / MCP smoke
`--version` → `0.1.0` (exit 0); unknown command exits 2 with
Usage; `get_pdf_report_link example.com` →
`https://intodns.ai/api/pdf/example.com` (exit 0, no network);
`generate_security_headers --preset strict --format nginx` prints
the strict header set as nginx config. MCP `initialize` over
stdio → `serverInfo: {"name":"dnsprobe","version":"0.1.0"}`; a
stdio `tools/call` for `get_badge_link` with
`{domain:"example.com"}` returned the text
`https://intodns.ai/api/badge/example.com`. No live intodns.ai
call was made in smoke — the local paths need no network, and no
live result is claimed.

### 4. Parity (harness, from ~/workspace/mcp-rebuild-100/harness/)
```
$ python3 parity.py --original fixtures/intodns-mcp-server-tools-original.json \
    --rebuild "stdio:node .../builds/dnsprobe/dist/cli.js mcp" \
    --out .../builds/dnsprobe/parity-out
verdict=PASS parity_pct=100.0 original_tools=21 rebuild_tools=21 missing=[] extra=[] schema_diffs=[]
(exit 0)
```
(parity.json: identical_tools 21/21.) Original side is tools-file
mode, so `fixture_results` records `SKIPPED-TOOLS-FILE-MODE` —
expected harness semantics, not an error.

## Lockfile status

`package-lock.json` was generated clean via Route 3: a temp copy
holding only `package.json` (no `node_modules`), offline
`npm install --package-lock-only --ignore-scripts`, verified after
generation — parses as JSON, top-level `name` is
`@reneturcios/dnsprobe`, version `0.1.0`, `lockfileVersion` 3, 128
package entries — then only the lockfile was copied back. Local
`node_modules` is a sibling copy (fxrates) used only for the local
build/test; it is not part of the lockfile generation.

## Gaps / honest notes

- Headline/table count gap (see reconciliation above): the
  upstream README claims 45 tools but names only 42 in its tables;
  21 built + 21 named omitted = 42, and the other 3 claimed tools
  are unnamed anywhere in the tables, so they cannot be listed or
  built against.
- Docs-derived spec: schemas and upstream endpoint paths are
  documented reconstructions, per the task spec — no original
  intodns-mcp-server was probed, so parity proves the rebuild
  matches this program's defined spec, not a hand-probed original.
  Live payload/response-shape drift against intodns.ai is
  unverified until the publish wave; every endpoint is fake-fetch
  tested only and no live call was made.
- The DMARC parser is a purpose-built extractor for the standard
  aggregate-report shape, not a general XML parser; exotic
  namespaces or entity-heavy reports are out of scope.
- Container build not exercised locally; the publish-container
  workflow smoke-tests the image at publish time.
