# dnsprobe

dnsprobe runs DNS and email-security diagnostics against the free,
keyless intodns.ai public API: full domain scans, DNS lookups,
DNSSEC validation, propagation checks, WHOIS/RDAP, and the email
authentication stack — SPF (including flattening), DKIM discovery,
DMARC, BIMI, MTA-STS, and blacklist checks. It also parses DMARC
aggregate reports and raw emails locally, and generates HTTP
security-header sets locally. One binary serves a command-line
interface and a stdio MCP server.

This is a labelled core subset: 21 of the tools named in the
upstream README's tool tables are built. The named tools not built
are `nis2_quickscan`, `get_everything_report`,
`create_report_snapshot`, `get_report_snapshot`, `start_deep_scan`,
`get_deep_scan_status`, `cancel_deep_scan`, `check_tlsa_dane`,
`check_smtp_tls`, `check_fcrdns`, `check_sender_requirements`,
`create_email_test`, `get_email_test`, `poll_email_test`,
`explain_issue`, `generate_dns_fix`, `check_http3`,
`get_hall_of_fame`, `read_llm_discovery`, `get_citation_guidance`,
and `scan_csp`. (The upstream README headline says 45 tools; its
six tables enumerate 42 named tools.)

No API key is needed. The site base URL can be overridden with
`DNSPROBE_SITE_URL`; when it is not set, calls go to
`https://intodns.ai`. Upstream endpoint paths are documented
reconstructions from the site's visible `/api/...` conventions —
the public spec documents tool names and descriptions, not paths.

## Install

```bash
npx @reneturcios/dnsprobe get_health
```

Or run the container image:

```bash
docker run -i ghcr.io/cloudcorprecords/dnsprobe
```

The container defaults to the MCP server (see below). Pass CLI
arguments to use it as a CLI instead.

## CLI

Subcommands mirror the MCP tool names:

```bash
dnsprobe scan_domain example.com
dnsprobe lookup_dns example.com --type MX
dnsprobe validate_dnssec example.com
dnsprobe whois_lookup example.com
dnsprobe check_spf example.com
dnsprobe check_email_security example.com
dnsprobe analyze_security_headers https://example.com
dnsprobe generate_security_headers --preset strict --format nginx
dnsprobe get_health
dnsprobe get_pdf_report_link example.com

dnsprobe --version
```

Commands print the upstream JSON payload, the locally computed
result, or the built link. Exit codes: `0` on success, `1` when a
call fails (including an upstream API error), `2` for usage errors.

Five tools never call the network: `parse_dmarc_report` parses a
DMARC aggregate (RUA) XML report into structured metadata, policy,
and per-record SPF/DKIM/DMARC results with message totals;
`analyze_raw_email` parses raw MIME headers (with unfolding),
extracts the `Authentication-Results` SPF/DKIM/DMARC verdicts, and
counts `Received` hops; `generate_security_headers` renders a
header set from the `recommended`, `strict`, or `report-only`
preset as raw headers or nginx, Apache, Caddy, Cloudflare, or
`_headers` config; `get_pdf_report_link` and `get_badge_link` build
`{base}/api/pdf/{domain}` and `{base}/api/badge/{domain}`.

## MCP server

One bin serves both faces. The `mcp` subcommand starts a stdio MCP
server:

```bash
npx -y @reneturcios/dnsprobe mcp
```

MCP client configuration:

```json
{
  "mcpServers": {
    "dnsprobe": {
      "command": "npx",
      "args": ["-y", "@reneturcios/dnsprobe", "mcp"]
    }
  }
}
```

To point the server at a different intodns.ai-compatible host, add
`DNSPROBE_SITE_URL` to the client's `env` for this server.

### Tools

| Tool | Input | What it returns |
| --- | --- | --- |
| `scan_domain` | `domain` | Grade, score, DNS/email/security results, issues, recommendations. |
| `lookup_dns` | `domain`, optional `type` | DNS records for the domain. |
| `validate_dnssec` | `domain` | DNSSEC chain, DS/DNSKEY, and algorithm validation. |
| `check_dns_propagation` | `domain` | Propagation across global resolvers. |
| `whois_lookup` | `query` | WHOIS/RDAP data for a domain or IP. |
| `check_spf` | `domain` | SPF parse, lookup graph, and validation. |
| `flatten_spf` | `domain` | The SPF graph flattened to literal ip4/ip6 mechanisms. |
| `discover_dkim` | `domain` | Discovered DKIM selectors. |
| `check_dmarc` | `domain` | DMARC parse and policy validation. |
| `parse_dmarc_report` | `xml` | Structured DMARC aggregate report (local parse). |
| `check_bimi` | `domain` | BIMI DNS, logo URL, and VMC/CMC readiness. |
| `check_mta_sts` | `domain` | MTA-STS DNS and policy-file validation. |
| `check_blacklist` | `domain` | Blacklist status for the domain's mail servers. |
| `check_email_security` | `domain` | Full SPF/DKIM/DMARC/blacklist check with score and issues. |
| `analyze_raw_email` | `raw` | Header and authentication analysis of a raw email (local). |
| `analyze_security_headers` | `url` | Present/missing HTTP security headers for a live site. |
| `generate_security_headers` | optional `preset`, `format` | A generated security-header set and config snippet (local). |
| `get_health` | (none) | API, cache, and runtime health. |
| `get_stats` | (none) | Public scan/check counters. |
| `get_pdf_report_link` | `domain` | The `{base}/api/pdf/{domain}` URL (local). |
| `get_badge_link` | `domain` | The `{base}/api/badge/{domain}` URL (local). |

## Development

```bash
npm install
npm run build   # tsc -> dist/
npm test        # node test runner over test/*.test.ts, no network (fake fetch fixtures)
npm run dev     # run the CLI from source via tsx
```

## License

MIT — see `LICENSE`.
