# Changelog

## 0.1.0 (2026-10-26)

- Initial release.
- CLI: `dnsprobe <tool-name> ...` subcommands mirroring all 21 MCP
  tools, plus `dnsprobe mcp` and `dnsprobe --version`.
- MCP server (`dnsprobe mcp`, stdio) with 21 tools: a labelled core
  subset of the intodns-mcp-server documented surface (see README
  for the omitted tools).
- Sixteen tools call the intodns.ai public API under the base URL
  from `DNSPROBE_SITE_URL`, defaulting to `https://intodns.ai`; the
  service is keyless. Endpoint paths are documented reconstructions.
- Five tools are local-only: `parse_dmarc_report` (DMARC aggregate
  XML parsing), `analyze_raw_email` (raw MIME header analysis),
  `generate_security_headers` (recommended/strict/report-only
  presets in raw, nginx, Apache, Caddy, Cloudflare, and `_headers`
  formats), and the `get_pdf_report_link` / `get_badge_link` URL
  builders.
- HTTP failures surface the status plus the upstream `message` or
  `error` when present.
- All HTTP goes through an injectable fetch function, so the test
  suite runs entirely on hand-written fixtures with no network access.
