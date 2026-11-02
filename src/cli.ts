#!/usr/bin/env node
/**
 * dnsprobe CLI. Subcommands mirror the MCP tool names:
 *
 *   dnsprobe scan_domain <domain>
 *   dnsprobe lookup_dns <domain> [--type MX]
 *   dnsprobe validate_dnssec <domain>
 *   dnsprobe check_dns_propagation <domain>
 *   dnsprobe whois_lookup <query>
 *   dnsprobe check_spf <domain>
 *   dnsprobe flatten_spf <domain>
 *   dnsprobe discover_dkim <domain>
 *   dnsprobe check_dmarc <domain>
 *   dnsprobe parse_dmarc_report <xml>
 *   dnsprobe check_bimi <domain>
 *   dnsprobe check_mta_sts <domain>
 *   dnsprobe check_blacklist <domain>
 *   dnsprobe check_email_security <domain>
 *   dnsprobe analyze_raw_email <raw>
 *   dnsprobe analyze_security_headers <url>
 *   dnsprobe generate_security_headers [--preset strict] [--format nginx]
 *   dnsprobe get_health
 *   dnsprobe get_stats
 *   dnsprobe get_pdf_report_link <domain>
 *   dnsprobe get_badge_link <domain>
 *   dnsprobe mcp
 *
 * Keyless. Base URL from DNSPROBE_SITE_URL, default https://intodns.ai.
 * Exit codes: 0 success, 1 API/local error, 2 usage error.
 */
import {
  BASE_URL_ENV,
  analyzeRawEmail,
  analyzeSecurityHeaders,
  checkBimi,
  checkBlacklist,
  checkDmarc,
  checkDnsPropagation,
  checkEmailSecurity,
  checkMtaSts,
  checkSpf,
  discoverDkim,
  flattenSpf,
  formatPayload,
  generateSecurityHeaders,
  getBadgeLink,
  getHealth,
  getPdfReportLink,
  getStats,
  lookupDns,
  parseDmarcReport,
  resolveBaseUrl,
  scanDomain,
  validateDnssec,
  VERSION,
  whoisLookup,
} from "./dnsprobe.js";
import type { FetchFn, SecurityHeadersPreset } from "./types.js";

const DOMAIN_TOOLS = [
  "scan_domain", "validate_dnssec", "check_dns_propagation", "check_spf",
  "flatten_spf", "discover_dkim", "check_dmarc", "check_bimi",
  "check_mta_sts", "check_blacklist", "check_email_security",
  "get_pdf_report_link", "get_badge_link",
];

function usage(): never {
  console.error(`Usage:
  dnsprobe scan_domain <domain>
  dnsprobe lookup_dns <domain> [--type MX]
  dnsprobe validate_dnssec <domain>
  dnsprobe check_dns_propagation <domain>
  dnsprobe whois_lookup <query>
  dnsprobe check_spf <domain>
  dnsprobe flatten_spf <domain>
  dnsprobe discover_dkim <domain>
  dnsprobe check_dmarc <domain>
  dnsprobe parse_dmarc_report <xml>
  dnsprobe check_bimi <domain>
  dnsprobe check_mta_sts <domain>
  dnsprobe check_blacklist <domain>
  dnsprobe check_email_security <domain>
  dnsprobe analyze_raw_email <raw>
  dnsprobe analyze_security_headers <url>
  dnsprobe generate_security_headers [--preset recommended|strict|report-only] [--format raw|nginx|apache|caddy|cloudflare|_headers]
  dnsprobe get_health
  dnsprobe get_stats
  dnsprobe get_pdf_report_link <domain>
  dnsprobe get_badge_link <domain>
  dnsprobe mcp
  dnsprobe --version`);
  process.exit(2);
}

function flag(rest: string[], name: string): string | undefined {
  const i = rest.indexOf(name);
  return i >= 0 ? rest[i + 1] : undefined;
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "--version" || cmd === "-v") {
    console.log(VERSION);
    return;
  }
  if (cmd === "mcp") {
    await import("./mcp.js");
    return;
  }
  if (!cmd) usage();
  const fetchFn = globalThis.fetch as unknown as FetchFn;
  const baseUrl = resolveBaseUrl(process.env[BASE_URL_ENV]);
  try {
    let out: unknown;
    if (DOMAIN_TOOLS.includes(cmd)) {
      if (!rest[0]) usage();
      const domain = rest[0];
      switch (cmd) {
        case "scan_domain": out = await scanDomain(fetchFn, baseUrl, { domain }); break;
        case "validate_dnssec": out = await validateDnssec(fetchFn, baseUrl, { domain }); break;
        case "check_dns_propagation": out = await checkDnsPropagation(fetchFn, baseUrl, { domain }); break;
        case "check_spf": out = await checkSpf(fetchFn, baseUrl, { domain }); break;
        case "flatten_spf": out = await flattenSpf(fetchFn, baseUrl, { domain }); break;
        case "discover_dkim": out = await discoverDkim(fetchFn, baseUrl, { domain }); break;
        case "check_dmarc": out = await checkDmarc(fetchFn, baseUrl, { domain }); break;
        case "check_bimi": out = await checkBimi(fetchFn, baseUrl, { domain }); break;
        case "check_mta_sts": out = await checkMtaSts(fetchFn, baseUrl, { domain }); break;
        case "check_blacklist": out = await checkBlacklist(fetchFn, baseUrl, { domain }); break;
        case "check_email_security": out = await checkEmailSecurity(fetchFn, baseUrl, { domain }); break;
        case "get_pdf_report_link": out = getPdfReportLink(baseUrl, { domain }); break;
        default: out = getBadgeLink(baseUrl, { domain }); break;
      }
    } else if (cmd === "lookup_dns") {
      if (!rest[0]) usage();
      out = await lookupDns(fetchFn, baseUrl, { domain: rest[0], type: flag(rest, "--type") });
    } else if (cmd === "whois_lookup") {
      if (!rest[0]) usage();
      out = await whoisLookup(fetchFn, baseUrl, { query: rest[0] });
    } else if (cmd === "parse_dmarc_report") {
      if (!rest[0]) usage();
      out = parseDmarcReport({ xml: rest[0] });
    } else if (cmd === "analyze_raw_email") {
      if (!rest[0]) usage();
      out = analyzeRawEmail({ raw: rest[0] });
    } else if (cmd === "analyze_security_headers") {
      if (!rest[0]) usage();
      out = await analyzeSecurityHeaders(fetchFn, baseUrl, { url: rest[0] });
    } else if (cmd === "generate_security_headers") {
      out = generateSecurityHeaders({
        preset: flag(rest, "--preset") as SecurityHeadersPreset | undefined,
        format: flag(rest, "--format"),
      });
    } else if (cmd === "get_health") {
      out = await getHealth(fetchFn, baseUrl);
    } else if (cmd === "get_stats") {
      out = await getStats(fetchFn, baseUrl);
    } else {
      usage();
    }
    console.log(formatPayload(out));
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

void main();
