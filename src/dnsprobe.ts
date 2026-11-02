/**
 * dnsprobe core: a labelled core subset (21 of the named tools) of
 * the intodns-mcp-server surface, backed by the free keyless
 * intodns.ai public API.
 *
 * Upstream tools (16) call the public API under the base URL from
 * DNSPROBE_SITE_URL (default https://intodns.ai). The endpoint paths
 * below are DOCUMENTED RECONSTRUCTIONS (labelled): the public README
 * documents tool names and one-line descriptions only, so the paths
 * follow the site's visible /api/... conventions (e.g. the
 * documented /api/pdf/{domain} and /api/badge/{domain} routes).
 *
 * Local-only tools (5) never call upstream:
 *   parse_dmarc_report       parses DMARC aggregate XML locally
 *   analyze_raw_email        parses raw MIME headers locally
 *   generate_security_headers generates a header set locally
 *   get_pdf_report_link      builds {base}/api/pdf/{domain}
 *   get_badge_link           builds {base}/api/badge/{domain}
 *
 * Keyless: no credential is required, read, or sent. All HTTP goes
 * through an injected FetchFn so everything is testable offline.
 */
import type {
  AnalyzeRawEmailOptions,
  AnalyzeSecurityHeadersOptions,
  DmarcRecord,
  DmarcReport,
  DomainOptions,
  FetchFn,
  GenerateSecurityHeadersOptions,
  GeneratedSecurityHeaders,
  LookupDnsOptions,
  ParseDmarcReportOptions,
  RawEmailAnalysis,
  SecurityHeadersPreset,
  WhoisOptions,
} from "./types.js";

export const VERSION = "0.1.0";

export const DEFAULT_BASE_URL = "https://intodns.ai";

export const BASE_URL_ENV = "DNSPROBE_SITE_URL";

/** Resolve the site base URL: env value when non-blank, else default. Trailing slashes are stripped. */
export function resolveBaseUrl(value?: string): string {
  const v = typeof value === "string" ? value.trim() : "";
  const base = v ? v : DEFAULT_BASE_URL;
  return base.replace(/\/+$/, "");
}

function requireNonEmpty(value: unknown, field: string): string {
  const v = typeof value === "string" ? value.trim() : "";
  if (!v) throw new Error(`${field} must be a non-empty string`);
  return v;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function callApi(
  fetchFn: FetchFn,
  baseUrl: string,
  path: string,
  query?: Record<string, string>,
): Promise<unknown> {
  let url = `${resolveBaseUrl(baseUrl)}${path}`;
  if (query) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) params.set(k, v);
    const qs = params.toString();
    if (qs) url += `?${qs}`;
  }
  let response;
  try {
    response = await fetchFn(url, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
  } catch (err) {
    throw new Error(
      `intodns.ai API request failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!response.ok) {
    let detail = "";
    try {
      const payload: unknown = await response.json();
      if (isRecord(payload)) {
        if (typeof payload.message === "string" && payload.message) {
          detail = `: ${payload.message}`;
        } else if (typeof payload.error === "string" && payload.error) {
          detail = `: ${payload.error}`;
        }
      }
    } catch {
      // A non-JSON error body still reports its HTTP status below.
    }
    throw new Error(
      `intodns.ai API request failed: HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}${detail}`,
    );
  }
  try {
    return await response.json();
  } catch {
    throw new Error("intodns.ai API returned a response that was not valid JSON");
  }
}

/** Shared helper for the domain-addressed GET endpoints (documented reconstructions). */
async function domainCall(
  fetchFn: FetchFn,
  baseUrl: string | undefined,
  segment: string,
  options: DomainOptions,
): Promise<unknown> {
  const domain = requireNonEmpty(options.domain, "domain");
  return callApi(fetchFn, resolveBaseUrl(baseUrl), `/api/${segment}/${encodeURIComponent(domain)}`);
}

// ---------------------------------------------------------------------------
// Upstream tools
// ---------------------------------------------------------------------------

/** Fast full scan of a domain: grade, score, DNS/email/security results. */
export function scanDomain(fetchFn: FetchFn, baseUrl: string | undefined, options: DomainOptions): Promise<unknown> {
  return domainCall(fetchFn, baseUrl, "scan", options);
}

/** Look up DNS records for a domain, optionally narrowed to one record type. */
export async function lookupDns(fetchFn: FetchFn, baseUrl: string | undefined, options: LookupDnsOptions): Promise<unknown> {
  const domain = requireNonEmpty(options.domain, "domain");
  const type = typeof options.type === "string" ? options.type.trim() : "";
  return callApi(
    fetchFn,
    resolveBaseUrl(baseUrl),
    `/api/dns/${encodeURIComponent(domain)}`,
    type ? { type } : undefined,
  );
}

/** Validate the DNSSEC chain, DS/DNSKEY records, and algorithms. */
export function validateDnssec(fetchFn: FetchFn, baseUrl: string | undefined, options: DomainOptions): Promise<unknown> {
  return domainCall(fetchFn, baseUrl, "dnssec", options);
}

/** Check DNS propagation across global resolvers. */
export function checkDnsPropagation(fetchFn: FetchFn, baseUrl: string | undefined, options: DomainOptions): Promise<unknown> {
  return domainCall(fetchFn, baseUrl, "propagation", options);
}

/** WHOIS/RDAP lookup for a domain or IP address. */
export async function whoisLookup(fetchFn: FetchFn, baseUrl: string | undefined, options: WhoisOptions): Promise<unknown> {
  const query = requireNonEmpty(options.query, "query");
  return callApi(fetchFn, resolveBaseUrl(baseUrl), `/api/whois/${encodeURIComponent(query)}`);
}

/** Parse and validate a domain's SPF record, including its lookup graph. */
export function checkSpf(fetchFn: FetchFn, baseUrl: string | undefined, options: DomainOptions): Promise<unknown> {
  return domainCall(fetchFn, baseUrl, "spf", options);
}

/** Flatten a domain's SPF graph to literal ip4/ip6 mechanisms. */
export async function flattenSpf(fetchFn: FetchFn, baseUrl: string | undefined, options: DomainOptions): Promise<unknown> {
  const domain = requireNonEmpty(options.domain, "domain");
  return callApi(fetchFn, resolveBaseUrl(baseUrl), `/api/spf/${encodeURIComponent(domain)}/flatten`);
}

/** Discover DKIM selectors for a domain. */
export function discoverDkim(fetchFn: FetchFn, baseUrl: string | undefined, options: DomainOptions): Promise<unknown> {
  return domainCall(fetchFn, baseUrl, "dkim", options);
}

/** Parse and validate a domain's DMARC record and policy. */
export function checkDmarc(fetchFn: FetchFn, baseUrl: string | undefined, options: DomainOptions): Promise<unknown> {
  return domainCall(fetchFn, baseUrl, "dmarc", options);
}

/** Check BIMI DNS, hosted logo, and VMC/CMC readiness. */
export function checkBimi(fetchFn: FetchFn, baseUrl: string | undefined, options: DomainOptions): Promise<unknown> {
  return domainCall(fetchFn, baseUrl, "bimi", options);
}

/** Validate MTA-STS DNS and the hosted policy file. */
export function checkMtaSts(fetchFn: FetchFn, baseUrl: string | undefined, options: DomainOptions): Promise<unknown> {
  return domainCall(fetchFn, baseUrl, "mta-sts", options);
}

/** Check a domain's mail servers (or a direct IP) against DNS blacklists. */
export function checkBlacklist(fetchFn: FetchFn, baseUrl: string | undefined, options: DomainOptions): Promise<unknown> {
  return domainCall(fetchFn, baseUrl, "blacklist", options);
}

/** Full email-security check: SPF, DKIM, DMARC, blacklist, score, and issues. */
export function checkEmailSecurity(fetchFn: FetchFn, baseUrl: string | undefined, options: DomainOptions): Promise<unknown> {
  return domainCall(fetchFn, baseUrl, "email-security", options);
}

/** Scan a live site's HTTP security headers and report present/missing ones. */
export async function analyzeSecurityHeaders(fetchFn: FetchFn, baseUrl: string | undefined, options: AnalyzeSecurityHeadersOptions): Promise<unknown> {
  const url = requireNonEmpty(options.url, "url");
  return callApi(fetchFn, resolveBaseUrl(baseUrl), "/api/security-headers", { url });
}

/** API, cache, and runtime health of the intodns.ai service. */
export function getHealth(fetchFn: FetchFn, baseUrl?: string): Promise<unknown> {
  return callApi(fetchFn, resolveBaseUrl(baseUrl), "/api/health");
}

/** Public scan and check counters for the intodns.ai service. */
export function getStats(fetchFn: FetchFn, baseUrl?: string): Promise<unknown> {
  return callApi(fetchFn, resolveBaseUrl(baseUrl), "/api/stats");
}

// ---------------------------------------------------------------------------
// Local-only tools (no upstream call)
// ---------------------------------------------------------------------------

function xmlTag(block: string, tag: string): string | undefined {
  const m = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`).exec(block);
  const v = m ? m[1].trim() : "";
  return v ? v : undefined;
}

function xmlBlocks(xml: string, tag: string): string[] {
  const re = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, "g");
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) out.push(m[1]);
  return out;
}

function toInt(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : undefined;
}

/**
 * Parse a DMARC aggregate (RUA) XML report locally into structured
 * metadata, the published policy, and per-record results. This is a
 * small purpose-built extractor for the standard RFC 7489 report
 * shape, not a general XML parser.
 */
export function parseDmarcReport(options: ParseDmarcReportOptions): DmarcReport {
  const xml = requireNonEmpty(options.xml, "xml");
  if (!/<feedback[\s>]/.test(xml)) {
    throw new Error("xml does not look like a DMARC aggregate report (no <feedback> root)");
  }
  const metadata = xmlBlocks(xml, "report_metadata")[0] ?? "";
  const policyBlock = xmlBlocks(xml, "policy_published")[0] ?? "";
  const begin = toInt(xmlTag(xmlBlocks(xml, "date_range")[0] ?? "", "begin"));
  const end = toInt(xmlTag(xmlBlocks(xml, "date_range")[0] ?? "", "end"));

  const records: DmarcRecord[] = xmlBlocks(xml, "record").map((rec) => {
    const row = xmlBlocks(rec, "row")[0] ?? "";
    const identifiers = xmlBlocks(rec, "identifiers")[0] ?? "";
    const auth = xmlBlocks(rec, "auth_results")[0] ?? "";
    const authResults: DmarcRecord["auth_results"] = [];
    for (const block of xmlBlocks(auth, "dkim")) {
      authResults.push({ type: "dkim", domain: xmlTag(block, "domain"), result: xmlTag(block, "result") });
    }
    for (const block of xmlBlocks(auth, "spf")) {
      authResults.push({ type: "spf", domain: xmlTag(block, "domain"), result: xmlTag(block, "result") });
    }
    const policyEval = xmlBlocks(row, "policy_evaluated")[0] ?? "";
    const record: DmarcRecord = {
      source_ip: xmlTag(row, "source_ip"),
      count: toInt(xmlTag(row, "count")),
      disposition: xmlTag(policyEval, "disposition"),
      dkim: xmlTag(policyEval, "dkim"),
      spf: xmlTag(policyEval, "spf"),
      header_from: xmlTag(identifiers, "header_from"),
      auth_results: authResults,
    };
    return record;
  });

  const report: DmarcReport = {
    org_name: xmlTag(metadata, "org_name"),
    report_id: xmlTag(metadata, "report_id"),
    policy: {
      domain: xmlTag(policyBlock, "domain"),
      adkim: xmlTag(policyBlock, "adkim"),
      aspf: xmlTag(policyBlock, "aspf"),
      p: xmlTag(policyBlock, "p"),
      sp: xmlTag(policyBlock, "sp"),
      pct: toInt(xmlTag(policyBlock, "pct")),
    },
    records,
    total_messages: records.reduce((sum, r) => sum + (r.count ?? 0), 0),
  };
  if (begin !== undefined) report.date_begin = begin;
  if (end !== undefined) report.date_end = end;
  return report;
}

function authVerdict(authResults: string | undefined, mechanism: string): string | undefined {
  if (!authResults) return undefined;
  const m = new RegExp(`${mechanism}=([a-z]+)`, "i").exec(authResults);
  return m ? m[1].toLowerCase() : undefined;
}

/** Analyze a pasted raw MIME email locally: headers, auth verdicts, hops. */
export function analyzeRawEmail(options: AnalyzeRawEmailOptions): RawEmailAnalysis {
  const raw = requireNonEmpty(options.raw, "raw");
  const splitAt = raw.search(/\r?\n\r?\n/);
  const headBlock = splitAt >= 0 ? raw.slice(0, splitAt) : raw;
  const body = splitAt >= 0 ? raw.slice(splitAt).replace(/^\r?\n\r?\n/, "") : "";

  // Unfold continuation lines (a line starting with space/tab continues the last).
  const lines: string[] = [];
  for (const line of headBlock.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && lines.length) {
      lines[lines.length - 1] += ` ${line.trim()}`;
    } else if (line.trim()) {
      lines.push(line);
    }
  }
  const headers: Record<string, string> = {};
  let receivedCount = 0;
  for (const line of lines) {
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (key === "received") receivedCount += 1;
    if (!(key in headers)) headers[key] = value;
  }

  const auth = headers["authentication-results"];
  const analysis: RawEmailAnalysis = {
    headers,
    received_count: receivedCount,
    has_body: body.trim().length > 0,
  };
  if (headers["from"]) analysis.from = headers["from"];
  if (headers["to"]) analysis.to = headers["to"];
  if (headers["subject"]) analysis.subject = headers["subject"];
  if (headers["date"]) analysis.date = headers["date"];
  if (headers["message-id"]) analysis.message_id = headers["message-id"];
  if (headers["return-path"]) analysis.return_path = headers["return-path"];
  if (headers["content-type"]) analysis.content_type = headers["content-type"];
  if (auth) {
    analysis.authentication_results = auth;
    const spf = authVerdict(auth, "spf");
    const dkim = authVerdict(auth, "dkim");
    const dmarc = authVerdict(auth, "dmarc");
    if (spf) analysis.spf_result = spf;
    if (dkim) analysis.dkim_result = dkim;
    if (dmarc) analysis.dmarc_result = dmarc;
  }
  if (analysis.has_body) analysis.body_preview = body.trim().slice(0, 200);
  return analysis;
}

const CSP_RECOMMENDED = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'";
const CSP_STRICT = "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'";
const CSP_REPORT_ONLY = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; report-uri /csp-report";

function renderConfig(headers: Record<string, string>, format: string): string {
  const entries = Object.entries(headers);
  switch (format) {
    case "nginx":
      return entries.map(([k, v]) => `add_header ${k} "${v}" always;`).join("\n");
    case "apache":
      return entries.map(([k, v]) => `Header always set ${k} "${v}"`).join("\n");
    case "caddy":
      return `header {\n${entries.map(([k, v]) => `  ${k} "${v}"`).join("\n")}\n}`;
    case "_headers":
      return `/*\n${entries.map(([k, v]) => `  ${k}: ${v}`).join("\n")}`;
    case "cloudflare":
    case "raw":
    default:
      return entries.map(([k, v]) => `${k}: ${v}`).join("\n");
  }
}

/** Generate a best-practice HTTP security-header set locally from a preset. */
export function generateSecurityHeaders(options: GenerateSecurityHeadersOptions = {}): GeneratedSecurityHeaders {
  const presetRaw = typeof options.preset === "string" ? options.preset.trim() : "";
  const preset = (presetRaw || "recommended") as SecurityHeadersPreset;
  if (!["recommended", "strict", "report-only"].includes(preset)) {
    throw new Error("preset must be one of: recommended, strict, report-only");
  }
  const formatRaw = typeof options.format === "string" ? options.format.trim().toLowerCase() : "";
  const format = formatRaw || "raw";
  if (!["raw", "nginx", "apache", "caddy", "cloudflare", "_headers"].includes(format)) {
    throw new Error("format must be one of: raw, nginx, apache, caddy, cloudflare, _headers");
  }

  const strict = preset === "strict";
  const headers: Record<string, string> = {
    "Strict-Transport-Security": strict
      ? "max-age=63072000; includeSubDomains; preload"
      : "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": strict ? "DENY" : "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
  };
  if (preset === "report-only") {
    headers["Content-Security-Policy-Report-Only"] = CSP_REPORT_ONLY;
  } else {
    headers["Content-Security-Policy"] = strict ? CSP_STRICT : CSP_RECOMMENDED;
  }
  return { preset, format, headers, config: renderConfig(headers, format) };
}

/** Build the direct PDF report URL for a domain: {base}/api/pdf/{domain}. */
export function getPdfReportLink(baseUrl: string | undefined, options: DomainOptions): string {
  const domain = requireNonEmpty(options.domain, "domain");
  return `${resolveBaseUrl(baseUrl)}/api/pdf/${encodeURIComponent(domain)}`;
}

/** Build the direct SVG badge URL for a domain: {base}/api/badge/{domain}. */
export function getBadgeLink(baseUrl: string | undefined, options: DomainOptions): string {
  const domain = requireNonEmpty(options.domain, "domain");
  return `${resolveBaseUrl(baseUrl)}/api/badge/${encodeURIComponent(domain)}`;
}

/** Render a payload as the JSON text block MCP clients show. */
export function formatPayload(payload: unknown): string {
  return typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
}
