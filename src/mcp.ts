/**
 * dnsprobe MCP server: the 21-tool labelled core subset.
 *
 * Why the low-level Server instead of McpServer: the high-level
 * helper converts zod schemas to JSON Schema and injects keys that
 * are not in this tool's public spec ("$schema" and
 * "additionalProperties"), which breaks exact tool-list/schema
 * parity with the spec. This file serves tools/list with the spec's
 * exact input schemas as explicit literals, while zod still
 * validates every tools/call argument set.
 *
 * Keyless. The site base URL is read from DNSPROBE_SITE_URL at call
 * time and defaults to https://intodns.ai.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
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
import type { FetchFn } from "./types.js";

const NoArgs = z.object({});
const DomainArgs = z.object({ domain: z.string() });
const LookupDnsArgs = z.object({ domain: z.string(), type: z.string().optional() });
const WhoisArgs = z.object({ query: z.string() });
const ParseDmarcArgs = z.object({ xml: z.string() });
const AnalyzeRawEmailArgs = z.object({ raw: z.string() });
const AnalyzeSecurityHeadersArgs = z.object({ url: z.string() });
const GenerateSecurityHeadersArgs = z.object({
  preset: z.enum(["recommended", "strict", "report-only"]).optional(),
  format: z.string().optional(),
});

const domainSchema = {
  type: "object" as const,
  properties: { domain: { type: "string", description: "Domain name this tool operates on." } },
  required: ["domain"],
};

const TOOLS = [
  { name: "scan_domain", description: "Fast scan of a domain with grade, score, DNS/email/security results, issues, and recommendations.", inputSchema: domainSchema },
  {
    name: "lookup_dns",
    description: "Look up DNS records for a domain (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, PTR, DNSKEY, DS and more), optionally for one record type.",
    inputSchema: { type: "object" as const, properties: { domain: { type: "string", description: "Domain name to look up DNS records for." }, type: { type: "string", description: "Single record type to return, such as A, MX, or TXT; omit to return all types." } }, required: ["domain"] },
  },
  { name: "validate_dnssec", description: "Validate the DNSSEC chain, DS/DNSKEY records, and signing algorithms for a domain.", inputSchema: domainSchema },
  { name: "check_dns_propagation", description: "Check DNS propagation for a domain across global resolvers.", inputSchema: domainSchema },
  {
    name: "whois_lookup",
    description: "WHOIS/RDAP lookup for a domain or IP: registrar, status, nameservers, dates, and abuse contact.",
    inputSchema: { type: "object" as const, properties: { query: { type: "string", description: "Domain name or IP address to look up." } }, required: ["query"] },
  },
  { name: "check_spf", description: "Parse and validate a domain's SPF record, including its recursive lookup graph.", inputSchema: domainSchema },
  { name: "flatten_spf", description: "Flatten a domain's SPF include/a/mx graph to literal ip4/ip6 addresses under the 10-lookup limit.", inputSchema: domainSchema },
  { name: "discover_dkim", description: "Discover DKIM selectors for a domain.", inputSchema: domainSchema },
  { name: "check_dmarc", description: "Parse and validate a domain's DMARC record and policy.", inputSchema: domainSchema },
  {
    name: "parse_dmarc_report",
    description: "Parse a DMARC aggregate (RUA) XML report locally into structured sources, counts, and SPF/DKIM/DMARC results.",
    inputSchema: { type: "object" as const, properties: { xml: { type: "string", description: "DMARC aggregate (RUA) report XML content to parse." } }, required: ["xml"] },
  },
  { name: "check_bimi", description: "Check BIMI DNS, the hosted SVG/logo URL, and VMC/CMC readiness for a domain.", inputSchema: domainSchema },
  { name: "check_mta_sts", description: "Validate MTA-STS DNS and the hosted policy file for a domain.", inputSchema: domainSchema },
  { name: "check_blacklist", description: "Check a domain's mail servers, or a direct IP, against DNS blacklists.", inputSchema: domainSchema },
  { name: "check_email_security", description: "Full email-security check for a domain: SPF, DKIM, DMARC, blacklist, score, and issues.", inputSchema: domainSchema },
  {
    name: "analyze_raw_email",
    description: "Analyze a pasted raw MIME email source locally: headers, authentication verdicts, and hops.",
    inputSchema: { type: "object" as const, properties: { raw: { type: "string", description: "Raw MIME email source to analyze." } }, required: ["raw"] },
  },
  {
    name: "analyze_security_headers",
    description: "Scan a live site's HTTP security headers and report which are present or missing.",
    inputSchema: { type: "object" as const, properties: { url: { type: "string", description: "URL of the live site whose HTTP response headers to scan." } }, required: ["url"] },
  },
  {
    name: "generate_security_headers",
    description: "Generate a best-practice HTTP security-header set locally from a recommended, strict, or report-only preset.",
    inputSchema: {
      type: "object" as const,
      properties: {
        preset: { type: "string", enum: ["recommended", "strict", "report-only"], description: "Header preset to generate: recommended, strict, or report-only." },
        format: { type: "string", description: "Output format for the generated header set." },
      },
    },
  },
  { name: "get_health", description: "Get the health of the intodns.ai API, cache, and runtime.", inputSchema: { type: "object" as const, properties: {} } },
  { name: "get_stats", description: "Get public scan and check counters for the intodns.ai service.", inputSchema: { type: "object" as const, properties: {} } },
  { name: "get_pdf_report_link", description: "Build the direct PDF report URL for a domain ({base}/api/pdf/{domain}).", inputSchema: domainSchema },
  { name: "get_badge_link", description: "Build the direct SVG badge URL for a domain ({base}/api/badge/{domain}).", inputSchema: domainSchema },
];

function textResult(value: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: typeof value === "string" ? value : JSON.stringify(value, null, 2),
      },
    ],
  };
}

function errorResult(err: unknown) {
  return {
    content: [
      { type: "text" as const, text: err instanceof Error ? err.message : String(err) },
    ],
    isError: true,
  };
}

const server = new Server(
  { name: "dnsprobe", version: VERSION },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const fetchFn = globalThis.fetch as unknown as FetchFn;
  const baseUrl = resolveBaseUrl(process.env[BASE_URL_ENV]);
  try {
    let out: unknown;
    switch (name) {
      case "scan_domain": out = await scanDomain(fetchFn, baseUrl, DomainArgs.parse(args ?? {})); break;
      case "lookup_dns": out = await lookupDns(fetchFn, baseUrl, LookupDnsArgs.parse(args ?? {})); break;
      case "validate_dnssec": out = await validateDnssec(fetchFn, baseUrl, DomainArgs.parse(args ?? {})); break;
      case "check_dns_propagation": out = await checkDnsPropagation(fetchFn, baseUrl, DomainArgs.parse(args ?? {})); break;
      case "whois_lookup": out = await whoisLookup(fetchFn, baseUrl, WhoisArgs.parse(args ?? {})); break;
      case "check_spf": out = await checkSpf(fetchFn, baseUrl, DomainArgs.parse(args ?? {})); break;
      case "flatten_spf": out = await flattenSpf(fetchFn, baseUrl, DomainArgs.parse(args ?? {})); break;
      case "discover_dkim": out = await discoverDkim(fetchFn, baseUrl, DomainArgs.parse(args ?? {})); break;
      case "check_dmarc": out = await checkDmarc(fetchFn, baseUrl, DomainArgs.parse(args ?? {})); break;
      case "parse_dmarc_report": out = parseDmarcReport(ParseDmarcArgs.parse(args ?? {})); break;
      case "check_bimi": out = await checkBimi(fetchFn, baseUrl, DomainArgs.parse(args ?? {})); break;
      case "check_mta_sts": out = await checkMtaSts(fetchFn, baseUrl, DomainArgs.parse(args ?? {})); break;
      case "check_blacklist": out = await checkBlacklist(fetchFn, baseUrl, DomainArgs.parse(args ?? {})); break;
      case "check_email_security": out = await checkEmailSecurity(fetchFn, baseUrl, DomainArgs.parse(args ?? {})); break;
      case "analyze_raw_email": out = analyzeRawEmail(AnalyzeRawEmailArgs.parse(args ?? {})); break;
      case "analyze_security_headers": out = await analyzeSecurityHeaders(fetchFn, baseUrl, AnalyzeSecurityHeadersArgs.parse(args ?? {})); break;
      case "generate_security_headers": out = generateSecurityHeaders(GenerateSecurityHeadersArgs.parse(args ?? {})); break;
      case "get_health": NoArgs.parse(args ?? {}); out = await getHealth(fetchFn, baseUrl); break;
      case "get_stats": NoArgs.parse(args ?? {}); out = await getStats(fetchFn, baseUrl); break;
      case "get_pdf_report_link": out = getPdfReportLink(baseUrl, DomainArgs.parse(args ?? {})); break;
      case "get_badge_link": out = getBadgeLink(baseUrl, DomainArgs.parse(args ?? {})); break;
      default: throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }
    return textResult(formatPayload(out));
  } catch (err) {
    if (err instanceof McpError) throw err;
    return errorResult(err);
  }
});

async function main(): Promise<void> {
  await server.connect(new StdioServerTransport());
}

void main();
