/**
 * dnsprobe types.
 *
 * Inputs for the labelled core subset of the intodns.ai diagnostics
 * surface. Most tools take a single domain; a few take a free-form
 * query, an XML document, a raw email, or a URL instead. HTTP access
 * is described by a minimal response surface so tests can inject a
 * fake fetch and never touch the network.
 */

export interface DomainOptions {
  domain: string;
}

export interface LookupDnsOptions {
  domain: string;
  type?: string;
}

export interface WhoisOptions {
  query: string;
}

export interface ParseDmarcReportOptions {
  xml: string;
}

export interface AnalyzeRawEmailOptions {
  raw: string;
}

export interface AnalyzeSecurityHeadersOptions {
  url: string;
}

export type SecurityHeadersPreset = "recommended" | "strict" | "report-only";

export interface GenerateSecurityHeadersOptions {
  preset?: SecurityHeadersPreset;
  format?: string;
}

export interface DmarcRecord {
  source_ip?: string;
  count?: number;
  disposition?: string;
  dkim?: string;
  spf?: string;
  header_from?: string;
  auth_results: Array<{ type: string; domain?: string; result?: string }>;
}

export interface DmarcReport {
  org_name?: string;
  report_id?: string;
  date_begin?: number;
  date_end?: number;
  policy: {
    domain?: string;
    adkim?: string;
    aspf?: string;
    p?: string;
    sp?: string;
    pct?: number;
  };
  records: DmarcRecord[];
  total_messages: number;
}

export interface RawEmailAnalysis {
  headers: Record<string, string>;
  from?: string;
  to?: string;
  subject?: string;
  date?: string;
  message_id?: string;
  return_path?: string;
  content_type?: string;
  authentication_results?: string;
  spf_result?: string;
  dkim_result?: string;
  dmarc_result?: string;
  received_count: number;
  has_body: boolean;
  body_preview?: string;
}

export interface GeneratedSecurityHeaders {
  preset: SecurityHeadersPreset;
  format: string;
  headers: Record<string, string>;
  config: string;
}

/** Minimal HTTP response surface so tests can inject fixtures. */
export interface HttpResponse {
  ok: boolean;
  status: number;
  statusText?: string;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
  json(): Promise<unknown>;
}

export type FetchFn = (
  url: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    redirect?: string;
  },
) => Promise<HttpResponse>;
