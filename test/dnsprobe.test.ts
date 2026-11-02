import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
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
  whoisLookup,
} from "../src/dnsprobe.js";
import type { FetchFn, HttpResponse } from "../src/types.js";

function jsonResponse(body: unknown, status = 200, statusText = "OK"): HttpResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText,
    headers: { get: () => "application/json" },
    text: async () => JSON.stringify(body),
    json: async () => body,
  };
}

interface Captured { url?: string; method?: string }

function fakeFetch(captured: Captured, body: unknown = { ok: true }): FetchFn {
  return async (url: string, init?: { method?: string }) => {
    captured.url = url;
    captured.method = init?.method;
    return jsonResponse(body);
  };
}

const BASE = "https://intodns.ai";
const noFetch: FetchFn = async () => { throw new Error("must not be called"); };

describe("base URL resolution", () => {
  it("defaults to https://intodns.ai and strips trailing slashes", () => {
    assert.equal(resolveBaseUrl(undefined), BASE);
    assert.equal(resolveBaseUrl("  "), BASE);
    assert.equal(resolveBaseUrl("http://localhost:3000/"), "http://localhost:3000");
  });
});

describe("upstream domain tools", () => {
  const cases: Array<[string, (f: FetchFn) => Promise<unknown>, string]> = [
    ["scan_domain", (f) => scanDomain(f, BASE, { domain: "example.com" }), "/api/scan/example.com"],
    ["validate_dnssec", (f) => validateDnssec(f, BASE, { domain: "example.com" }), "/api/dnssec/example.com"],
    ["check_dns_propagation", (f) => checkDnsPropagation(f, BASE, { domain: "example.com" }), "/api/propagation/example.com"],
    ["check_spf", (f) => checkSpf(f, BASE, { domain: "example.com" }), "/api/spf/example.com"],
    ["flatten_spf", (f) => flattenSpf(f, BASE, { domain: "example.com" }), "/api/spf/example.com/flatten"],
    ["discover_dkim", (f) => discoverDkim(f, BASE, { domain: "example.com" }), "/api/dkim/example.com"],
    ["check_dmarc", (f) => checkDmarc(f, BASE, { domain: "example.com" }), "/api/dmarc/example.com"],
    ["check_bimi", (f) => checkBimi(f, BASE, { domain: "example.com" }), "/api/bimi/example.com"],
    ["check_mta_sts", (f) => checkMtaSts(f, BASE, { domain: "example.com" }), "/api/mta-sts/example.com"],
    ["check_blacklist", (f) => checkBlacklist(f, BASE, { domain: "example.com" }), "/api/blacklist/example.com"],
    ["check_email_security", (f) => checkEmailSecurity(f, BASE, { domain: "example.com" }), "/api/email-security/example.com"],
  ];
  for (const [name, run, path] of cases) {
    it(`${name} GETs ${path}`, async () => {
      const c: Captured = {};
      const out = (await run(fakeFetch(c, { tool: name }))) as Record<string, unknown>;
      assert.equal(out.tool, name);
      assert.equal(c.url, `${BASE}${path}`);
      assert.equal(c.method, "GET");
    });
  }

  it("lookup_dns without a type has no query string", async () => {
    const c: Captured = {};
    await lookupDns(fakeFetch(c), BASE, { domain: "example.com" });
    assert.equal(c.url, `${BASE}/api/dns/example.com`);
  });

  it("lookup_dns composes the record type query param", async () => {
    const c: Captured = {};
    await lookupDns(fakeFetch(c), BASE, { domain: "example.com", type: "MX" });
    const url = new URL(c.url ?? "");
    assert.equal(url.pathname, "/api/dns/example.com");
    assert.equal(url.searchParams.get("type"), "MX");
  });

  it("whois_lookup addresses the query, URL-encoded", async () => {
    const c: Captured = {};
    await whoisLookup(fakeFetch(c), BASE, { query: "8.8.8.8" });
    assert.equal(c.url, `${BASE}/api/whois/8.8.8.8`);
  });

  it("analyze_security_headers passes the target url as a query param", async () => {
    const c: Captured = {};
    await analyzeSecurityHeaders(fakeFetch(c), BASE, { url: "https://example.com/login" });
    const url = new URL(c.url ?? "");
    assert.equal(url.pathname, "/api/security-headers");
    assert.equal(url.searchParams.get("url"), "https://example.com/login");
  });

  it("get_health and get_stats hit their endpoints on the default base", async () => {
    const c1: Captured = {};
    await getHealth(fakeFetch(c1), undefined);
    assert.equal(c1.url, `${BASE}/api/health`);
    const c2: Captured = {};
    await getStats(fakeFetch(c2), undefined);
    assert.equal(c2.url, `${BASE}/api/stats`);
  });

  it("an empty domain is rejected before any request", async () => {
    let called = false;
    const spy: FetchFn = async () => { called = true; return jsonResponse({}); };
    await assert.rejects(() => scanDomain(spy, BASE, { domain: "  " }), /domain/);
    assert.equal(called, false);
  });
});

describe("parse_dmarc_report (local)", () => {
  const xml = `<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <report_id>123456789</report_id>
    <date_range><begin>1728000000</begin><end>1728086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><adkim>r</adkim><aspf>r</aspf>
    <p>reject</p><sp>reject</sp><pct>100</pct>
  </policy_published>
  <record>
    <row><source_ip>1.2.3.4</source_ip><count>7</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row><source_ip>5.6.7.8</source_ip><count>3</count>
      <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <spf><domain>other.test</domain><result>fail</result></spf>
    </auth_results>
  </record>
</feedback>`;

  it("parses metadata, policy, records, and totals with no fetch", async () => {
    void noFetch;
    const out = parseDmarcReport({ xml });
    assert.equal(out.org_name, "google.com");
    assert.equal(out.report_id, "123456789");
    assert.equal(out.date_begin, 1728000000);
    assert.equal(out.date_end, 1728086400);
    assert.equal(out.policy.domain, "example.com");
    assert.equal(out.policy.p, "reject");
    assert.equal(out.policy.pct, 100);
    assert.equal(out.records.length, 2);
    assert.equal(out.records[0].source_ip, "1.2.3.4");
    assert.equal(out.records[0].count, 7);
    assert.equal(out.records[0].disposition, "none");
    assert.deepEqual(out.records[0].auth_results, [
      { type: "dkim", domain: "example.com", result: "pass" },
      { type: "spf", domain: "example.com", result: "pass" },
    ]);
    assert.equal(out.records[1].auth_results.length, 1);
    assert.equal(out.total_messages, 10);
  });

  it("rejects input without a <feedback> root and empty input", () => {
    assert.throws(() => parseDmarcReport({ xml: "<html></html>" }), /DMARC aggregate/);
    assert.throws(() => parseDmarcReport({ xml: " " }), /xml/);
  });
});

describe("analyze_raw_email (local)", () => {
  const raw = [
    "Return-Path: <bounce@sender.test>",
    "Received: from mail.sender.test by mx.example.com",
    "Received: from laptop by mail.sender.test",
    "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=sender.test; dkim=pass header.d=sender.test; dmarc=pass header.from=sender.test",
    "From: Sender <a@sender.test>",
    "To: b@example.com",
    "Subject: A folded",
    " subject line",
    "Date: Mon, 26 Oct 2026 10:00:00 -0700",
    "Message-ID: <abc123@sender.test>",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Hello there, this is the body.",
  ].join("\r\n");

  it("parses headers, unfolds continuations, and extracts auth verdicts", () => {
    const out = analyzeRawEmail({ raw });
    assert.equal(out.from, "Sender <a@sender.test>");
    assert.equal(out.to, "b@example.com");
    assert.equal(out.subject, "A folded subject line");
    assert.equal(out.message_id, "<abc123@sender.test>");
    assert.equal(out.return_path, "<bounce@sender.test>");
    assert.equal(out.spf_result, "pass");
    assert.equal(out.dkim_result, "pass");
    assert.equal(out.dmarc_result, "pass");
    assert.equal(out.received_count, 2);
    assert.equal(out.has_body, true);
    assert.match(out.body_preview ?? "", /Hello there/);
  });

  it("handles a header-only message and rejects empty input", () => {
    const out = analyzeRawEmail({ raw: "From: a@x.test\r\nSubject: Hi" });
    assert.equal(out.has_body, false);
    assert.equal(out.received_count, 0);
    assert.throws(() => analyzeRawEmail({ raw: "" }), /raw/);
  });
});

describe("generate_security_headers (local)", () => {
  it("defaults to the recommended preset in raw format", () => {
    const out = generateSecurityHeaders({});
    assert.equal(out.preset, "recommended");
    assert.equal(out.format, "raw");
    assert.equal(out.headers["X-Content-Type-Options"], "nosniff");
    assert.equal(out.headers["X-Frame-Options"], "SAMEORIGIN");
    assert.match(out.headers["Content-Security-Policy"], /default-src 'self'/);
    assert.match(out.config, /Strict-Transport-Security: max-age=31536000/);
  });

  it("strict preset denies framing and preloads HSTS", () => {
    const out = generateSecurityHeaders({ preset: "strict" });
    assert.equal(out.headers["X-Frame-Options"], "DENY");
    assert.match(out.headers["Strict-Transport-Security"], /preload/);
    assert.match(out.headers["Content-Security-Policy"], /default-src 'none'/);
  });

  it("report-only preset uses the Report-Only CSP header", () => {
    const out = generateSecurityHeaders({ preset: "report-only" });
    assert.ok(out.headers["Content-Security-Policy-Report-Only"]);
    assert.equal(out.headers["Content-Security-Policy"], undefined);
  });

  it("nginx format renders add_header lines", () => {
    const out = generateSecurityHeaders({ format: "nginx" });
    assert.match(out.config, /add_header X-Content-Type-Options "nosniff" always;/);
  });

  it("rejects an unknown preset or format", () => {
    assert.throws(() => generateSecurityHeaders({ preset: "wild" as never }), /preset/);
    assert.throws(() => generateSecurityHeaders({ format: "iis" }), /format/);
  });
});

describe("link builders (local)", () => {
  it("builds pdf and badge URLs on the default and custom bases", () => {
    assert.equal(getPdfReportLink(undefined, { domain: "example.com" }), `${BASE}/api/pdf/example.com`);
    assert.equal(getBadgeLink(undefined, { domain: "example.com" }), `${BASE}/api/badge/example.com`);
    assert.equal(getPdfReportLink("http://localhost:3000/", { domain: "a.test" }), "http://localhost:3000/api/pdf/a.test");
  });

  it("rejects an empty domain", () => {
    assert.throws(() => getBadgeLink(undefined, { domain: "" }), /domain/);
  });
});

describe("errors", () => {
  it("HTTP 404 surfaces status and upstream message", async () => {
    const failing: FetchFn = async () => jsonResponse({ message: "not found" }, 404, "Not Found");
    await assert.rejects(() => getHealth(failing, BASE), /HTTP 404.*not found/);
  });

  it("network failure is wrapped with context", async () => {
    const failing: FetchFn = async () => { throw new Error("socket hang up"); };
    await assert.rejects(() => getStats(failing, BASE), /intodns\.ai API request failed: socket hang up/);
  });
});
