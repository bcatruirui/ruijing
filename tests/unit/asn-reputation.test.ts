import { describe, it, expect } from "vitest";
// @ts-expect-error Build helper has no declaration file.
import { parseAsnReputation } from "../../scripts/asn-reputation.mjs";
const header = "asn,organization,ips_observed,abuse_rate_pct,proxy_rate_pct,ffraud_risk_score\n";
describe("ASN sample parser (synthetic fixtures)", () => {
  it("preserves sample counts but discards proprietary risk scores", () => {
    expect(parseAsnReputation(header + "64512,Example,200,95.5,80,99").get(64512)).toEqual({ asn: 64512, observed: 200, abuse: 95.5, proxy: 80 });
  });
  it.each(["64512,Example,0,95,80,99", "64512,Example,200,101,80,99", "64512,Example,200,,80,99", "4294967296,Example,200,90,80,99"])("rejects invalid statistics %s", row => {
    expect(() => parseAsnReputation(header + row)).toThrow();
  });
  it("rejects duplicate ASN rows and changed schemas", () => {
    expect(() => parseAsnReputation(header + "64512,X,200,90,80,99\n64512,Y,210,95,80,99")).toThrow();
    expect(() => parseAsnReputation("other,data\n1,2")).toThrow();
  });
});
