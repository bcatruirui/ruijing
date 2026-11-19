import { describe, expect, it } from "vitest";
// Builder runs as native Node ESM; this parser is shared with real stream ingestion.
// @ts-ignore Native ESM build utility intentionally does not require a declaration file.
import { parseDbipCityLine } from "../../scripts/data-utils.mjs";

describe("DB-IP reviewed CSV schema regression", () => {
  it("keeps continent separate from country, state and city", () => {
    const row = parseDbipCityLine(
      "8.8.8.0,8.8.8.255,NA,US,California,Mountain View,37.386,-122.0838",
    );
    expect(row.payload).toMatchObject({
      countryCode: "US",
      region: "California",
      city: "Mountain View",
      latitude: 37.386,
      longitude: -122.0838,
    });
    expect(row.payload.countryCode).not.toBe("NA");
    expect(row.payload.postalCode).toBeUndefined();
    expect(row.payload.timezone).toBeUndefined();
  });
  it("supports the actual IPv6 schema and quoted city fields", () => {
    const row = parseDbipCityLine(
      '2001:db8::,2001:db8::ffff,NA,US,District of Columbia,"Washington, D.C.",38.9,-77.03',
    );
    expect(row.family).toBe(6);
    expect(row.payload.city).toBe("Washington, D.C.");
    expect(row.payload.latitude).toBe(38.9);
    expect(row.payload.longitude).toBe(-77.03);
  });
  it("refuses five-column, reordered and invalid-coordinate input", () => {
    expect(() =>
      parseDbipCityLine("1.1.1.0,1.1.1.255,AU,New South Wales,Sydney"),
    ).toThrow(/8-column/);
    expect(() =>
      parseDbipCityLine(
        "1.1.1.0,1.1.1.255,AU,OC,New South Wales,Sydney,-33,151",
      ),
    ).toThrow(/continent/);
    expect(() =>
      parseDbipCityLine(
        "1.1.1.0,1.1.1.255,OC,AU,New South Wales,Sydney,-133,151",
      ),
    ).toThrow(/coordinates/);
  });
  it("preserves valid zero coordinates without manufacturing extra location fields", () => {
    const row = parseDbipCityLine("8.8.8.0,8.8.8.255,AF,GH,,Accra,0,0");
    expect(row.payload.latitude).toBe(0);
    expect(row.payload.longitude).toBe(0);
    expect(row.payload.postalCode).toBeUndefined();
    expect(row.payload.timezone).toBeUndefined();
  });
  it.each([" ", "0x10", "1e1", "NaN", "Infinity", "91"])("rejects malformed latitude %j", (latitude) => {
    expect(() => parseDbipCityLine(`8.8.8.0,8.8.8.255,NA,US,California,Mountain View,${latitude},-122.08`)).toThrow(/coordinates/);
  });
});
