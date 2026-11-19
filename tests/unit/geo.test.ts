import { describe, expect, it } from "vitest";
import { parseCoordinate, validPostalCode, validTimezone } from "../../shared/geo";

describe("provider geolocation metadata validation", () => {
  it("accepts valid decimal boundary and zero coordinates", () => {
    expect(parseCoordinate("0", "latitude")).toBe(0);
    expect(parseCoordinate(0, "longitude")).toBe(0);
    expect(parseCoordinate("-90", "latitude")).toBe(-90);
    expect(parseCoordinate("180.0", "longitude")).toBe(180);
    expect(parseCoordinate("33.4161", "latitude")).toBe(33.4161);
    expect(parseCoordinate("-112.009", "longitude")).toBe(-112.009);
  });
  it.each([undefined, null, {}, "", " ", "0x10", "1e2", "12junk", "91", 91, NaN, Infinity])("rejects malformed latitude %j", (value) => {
    expect(parseCoordinate(value, "latitude")).toBeUndefined();
  });
  it("rejects longitude outside its own range", () => {
    expect(parseCoordinate("-180.01", "longitude")).toBeUndefined();
    expect(parseCoordinate(181, "longitude")).toBeUndefined();
  });
  it("preserves legitimate international postcodes and leading zeros", () => {
    expect(validPostalCode("00100")).toBe(true);
    expect(validPostalCode("SW1A 1AA")).toBe(true);
    expect(validPostalCode("85040-1234")).toBe(true);
    expect(validPostalCode("" )).toBe(false);
    expect(validPostalCode(" null ")).toBe(false);
    expect(validPostalCode("123\n456")).toBe(false);
    expect(validPostalCode(85040)).toBe(false);
  });
  it("accepts supported IANA zones and rejects invented values", () => {
    expect(validTimezone("America/Phoenix")).toBe(true);
    expect(validTimezone("Asia/Shanghai")).toBe(true);
    expect(validTimezone("UTC")).toBe(true);
    expect(validTimezone("Etc/GMT+8")).toBe(true);
    expect(validTimezone("America/Imaginary")).toBe(false);
    expect(validTimezone("+08:00")).toBe(false);
    expect(validTimezone(null)).toBe(false);
  });
});
