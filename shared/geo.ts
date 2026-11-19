/** Accept decimal coordinates only: blanks, hexadecimal and scientific notation
 * are not provider location values. Zero is a legitimate coordinate. */
export function parseCoordinate(value: unknown, axis: "latitude" | "longitude"): number | undefined {
  if (typeof value === "string") {
    if (!/^[+-]?(?:\d+(?:\.\d+)?|\.\d+)$/.test(value)) return;
    value = Number(value);
  }
  if (typeof value !== "number" || !Number.isFinite(value)) return;
  if (Math.abs(value) > (axis === "latitude" ? 90 : 180)) return;
  return value;
}

export function validPostalCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9](?:[A-Za-z0-9 -]{0,30}[A-Za-z0-9])?$/.test(value);
}

export function validTimezone(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 80 || !/^[A-Za-z_+-]+(?:\/[A-Za-z0-9_+-]+)*$/.test(value)) return false;
  try {
    new Intl.DateTimeFormat("en", { timeZone: value });
    return true;
  } catch {
    return false;
  }
}
