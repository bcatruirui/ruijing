import { flagCodes } from "../lib/flag-codes";
import { assetPath } from "../lib/api.ts";

export function CountryFlag({ code, name }: { code?: string; name?: string }) {
  if (!code || !flagCodes.has(code)) return null;
  return <span className="country-flag"><img src={assetPath(`assets/flag-${code.toLowerCase()}.svg`)} width="32" height="24" alt="" /><span>{name || code}<small>{code}</small></span></span>;
}
