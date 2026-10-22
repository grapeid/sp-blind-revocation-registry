/**
 * The bytes every service-provider request is signed over: the one form set by
 * the Identity Agent's ADR-049, implemented in Go as relayproto.CanonicalBody.
 *
 * Every field (keys included) is a string of printable ASCII; anything else is
 * refused, never signed. The "signature" field is left out. Keys sort by code
 * unit, which for ASCII is byte order. JSON.stringify of such strings escapes
 * only `"` and `\`, writes `/` as it is and adds no whitespace, which is exactly
 * the form.
 */
export function canonicalBody(fields: Record<string, unknown>): string {
  const out: Record<string, string> = {};
  for (const key of Object.keys(fields).sort()) {
    if (key === 'signature') continue;
    const value = fields[key];
    if (!printableASCII(key) || typeof value !== 'string' || !printableASCII(value)) {
      throw new Error(`every signed field is a string of printable ASCII; ${JSON.stringify(key)} is not`);
    }
    out[key] = value;
  }
  return JSON.stringify(out);
}

function printableASCII(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}
