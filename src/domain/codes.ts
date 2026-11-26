// Typing codes back: recovery codes and pairing codes use Crockford base32, so the input forgives
// what people mix up when they copy from paper (UX 4.2 step 2).

/** Upper case, without spaces and dashes, `O` read as `0`, `I` and `L` read as `1`. */
export function normalizeCode(input: string): string {
  return input
    .toUpperCase()
    .replace(/[\s\-_.]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
}

/** A recovery code as eight groups of four, however it was pasted. */
export function splitGroups(code: string, size = 4): string[] {
  const clean = normalizeCode(code);
  const groups: string[] = [];
  for (let i = 0; i < clean.length; i += size) groups.push(clean.slice(i, i + size));
  return groups;
}

/** Characters spaced out, so a screen reader reads "D 7 K Q" instead of a word. */
export function spellOut(group: string): string {
  return Array.from(group).join(" ");
}

/** A full recovery code: 32 Crockford characters once normalized. */
export function looksLikeRecoveryCode(input: string): boolean {
  return /^[0-9A-HJKMNP-TV-Z]{32}$/.test(normalizeCode(input));
}
