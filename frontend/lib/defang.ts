// Turn a URL into plain, non-clickable display text:
// https -> hxxps, http -> hxxp, and dots in the host -> [.]
// Only the host part is changed; paths are left alone.
export function defangUrl(text: string): string {
  const withScheme = text
    .replace(/https:\/\//gi, "hxxps://")
    .replace(/http:\/\//gi, "hxxp://");
  const hostMatch = /^(hxxps?:\/\/[^/]*)/i.exec(withScheme);
  if (hostMatch) {
    return hostMatch[1].replace(/\./g, "[.]") + withScheme.slice(hostMatch[1].length);
  }
  // Bare domain without a scheme (no spaces or slashes): defang all dots.
  if (/^[\w.-]+$/.test(withScheme)) {
    return withScheme.replace(/\./g, "[.]");
  }
  return withScheme;
}
