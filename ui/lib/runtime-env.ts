// Reads a runtime env var, with an optional deprecated-name fallback.
//
// Both names are read through a computed key (never a literal `process.env.X`
// member access) so Next.js/Turbopack does NOT inline them at build time. This
// is essential for the legacy `NEXT_PUBLIC_*` names: a literal read would be
// replaced with the build-time snapshot, defeating the runtime fallback. The
// new `UI_*` names are not `NEXT_PUBLIC_`-prefixed, so they are runtime reads
// regardless. Empty/whitespace values are treated as unset so a leftover empty
// `UI_*` still falls through to a configured legacy var.
const clean = (value?: string): string | null =>
  value && value.trim() !== "" ? value : null;

export function readEnv(
  primary: keyof NodeJS.ProcessEnv,
  legacy?: keyof NodeJS.ProcessEnv,
): string | null {
  const env = typeof process === "undefined" ? undefined : process.env;
  if (!env) return null;

  return clean(env[primary]) ?? (legacy ? clean(env[legacy]) : null);
}

// Reads a runtime boolean flag.
export function readBoolEnv(key: keyof NodeJS.ProcessEnv): boolean {
  return (readEnv(key) ?? "").trim() === "true";
}
