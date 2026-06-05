// Escape a value for an inline <script>. JSON.stringify already handles
// U+2028/U+2029, so only <, >, & need neutralizing to block </script>/<!-- breakout.
export function serializeForScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");
}
