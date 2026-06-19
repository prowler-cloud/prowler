// Escape a value for an inline <script>. Neutralizes < > & to block the
// </script>/<!-- breakout (the only vector when read as inert JSON), plus the
// U+2028/U+2029 line terminators that JSON.stringify leaves raw, so the output
// is also safe if ever inlined into an executed-JS context. JSON.parse decodes
// all of these back to the original characters.
const LINE_SEPARATOR = new RegExp(String.fromCharCode(0x2028), "g");
const PARAGRAPH_SEPARATOR = new RegExp(String.fromCharCode(0x2029), "g");

export function serializeForScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(LINE_SEPARATOR, "\\u2028")
    .replace(PARAGRAPH_SEPARATOR, "\\u2029");
}
