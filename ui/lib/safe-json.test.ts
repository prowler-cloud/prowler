import { describe, expect, it } from "vitest";

import { serializeForScript } from "./safe-json";

const LINE_SEPARATOR = String.fromCharCode(0x2028); // U+2028
const PARAGRAPH_SEPARATOR = String.fromCharCode(0x2029); // U+2029

describe("serializeForScript", () => {
  it("neutralizes a </script> breakout so the script tag is not terminated early", () => {
    // Given
    const value = { sentryDsn: "</script><script>alert(1)</script>" };

    // When
    const serialized = serializeForScript(value);

    // Then
    expect(serialized).not.toContain("</script>");
    expect(serialized).not.toContain("<");
    expect(serialized).not.toContain(">");
  });

  it("neutralizes the HTML comment opener <!--", () => {
    // Given
    const value = { sentryDsn: "<!-- not a comment -->" };

    // When
    const serialized = serializeForScript(value);

    // Then
    expect(serialized).not.toContain("<!--");
    expect(serialized).not.toContain("<");
  });

  it("escapes ampersands", () => {
    // When
    const serialized = serializeForScript({ apiBaseUrl: "https://x?a=1&b=2" });

    // Then
    expect(serialized).not.toContain("&");
    expect(serialized).toContain("\\u0026");
  });

  it("escapes U+2028 and U+2029 so output stays safe in an executed-JS context", () => {
    // Given - JSON.stringify leaves these line terminators raw, which would
    // break a JS string literal if the island were ever inlined as executed JS.
    const value = { sentryDsn: `a${LINE_SEPARATOR}b${PARAGRAPH_SEPARATOR}c` };

    // When
    const serialized = serializeForScript(value);

    // Then
    expect(serialized).not.toContain(LINE_SEPARATOR);
    expect(serialized).not.toContain(PARAGRAPH_SEPARATOR);
    expect(serialized).toContain("\\u2028");
    expect(serialized).toContain("\\u2029");
  });

  it("round-trips back to the original value via JSON.parse", () => {
    // Given
    const value = {
      sentryDsn: "</script>",
      apiBaseUrl: "https://api.example.com?a=1&b=2",
      googleTagManagerId: null,
    };

    // When
    const parsed = JSON.parse(serializeForScript(value));

    // Then
    expect(parsed).toEqual(value);
  });

  it("round-trips line terminators back to their original characters", () => {
    // Given
    const value = { sentryDsn: `a${LINE_SEPARATOR}b${PARAGRAPH_SEPARATOR}c` };

    // When
    const parsed = JSON.parse(serializeForScript(value));

    // Then
    expect(parsed).toEqual(value);
  });
});
