import { describe, expect, it } from "vitest";

import { serializeForScript } from "./safe-json";

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
});
