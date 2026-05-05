import { describe, expect, it } from "vitest";

import { ALERT_ERROR_CODES } from "../../_types";
import {
  buildSuccessResult,
  buildUnexpectedError,
  isThrottled,
  mapJsonApiErrorToAction,
} from "../error-mapping";

describe("mapJsonApiErrorToAction", () => {
  it("maps a JSON:API validation error with a known code", () => {
    const error = mapJsonApiErrorToAction(
      400,
      {
        errors: [
          {
            code: "unknown_filter_field",
            detail: "Unknown filter field 'foo'.",
            source: { pointer: "/data/attributes/condition/filter/foo" },
          },
        ],
      },
      null,
    );

    expect(error.code).toBe(ALERT_ERROR_CODES.UNKNOWN_FILTER_FIELD);
    expect(error.detail).toBe("Unknown filter field 'foo'.");
    expect(error.source?.pointer).toContain("foo");
    expect(error.status).toBe(400);
  });

  it("falls back to status-based code when API code is unknown", () => {
    const error = mapJsonApiErrorToAction(
      404,
      { errors: [{ detail: "Not found." }] },
      null,
    );
    expect(error.code).toBe(ALERT_ERROR_CODES.NOT_FOUND);
  });

  it("parses Retry-After in seconds for throttled responses", () => {
    const error = mapJsonApiErrorToAction(429, null, "42");
    expect(error.code).toBe(ALERT_ERROR_CODES.THROTTLED);
    expect(error.retryAfterSeconds).toBe(42);
  });

  it("collects seeding warnings from meta", () => {
    const error = mapJsonApiErrorToAction(
      400,
      {
        errors: [{ code: "unknown_operator", detail: "bad op" }],
        meta: { warnings: ["non_portable_date_filter", "garbage_warning"] },
      },
      null,
    );
    expect(error.warnings).toEqual(["non_portable_date_filter"]);
  });

  it("returns UNKNOWN with status fallback for unrecognised 5xx", () => {
    const error = mapJsonApiErrorToAction(500, null, null);
    expect(error.code).toBe(ALERT_ERROR_CODES.UNKNOWN);
    expect(error.status).toBe(500);
  });
});

describe("buildSuccessResult", () => {
  it("returns ok=true with no warnings when meta has none", () => {
    const result = buildSuccessResult({ id: "1" }, null);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data).toEqual({ id: "1" });
      expect(result.warnings).toBeUndefined();
    }
  });

  it("filters meta.warnings to known seeding warnings", () => {
    const result = buildSuccessResult(
      { id: "1" },
      { meta: { warnings: ["pagination_not_supported", "totally_made_up"] } },
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.warnings).toEqual(["pagination_not_supported"]);
    }
  });
});

describe("isThrottled", () => {
  it("identifies a throttled action result", () => {
    const result = {
      ok: false as const,
      error: buildUnexpectedError(),
    };
    expect(isThrottled(result)).toBe(false);

    const throttled = {
      ok: false as const,
      error: { code: ALERT_ERROR_CODES.THROTTLED, detail: "x" },
    };
    expect(isThrottled(throttled)).toBe(true);
  });
});
