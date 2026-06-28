import { describe, expect, it } from "vitest";

import { getScanErrorDetails } from "./task.adapter";

describe("getScanErrorDetails", () => {
  it("returns null when response is not a record", () => {
    expect(getScanErrorDetails(null)).toBeNull();
    expect(getScanErrorDetails("oops")).toBeNull();
    expect(getScanErrorDetails(undefined)).toBeNull();
  });

  it("returns null when data is missing", () => {
    expect(getScanErrorDetails({})).toBeNull();
  });

  it("returns null when attributes.result is missing", () => {
    expect(getScanErrorDetails({ data: { attributes: {} } })).toBeNull();
  });

  it("returns null when result has no recognizable fields", () => {
    expect(
      getScanErrorDetails({ data: { attributes: { result: {} } } }),
    ).toBeNull();
  });

  it("parses an error with only an exc_type", () => {
    const details = getScanErrorDetails({
      data: { attributes: { result: { exc_type: "BotoCoreError" } } },
    });

    expect(details).toEqual({
      type: "BotoCoreError",
      messages: ["-"],
      module: undefined,
      copyValue: "ErrorType: BotoCoreError\nError: -",
    });
  });

  it("joins multiple exc_message entries in copyValue", () => {
    const details = getScanErrorDetails({
      data: {
        attributes: {
          result: {
            exc_type: "ScanError",
            exc_message: ["Failed to connect", "Retry exhausted"],
            exc_module: "scan.runner",
          },
        },
      },
    });

    expect(details).toEqual({
      type: "ScanError",
      messages: ["Failed to connect", "Retry exhausted"],
      module: "scan.runner",
      copyValue:
        "ErrorType: ScanError\nError: Failed to connect\nRetry exhausted",
    });
  });

  it("filters non-string entries out of exc_message", () => {
    const details = getScanErrorDetails({
      data: {
        attributes: {
          result: {
            exc_type: "ScanError",
            exc_message: ["valid", 42, null, "  ", " trimmed "],
          },
        },
      },
    });

    expect(details?.messages).toEqual(["valid", "trimmed"]);
  });

  it("returns null when only whitespace fields are present", () => {
    const details = getScanErrorDetails({
      data: {
        attributes: {
          result: {
            exc_type: "   ",
            exc_message: [""],
            exc_module: "",
          },
        },
      },
    });

    expect(details).toBeNull();
  });
});
