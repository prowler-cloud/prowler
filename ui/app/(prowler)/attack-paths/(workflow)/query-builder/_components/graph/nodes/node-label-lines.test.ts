import { describe, expect, it } from "vitest";

import { getNodeLabelDisplay, getNodeLabelLines } from "./node-label-lines";

describe("getNodeLabelLines", () => {
  it("adds an ellipsis within the max width when wrapped label text exceeds the visible line budget", () => {
    expect(
      getNodeLabelLines("AWSReservedSSO_AdministratorAccess", 16, 2),
    ).toEqual(["AWSReservedSSO_A", "dministratorAcc…"]);
  });

  it("splits long tokens so unbroken identifiers do not overflow node labels", () => {
    expect(getNodeLabelLines("OrganizationAccountAccessRole", 16, 4)).toEqual([
      "OrganizationAcco",
      "untAccessRole",
    ]);
  });

  it("reports whether the visible label was truncated", () => {
    expect(getNodeLabelDisplay("short-name", 16, 4)).toMatchObject({
      isTruncated: false,
      lines: ["short-name"],
    });
    expect(
      getNodeLabelDisplay(
        "arn:aws:iam::998057895221:role/OrganizationAccountAccessRole/integration",
        16,
        4,
      ),
    ).toMatchObject({ isTruncated: true });
  });
});
