import { describe, expect, it } from "vitest";

import {
  NODE_KIND,
  ORGANIZATION_TYPE,
  OrganizationType,
} from "@/types/organizations";

import {
  getCandidateNoun,
  getNameSourceLabel,
  getNodeLabel,
  toNodeKind,
} from "./organizations";

describe("getNodeLabel", () => {
  it("labels a node by its kind, regardless of organization type", () => {
    expect(
      getNodeLabel(ORGANIZATION_TYPE.AWS, NODE_KIND.ORGANIZATIONAL_UNIT),
    ).toBe("Organizational Unit");
    expect(getNodeLabel(ORGANIZATION_TYPE.GCP, NODE_KIND.FOLDER)).toBe(
      "Folder",
    );
  });

  it("falls back to the organization type's container label when kind is absent", () => {
    // Nodes served before the canonical `kind` attribute exists, or organization
    // rows that have no kind at all.
    expect(getNodeLabel(ORGANIZATION_TYPE.AWS)).toBe("Organizational Unit");
    expect(getNodeLabel(ORGANIZATION_TYPE.GCP)).toBe("Folder");
  });

  it("uses the organization type's own vocabulary for types without an onboarding flow", () => {
    // Display covers every organization type the API can report; an Azure
    // organization must never inherit AWS wording.
    expect(getNodeLabel(ORGANIZATION_TYPE.AZURE)).toBe("Management Group");
  });

  it("falls back to neutral wording for an organization type this build predates", () => {
    // The enum mirrors a server-side one: an unknown value must render neutrally
    // instead of crashing the cell or claiming AWS.
    expect(getNodeLabel("oci" as OrganizationType)).toBe("Group");
    expect(getNameSourceLabel("oci" as OrganizationType)).toBe(
      "the cloud provider",
    );
  });
});

describe("getNameSourceLabel", () => {
  it("names the provider-side source of the organization name", () => {
    expect(getNameSourceLabel(ORGANIZATION_TYPE.AWS)).toBe("AWS");
    expect(getNameSourceLabel(ORGANIZATION_TYPE.GCP)).toBe("Google Cloud");
    expect(getNameSourceLabel(ORGANIZATION_TYPE.AZURE)).toBe("Azure");
  });
});

describe("getCandidateNoun", () => {
  it("names what a discovered candidate is, per organization type", () => {
    expect(getCandidateNoun(ORGANIZATION_TYPE.AWS)).toEqual({
      singular: "account",
      plural: "accounts",
    });
    expect(getCandidateNoun(ORGANIZATION_TYPE.GCP)).toEqual({
      singular: "project",
      plural: "projects",
    });
  });
});

describe("toNodeKind", () => {
  it("narrows canonical kind values", () => {
    expect(toNodeKind("organizational-unit")).toBe(
      NODE_KIND.ORGANIZATIONAL_UNIT,
    );
    expect(toNodeKind("folder")).toBe(NODE_KIND.FOLDER);
  });

  it("returns undefined for absent or unknown kinds", () => {
    expect(toNodeKind(undefined)).toBeUndefined();
    expect(toNodeKind("")).toBeUndefined();
    expect(toNodeKind("organizational_unit")).toBeUndefined();
  });
});
