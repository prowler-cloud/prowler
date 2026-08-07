import { describe, expect, it } from "vitest";

import {
  NODE_KIND,
  NodeKind,
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
    expect(
      getNodeLabel(ORGANIZATION_TYPE.AZURE, NODE_KIND.MANAGEMENT_GROUP),
    ).toBe("Management Group");
  });

  it("falls back to the organization type's container label when kind is absent", () => {
    // Nodes served before the canonical `kind` attribute exists, or organization
    // rows that have no kind at all.
    expect(getNodeLabel(ORGANIZATION_TYPE.AWS)).toBe("Organizational Unit");
    expect(getNodeLabel(ORGANIZATION_TYPE.GCP)).toBe("Folder");
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

  it("falls back to the container label for a node kind this build predates", () => {
    // `kind` is typed but unvalidated: node rows pass the wire attribute
    // straight through, so a backend-added kind must resolve to the
    // organization's own container label. Returning `undefined` would crash
    // callers that lowercase the result (the deletion dialog). Every kind this
    // build knows now has a label, so the case needs a kind it does not.
    const unknownKind = "compartment" as NodeKind;

    expect(getNodeLabel(ORGANIZATION_TYPE.AWS, unknownKind)).toBe(
      "Organizational Unit",
    );
    expect(getNodeLabel(ORGANIZATION_TYPE.GCP, unknownKind)).toBe("Folder");
    expect(getNodeLabel(ORGANIZATION_TYPE.AZURE, unknownKind)).toBe(
      "Management Group",
    );
    expect(getNodeLabel("oci" as OrganizationType, unknownKind)).toBe("Group");
  });

  it("falls back for wire values that collide with Object.prototype keys", () => {
    // The lookup tables are object literals, so indexing them with an inherited
    // key returns a truthy non-string — a function, or the prototype itself.
    // That defeats a `??` fallback and hands the callers something they then
    // call `.toLowerCase()` on. Every label getter must survive it.
    for (const key of [
      "constructor",
      "toString",
      "valueOf",
      "hasOwnProperty",
      "__proto__",
    ]) {
      expect(getNodeLabel(ORGANIZATION_TYPE.AWS, key as NodeKind)).toBe(
        "Organizational Unit",
      );
      expect(getNodeLabel(key as OrganizationType, "folder" as NodeKind)).toBe(
        "Folder",
      );
      expect(getNodeLabel(key as OrganizationType)).toBe("Group");
      expect(getNameSourceLabel(key as OrganizationType)).toBe(
        "the cloud provider",
      );
      expect(getCandidateNoun(key as OrganizationType)).toEqual({
        singular: "account",
        plural: "accounts",
      });
    }
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
    expect(getCandidateNoun(ORGANIZATION_TYPE.AZURE)).toEqual({
      singular: "subscription",
      plural: "subscriptions",
    });
  });
});

describe("toNodeKind", () => {
  it("narrows canonical kind values", () => {
    expect(toNodeKind("organizational-unit")).toBe(
      NODE_KIND.ORGANIZATIONAL_UNIT,
    );
    expect(toNodeKind("folder")).toBe(NODE_KIND.FOLDER);
    expect(toNodeKind("management-group")).toBe(NODE_KIND.MANAGEMENT_GROUP);
  });

  it("returns undefined for absent or unknown kinds", () => {
    expect(toNodeKind(undefined)).toBeUndefined();
    expect(toNodeKind("")).toBeUndefined();
    expect(toNodeKind("organizational_unit")).toBeUndefined();
    // Azure's kind is kebab-case like the others: the underscore spelling is not it.
    expect(toNodeKind("management_group")).toBeUndefined();
  });
});
