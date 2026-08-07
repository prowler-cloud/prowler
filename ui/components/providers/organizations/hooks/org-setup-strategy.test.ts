import { describe, expect, it } from "vitest";

import {
  ORG_FLOW_TYPES,
  ORG_SECRET_TYPE,
  ORGANIZATION_TYPE,
  OrgFlowType,
} from "@/types/organizations";

import {
  bindOrgSetupStrategy,
  OrgSetupSubmissionData,
} from "./org-setup-strategy";

/**
 * One submission per onboarding flow, only as filled in as binding a strategy
 * needs. `satisfies Record<OrgFlowType, …>` keeps a new flow from slipping past
 * the table below.
 */
const SETUP_DATA = {
  [ORGANIZATION_TYPE.AWS]: {
    orgType: ORGANIZATION_TYPE.AWS,
    awsOrgId: "o-abc123def4",
    roleArn: "arn:aws:iam::123456789012:role/ProwlerOrgRole",
  },
  [ORGANIZATION_TYPE.AZURE]: {
    orgType: ORGANIZATION_TYPE.AZURE,
    tenantId: "11111111-1111-4111-8111-111111111111",
    clientId: "client-id",
    clientSecret: "client-secret",
  },
  [ORGANIZATION_TYPE.GCP]: {
    orgType: ORGANIZATION_TYPE.GCP,
    gcpOrgId: "123456789012",
    credentialMethod: ORG_SECRET_TYPE.STATIC,
    clientId: "client-id",
    clientSecret: "client-secret",
    refreshToken: "refresh-token",
  },
} as const satisfies Record<OrgFlowType, OrgSetupSubmissionData>;

/**
 * The structure each flow's hierarchy is made of. A tenant has no folders and an
 * organization has no Management Groups, so copy for a code every provider
 * reports has to pick the right one.
 */
const HIERARCHY_WORDING = {
  [ORGANIZATION_TYPE.AWS]: "organizational unit hierarchy",
  [ORGANIZATION_TYPE.AZURE]: "Management Group hierarchy",
  [ORGANIZATION_TYPE.GCP]: "folder hierarchy",
} as const satisfies Record<OrgFlowType, string>;

describe("bindOrgSetupStrategy", () => {
  // `hierarchy_depth_exceeded` is one API code for every provider. The
  // precedence chain (curated → server message → auth failure) is covered by the
  // submission hook's suite; what only an exhaustive per-flow check can catch is
  // one flow being told about another cloud's structure.
  it.each(ORG_FLOW_TYPES)(
    "describes %s's own hierarchy for the shared hierarchy_depth_exceeded code",
    (orgType) => {
      const message = bindOrgSetupStrategy(
        SETUP_DATA[orgType],
      ).discoveryFailureMessage("hierarchy_depth_exceeded");

      expect(message).toContain(HIERARCHY_WORDING[orgType]);

      const otherClouds = ORG_FLOW_TYPES.filter((other) => other !== orgType);
      for (const other of otherClouds) {
        expect(message).not.toContain(HIERARCHY_WORDING[other]);
      }
    },
  );

  it.each(ORG_FLOW_TYPES)(
    "prefers %s's shared-code copy over the server's own message",
    (orgType) => {
      // Curated copy stays ahead of `error_message`: it is the actionable one.
      const message = bindOrgSetupStrategy(
        SETUP_DATA[orgType],
      ).discoveryFailureMessage(
        "hierarchy_depth_exceeded",
        "Hierarchy too deep.",
      );

      expect(message).toContain(HIERARCHY_WORDING[orgType]);
    },
  );

  // The API stores an Azure tenant as `str(UUID(...))` — canonical lowercase —
  // and `filter[external_id]` is an exact lookup, so a tenant typed in uppercase
  // has to reach find-or-create already folded. Unfolded, the second wizard run
  // misses its own organization and then collides on the POST.
  it("folds an uppercase Azure tenant ID to the API's canonical form", () => {
    const bound = bindOrgSetupStrategy({
      ...SETUP_DATA[ORGANIZATION_TYPE.AZURE],
      tenantId: "  AAAAAAAA-1111-4111-8111-BBBBBBBBBBBB  ",
    });

    expect(bound.externalId).toBe("aaaaaaaa-1111-4111-8111-bbbbbbbbbbbb");
  });
});
