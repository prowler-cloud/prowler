import { describe, expect, it } from "vitest";

import { LIGHTHOUSE_V2_PROVIDER_TYPE } from "@/app/(prowler)/lighthouse/_types";

import {
  BEDROCK_AUTH_METHOD,
  buildCredentialPayload,
  buildLighthouseV2ConfigFormSchema,
  EMPTY_FORM_VALUES,
  type LighthouseV2ConfigFormValues,
} from "./config";

const BEDROCK = LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK;
const OPTIONAL = { credentialsOptional: true };

const values = (
  overrides: Partial<LighthouseV2ConfigFormValues>,
): LighthouseV2ConfigFormValues => ({ ...EMPTY_FORM_VALUES, ...overrides });

const errorPaths = (
  hasConfiguration: boolean,
  formValues: LighthouseV2ConfigFormValues,
  capabilities = {},
) => {
  const result = buildLighthouseV2ConfigFormSchema(
    BEDROCK,
    hasConfiguration,
    capabilities,
  ).safeParse(formValues);
  return result.success
    ? []
    : result.error.issues.map((issue) => issue.path.join("."));
};

describe("Bedrock configuration form", () => {
  describe("when the provider requires credentials", () => {
    it("should require both keys and the region for a new configuration", () => {
      // Given / When / Then
      expect(errorPaths(false, values({ awsRegionName: "us-east-1" }))).toEqual(
        ["awsAccessKeyId", "awsSecretAccessKey"],
      );
    });

    it("should still require keys to change only the region", () => {
      // Given / When / Then
      expect(errorPaths(true, values({ awsRegionName: "eu-west-1" }))).toEqual([
        "awsAccessKeyId",
        "awsSecretAccessKey",
      ]);
    });

    it("should send all three fields", () => {
      // Given
      const formValues = values({
        awsAccessKeyId: "AKIA",
        awsSecretAccessKey: "secret",
        awsRegionName: "us-east-1",
      });

      // When / Then
      expect(buildCredentialPayload(BEDROCK, formValues, false)).toEqual({
        aws_access_key_id: "AKIA",
        aws_secret_access_key: "secret",
        aws_region_name: "us-east-1",
      });
    });
  });

  describe("when the installation's own role can be used", () => {
    it("should accept a new configuration with only a region", () => {
      // Given / When / Then
      expect(
        errorPaths(false, values({ awsRegionName: "us-east-1" }), OPTIONAL),
      ).toEqual([]);
    });

    it("should still require the region for a new configuration", () => {
      // Given / When / Then
      expect(errorPaths(false, values({}), OPTIONAL)).toEqual([
        "awsRegionName",
      ]);
    });

    it("should accept a region change on an existing configuration", () => {
      // Given / When / Then
      expect(
        errorPaths(true, values({ awsRegionName: "eu-west-1" }), OPTIONAL),
      ).toEqual([]);
    });

    it("should require keys as a pair when one is given", () => {
      // Given / When / Then
      expect(
        errorPaths(
          false,
          values({ awsAccessKeyId: "AKIA", awsRegionName: "us-east-1" }),
          OPTIONAL,
        ),
      ).toEqual(["awsSecretAccessKey"]);
    });

    it("should send only the region, without empty key strings", () => {
      // Given
      const formValues = values({ awsRegionName: " us-east-1 " });

      // When / Then
      expect(
        buildCredentialPayload(BEDROCK, formValues, false, OPTIONAL),
      ).toEqual({ aws_region_name: "us-east-1" });
      expect(
        buildCredentialPayload(BEDROCK, formValues, true, OPTIONAL),
      ).toEqual({ aws_region_name: "us-east-1" });
    });

    it("should send keys when they are given", () => {
      // Given
      const formValues = values({
        awsAccessKeyId: "AKIA",
        awsSecretAccessKey: "secret",
        awsRegionName: "us-east-1",
      });

      // When / Then
      expect(
        buildCredentialPayload(BEDROCK, formValues, false, OPTIONAL),
      ).toEqual({
        aws_access_key_id: "AKIA",
        aws_secret_access_key: "secret",
        aws_region_name: "us-east-1",
      });
    });

    it("should keep the stored configuration when nothing is entered", () => {
      // Given / When / Then
      expect(
        buildCredentialPayload(BEDROCK, values({}), true, OPTIONAL),
      ).toBeUndefined();
    });
  });

  describe("when authenticating with a Bedrock API key", () => {
    const apiKeyValues = (overrides: Partial<LighthouseV2ConfigFormValues>) =>
      values({ bedrockAuthMethod: BEDROCK_AUTH_METHOD.API_KEY, ...overrides });

    it("should require the API key and the region for a new configuration", () => {
      // Given / When / Then
      expect(errorPaths(false, apiKeyValues({}))).toEqual([
        "apiKey",
        "awsRegionName",
      ]);
    });

    it("should still require the API key where the installation role is allowed", () => {
      // Given / When / Then
      expect(
        errorPaths(
          false,
          apiKeyValues({ awsRegionName: "us-east-1" }),
          OPTIONAL,
        ),
      ).toEqual(["apiKey"]);
    });

    it("should require the region to rotate the key on an existing configuration", () => {
      // Given / When / Then
      expect(
        errorPaths(true, apiKeyValues({ apiKey: "ABSKlongterm" })),
      ).toEqual(["awsRegionName"]);
    });

    it.each(["ABSKlongterm", "bedrock-api-key-shortterm"])(
      "should accept the %s key format",
      (apiKey) => {
        // Given / When / Then
        expect(
          errorPaths(
            false,
            apiKeyValues({ apiKey, awsRegionName: "us-east-1" }),
          ),
        ).toEqual([]);
      },
    );

    it("should reject a key that is not a Bedrock API key", () => {
      // Given / When / Then
      expect(
        errorPaths(
          false,
          apiKeyValues({ apiKey: "sk-proj-123", awsRegionName: "us-east-1" }),
        ),
      ).toEqual(["apiKey"]);
    });

    it("should send the key and region, without leftover access keys", () => {
      // Given: access keys typed before switching to the API key method
      const formValues = apiKeyValues({
        apiKey: " ABSKlongterm ",
        awsAccessKeyId: "AKIA",
        awsSecretAccessKey: "secret",
        awsRegionName: "us-east-1",
      });

      // When / Then
      expect(buildCredentialPayload(BEDROCK, formValues, false)).toEqual({
        api_key: "ABSKlongterm",
        aws_region_name: "us-east-1",
      });
    });

    it("should keep the stored configuration when nothing is entered", () => {
      // Given / When / Then
      expect(errorPaths(true, apiKeyValues({}))).toEqual([]);
      expect(
        buildCredentialPayload(BEDROCK, apiKeyValues({}), true),
      ).toBeUndefined();
    });
  });

  describe("when authenticating with access keys", () => {
    it("should ignore an API key left over from the other method", () => {
      // Given
      const formValues = values({
        apiKey: "ABSKlongterm",
        awsAccessKeyId: "AKIA",
        awsSecretAccessKey: "secret",
        awsRegionName: "us-east-1",
      });

      // When / Then
      expect(buildCredentialPayload(BEDROCK, formValues, false)).toEqual({
        aws_access_key_id: "AKIA",
        aws_secret_access_key: "secret",
        aws_region_name: "us-east-1",
      });
    });
  });
});
