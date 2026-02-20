import { z } from "zod";

import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { validateMutelistYaml, validateYaml } from "@/lib/yaml";

import { PROVIDER_TYPES, ProviderType } from "./providers";

export const addRoleFormSchema = z.object({
  name: z.string().min(1, "Name is required"),
  manage_users: z.boolean().default(false),
  manage_account: z.boolean().default(false),
  manage_billing: z.boolean().default(false),
  manage_providers: z.boolean().default(false),
  manage_integrations: z.boolean().default(false),
  manage_scans: z.boolean().default(false),
  unlimited_visibility: z.boolean().default(false),
  groups: z.array(z.string()).optional(),
});

export const editRoleFormSchema = z.object({
  name: z.string().min(1, "Name is required"),
  manage_users: z.boolean().default(false),
  manage_account: z.boolean().default(false),
  manage_billing: z.boolean().default(false),
  manage_providers: z.boolean().default(false),
  manage_integrations: z.boolean().default(false),
  manage_scans: z.boolean().default(false),
  unlimited_visibility: z.boolean().default(false),
  groups: z.array(z.string()).optional(),
});

export const editScanFormSchema = (currentName: string) =>
  z.object({
    scanName: z
      .string()
      .refine((val) => val === "" || val.length >= 3, {
        message: "Must be empty or have at least 3 characters.",
      })
      .refine((val) => val === "" || val.length <= 32, {
        message: "Must not exceed 32 characters.",
      })
      .refine((val) => val !== currentName, {
        message: "The new name must be different from the current one.",
      })
      .optional(),
    scanId: z.string(),
  });

export const onDemandScanFormSchema = () =>
  z.object({
    [ProviderCredentialFields.PROVIDER_ID]: z.string(),
    scanName: z.string().optional(),
    scannerArgs: z
      .object({
        checksToExecute: z.array(z.string()),
      })
      .optional(),
  });

export const scheduleScanFormSchema = () =>
  z.object({
    providerId: z.string(),
    scheduleDate: z.string(),
  });

export const awsCredentialsTypeSchema = z.object({
  awsCredentialsType: z.string().min(1, {
    message: "Please select the type of credentials you want to use",
  }),
});

export const addProviderFormSchema = z
  .object({
    providerType: z.enum(PROVIDER_TYPES, {
      error: "Please select a provider type",
    }),
  })
  .and(
    z.discriminatedUnion("providerType", [
      z.object({
        providerType: z.literal("aws"),
        [ProviderCredentialFields.PROVIDER_ALIAS]: z.string(),
        providerUid: z.string(),
      }),
      z.object({
        providerType: z.literal("azure"),
        [ProviderCredentialFields.PROVIDER_ALIAS]: z.string(),
        providerUid: z.string(),
        awsCredentialsType: z.string().optional(),
      }),
      z.object({
        providerType: z.literal("m365"),
        [ProviderCredentialFields.PROVIDER_ALIAS]: z.string(),
        providerUid: z.string(),
      }),
      z.object({
        providerType: z.literal("gcp"),
        [ProviderCredentialFields.PROVIDER_ALIAS]: z.string(),
        providerUid: z.string(),
        awsCredentialsType: z.string().optional(),
      }),
      z.object({
        providerType: z.literal("kubernetes"),
        [ProviderCredentialFields.PROVIDER_ALIAS]: z.string(),
        providerUid: z.string(),
        awsCredentialsType: z.string().optional(),
      }),
      z.object({
        providerType: z.literal("github"),
        [ProviderCredentialFields.PROVIDER_ALIAS]: z.string(),
        providerUid: z.string(),
      }),
      z.object({
        providerType: z.literal("iac"),
        [ProviderCredentialFields.PROVIDER_ALIAS]: z.string(),
        providerUid: z.string(),
      }),
      z.object({
        providerType: z.literal("oraclecloud"),
        [ProviderCredentialFields.PROVIDER_ALIAS]: z.string(),
        providerUid: z.string(),
      }),
      z.object({
        providerType: z.literal("mongodbatlas"),
        [ProviderCredentialFields.PROVIDER_ALIAS]: z.string(),
        providerUid: z.string(),
      }),
      z.object({
        providerType: z.literal("alibabacloud"),
        [ProviderCredentialFields.PROVIDER_ALIAS]: z.string(),
        providerUid: z.string(),
      }),
      z.object({
        providerType: z.literal("cloudflare"),
        [ProviderCredentialFields.PROVIDER_ALIAS]: z.string(),
        providerUid: z.string(),
      }),
      z.object({
        providerType: z.literal("openstack"),
        [ProviderCredentialFields.PROVIDER_ALIAS]: z.string(),
        providerUid: z.string(),
      }),
    ]),
  );

export const addCredentialsFormSchema = (
  providerType: ProviderType,
  via?: string | null,
) =>
  z
    .object({
      [ProviderCredentialFields.PROVIDER_ID]: z.string(),
      [ProviderCredentialFields.PROVIDER_TYPE]: z.string(),
      ...(providerType === "aws"
        ? {
            [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: z
              .string()
              .min(1, "AWS Access Key ID is required"),
            [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: z
              .string()
              .min(1, "AWS Secret Access Key is required"),
            [ProviderCredentialFields.AWS_SESSION_TOKEN]: z.string().optional(),
          }
        : providerType === "azure"
          ? {
              [ProviderCredentialFields.CLIENT_ID]: z
                .string()
                .min(1, "Client ID is required"),
              [ProviderCredentialFields.CLIENT_SECRET]: z
                .string()
                .min(1, "Client Secret is required"),
              [ProviderCredentialFields.TENANT_ID]: z
                .string()
                .min(1, "Tenant ID is required"),
            }
          : providerType === "gcp"
            ? {
                [ProviderCredentialFields.CLIENT_ID]: z
                  .string()
                  .min(1, "Client ID is required"),
                [ProviderCredentialFields.CLIENT_SECRET]: z
                  .string()
                  .min(1, "Client Secret is required"),
                [ProviderCredentialFields.REFRESH_TOKEN]: z
                  .string()
                  .min(1, "Refresh Token is required"),
              }
            : providerType === "kubernetes"
              ? {
                  [ProviderCredentialFields.KUBECONFIG_CONTENT]: z
                    .string()
                    .min(1, "Kubeconfig Content is required"),
                }
              : providerType === "m365"
                ? {
                    [ProviderCredentialFields.CLIENT_ID]: z
                      .string()
                      .min(1, "Client ID is required"),
                    [ProviderCredentialFields.CLIENT_SECRET]: z
                      .string()
                      .optional(),
                    [ProviderCredentialFields.CERTIFICATE_CONTENT]: z
                      .string()
                      .optional(),
                    [ProviderCredentialFields.TENANT_ID]: z
                      .string()
                      .min(1, "Tenant ID is required"),
                  }
                : providerType === "github"
                  ? {
                      [ProviderCredentialFields.PERSONAL_ACCESS_TOKEN]: z
                        .string()
                        .optional(),
                      [ProviderCredentialFields.OAUTH_APP_TOKEN]: z
                        .string()
                        .optional(),
                      [ProviderCredentialFields.GITHUB_APP_ID]: z
                        .string()
                        .optional(),
                      [ProviderCredentialFields.GITHUB_APP_KEY]: z
                        .string()
                        .optional(),
                    }
                  : providerType === "iac"
                    ? {
                        [ProviderCredentialFields.REPOSITORY_URL]: z
                          .string()
                          .optional(),
                        [ProviderCredentialFields.ACCESS_TOKEN]: z
                          .string()
                          .optional(),
                      }
                    : providerType === "oraclecloud"
                      ? {
                          [ProviderCredentialFields.OCI_USER]: z
                            .string()
                            .min(1, "User OCID is required"),
                          [ProviderCredentialFields.OCI_FINGERPRINT]: z
                            .string()
                            .min(1, "Fingerprint is required"),
                          [ProviderCredentialFields.OCI_KEY_CONTENT]: z
                            .string()
                            .min(1, "Private Key Content is required"),
                          [ProviderCredentialFields.OCI_TENANCY]: z
                            .string()
                            .min(1, "Tenancy OCID is required"),
                          [ProviderCredentialFields.OCI_REGION]: z
                            .string()
                            .min(1, "Region is required"),
                          [ProviderCredentialFields.OCI_PASS_PHRASE]: z
                            .union([z.string(), z.literal("")])
                            .optional(),
                        }
                      : providerType === "mongodbatlas"
                        ? {
                            [ProviderCredentialFields.ATLAS_PUBLIC_KEY]: z
                              .string()
                              .min(1, "Atlas Public Key is required"),
                            [ProviderCredentialFields.ATLAS_PRIVATE_KEY]: z
                              .string()
                              .min(1, "Atlas Private Key is required"),
                          }
                        : providerType === "alibabacloud"
                          ? {
                              [ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_ID]:
                                z.string().min(1, "Access Key ID is required"),
                              [ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_SECRET]:
                                z
                                  .string()
                                  .min(1, "Access Key Secret is required"),
                            }
                          : providerType === "cloudflare"
                            ? {
                                [ProviderCredentialFields.CLOUDFLARE_API_TOKEN]:
                                  z.string().optional(),
                                [ProviderCredentialFields.CLOUDFLARE_API_KEY]: z
                                  .string()
                                  .optional(),
                                [ProviderCredentialFields.CLOUDFLARE_API_EMAIL]:
                                  z
                                    .string()
                                    .superRefine((val, ctx) => {
                                      if (val && val.trim() !== "") {
                                        const emailRegex =
                                          /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                                        if (!emailRegex.test(val)) {
                                          ctx.addIssue({
                                            code: z.ZodIssueCode.custom,
                                            message:
                                              "Please enter a valid email address",
                                          });
                                        }
                                      }
                                    })
                                    .optional(),
                              }
                            : providerType === "openstack"
                              ? {
                                  [ProviderCredentialFields.OPENSTACK_CLOUDS_YAML_CONTENT]:
                                    z
                                      .string()
                                      .min(
                                        1,
                                        "Clouds YAML content is required",
                                      ),
                                  [ProviderCredentialFields.OPENSTACK_CLOUDS_YAML_CLOUD]:
                                    z.string().min(1, "Cloud name is required"),
                                }
                              : {}),
    })
    .superRefine((data: Record<string, string | undefined>, ctx) => {
      if (providerType === "m365") {
        // Validate based on the via parameter
        if (via === "app_client_secret") {
          const clientSecret = data[ProviderCredentialFields.CLIENT_SECRET];
          if (!clientSecret || clientSecret.trim() === "") {
            ctx.addIssue({
              code: "custom",
              message: "Client Secret is required",
              path: [ProviderCredentialFields.CLIENT_SECRET],
            });
          }
        } else if (via === "app_certificate") {
          const certificateContent =
            data[ProviderCredentialFields.CERTIFICATE_CONTENT];
          if (!certificateContent || certificateContent.trim() === "") {
            ctx.addIssue({
              code: "custom",
              message: "Certificate Content is required",
              path: [ProviderCredentialFields.CERTIFICATE_CONTENT],
            });
          }
        }
      }

      if (providerType === "github") {
        // For GitHub, validation depends on the 'via' parameter
        if (via === "personal_access_token") {
          if (!data[ProviderCredentialFields.PERSONAL_ACCESS_TOKEN]) {
            ctx.addIssue({
              code: "custom",
              message: "Personal Access Token is required",
              path: [ProviderCredentialFields.PERSONAL_ACCESS_TOKEN],
            });
          }
        } else if (via === "oauth_app") {
          if (!data[ProviderCredentialFields.OAUTH_APP_TOKEN]) {
            ctx.addIssue({
              code: "custom",
              message: "OAuth App Token is required",
              path: [ProviderCredentialFields.OAUTH_APP_TOKEN],
            });
          }
        } else if (via === "github_app") {
          if (!data[ProviderCredentialFields.GITHUB_APP_ID]) {
            ctx.addIssue({
              code: "custom",
              message: "GitHub App ID is required",
              path: [ProviderCredentialFields.GITHUB_APP_ID],
            });
          }
          if (!data[ProviderCredentialFields.GITHUB_APP_KEY]) {
            ctx.addIssue({
              code: "custom",
              message: "GitHub App Private Key is required",
              path: [ProviderCredentialFields.GITHUB_APP_KEY],
            });
          }
        }
      }

      if (providerType === "cloudflare") {
        // For Cloudflare, validation depends on the 'via' parameter
        if (via === "api_token") {
          const apiToken = data[ProviderCredentialFields.CLOUDFLARE_API_TOKEN];
          if (!apiToken || apiToken.trim() === "") {
            ctx.addIssue({
              code: "custom",
              message: "API Token is required",
              path: [ProviderCredentialFields.CLOUDFLARE_API_TOKEN],
            });
          }
        } else if (via === "api_key") {
          const apiKey = data[ProviderCredentialFields.CLOUDFLARE_API_KEY];
          const apiEmail = data[ProviderCredentialFields.CLOUDFLARE_API_EMAIL];
          if (!apiKey || apiKey.trim() === "") {
            ctx.addIssue({
              code: "custom",
              message: "API Key is required",
              path: [ProviderCredentialFields.CLOUDFLARE_API_KEY],
            });
          }
          if (!apiEmail || apiEmail.trim() === "") {
            ctx.addIssue({
              code: "custom",
              message: "Email is required",
              path: [ProviderCredentialFields.CLOUDFLARE_API_EMAIL],
            });
          }
        }
      }
    });

export const addCredentialsRoleFormSchema = (providerType: string) =>
  providerType === "aws"
    ? z
        .object({
          [ProviderCredentialFields.PROVIDER_ID]: z.string(),
          [ProviderCredentialFields.PROVIDER_TYPE]: z.string(),
          [ProviderCredentialFields.ROLE_ARN]: z
            .string()
            .min(1, "AWS Role ARN is required"),
          [ProviderCredentialFields.EXTERNAL_ID]: z.string().optional(),
          [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: z.string().optional(),
          [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: z
            .string()
            .optional(),
          [ProviderCredentialFields.AWS_SESSION_TOKEN]: z.string().optional(),
          [ProviderCredentialFields.SESSION_DURATION]: z.string().optional(),
          [ProviderCredentialFields.ROLE_SESSION_NAME]: z.string().optional(),
          [ProviderCredentialFields.CREDENTIALS_TYPE]: z.string().optional(),
        })
        .refine(
          (data) =>
            data[ProviderCredentialFields.CREDENTIALS_TYPE] !==
              "access-secret-key" ||
            (data[ProviderCredentialFields.AWS_ACCESS_KEY_ID] &&
              data[ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]),
          {
            message: "AWS Access Key ID and Secret Access Key are required.",
            path: [ProviderCredentialFields.AWS_ACCESS_KEY_ID],
          },
        )
    : providerType === "alibabacloud"
      ? z.object({
          [ProviderCredentialFields.PROVIDER_ID]: z.string(),
          [ProviderCredentialFields.PROVIDER_TYPE]: z.string(),
          [ProviderCredentialFields.ALIBABACLOUD_ROLE_ARN]: z
            .string()
            .min(1, "RAM Role ARN is required"),
          [ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_ID]: z
            .string()
            .min(1, "Access Key ID is required"),
          [ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_SECRET]: z
            .string()
            .min(1, "Access Key Secret is required"),
          [ProviderCredentialFields.ALIBABACLOUD_ROLE_SESSION_NAME]: z
            .string()
            .optional(),
        })
      : z.object({
          providerId: z.string(),
          providerType: z.string(),
        });

export const addCredentialsServiceAccountFormSchema = (
  providerType: ProviderType,
) =>
  providerType === "gcp"
    ? z.object({
        [ProviderCredentialFields.PROVIDER_ID]: z.string(),
        [ProviderCredentialFields.PROVIDER_TYPE]: z.string(),
        [ProviderCredentialFields.SERVICE_ACCOUNT_KEY]: z.string().refine(
          (val) => {
            try {
              const parsed = JSON.parse(val);
              return (
                typeof parsed === "object" &&
                parsed !== null &&
                !Array.isArray(parsed)
              );
            } catch {
              return false;
            }
          },
          {
            message: "Invalid JSON format. Please provide a valid JSON object.",
          },
        ),
      })
    : z.object({
        [ProviderCredentialFields.PROVIDER_ID]: z.string(),
        [ProviderCredentialFields.PROVIDER_TYPE]: z.string(),
      });

export const testConnectionFormSchema = z.object({
  [ProviderCredentialFields.PROVIDER_ID]: z.string(),
  runOnce: z.boolean().default(false),
});

export const launchScanFormSchema = () =>
  z.object({
    [ProviderCredentialFields.PROVIDER_ID]: z.string(),
    [ProviderCredentialFields.PROVIDER_TYPE]: z.string(),
    scannerArgs: z
      .object({
        checksToExecute: z.array(z.string()).optional(),
      })
      .optional(),
  });

export const editProviderFormSchema = (currentAlias: string) =>
  z.object({
    [ProviderCredentialFields.PROVIDER_ALIAS]: z
      .string()
      .refine((val) => val === "" || val.length >= 3, {
        message: "The alias must be empty or have at least 3 characters.",
      })
      .refine((val) => val !== currentAlias, {
        message: "The new alias must be different from the current one.",
      })
      .optional(),
    [ProviderCredentialFields.PROVIDER_ID]: z.string(),
  });

export const editInviteFormSchema = z.object({
  invitationId: z.uuid(),
  invitationEmail: z.email(),
  expires_at: z.string().optional(),
  role: z.string().optional(),
});

export const editUserFormSchema = () =>
  z.object({
    name: z
      .string()
      .min(3, { message: "The name must have at least 3 characters." })
      .max(150, { message: "The name cannot exceed 150 characters." })
      .optional(),
    email: z.email({ error: "Please enter a valid email address." }).optional(),
    password: z
      .string()
      .min(1, { message: "The password cannot be empty." })
      .optional(),
    company_name: z.string().optional(),
    userId: z.string(),
    role: z.string().optional(),
  });

export const samlConfigFormSchema = z.object({
  email_domain: z
    .string()
    .trim()
    .min(1, { message: "Email domain is required" }),
  metadata_xml: z
    .string()
    .trim()
    .min(1, { message: "Metadata XML is required" }),
});

export const mutedFindingsConfigFormSchema = z.object({
  configuration: z
    .string()
    .trim()
    .min(1, { message: "Configuration is required" })
    .superRefine((val, ctx) => {
      const yamlValidation = validateYaml(val);
      if (!yamlValidation.isValid) {
        ctx.addIssue({
          code: "custom",
          message: `Invalid YAML format: ${yamlValidation.error}`,
        });
        return;
      }

      const mutelistValidation = validateMutelistYaml(val);
      if (!mutelistValidation.isValid) {
        ctx.addIssue({
          code: "custom",
          message: `Invalid mutelist structure: ${mutelistValidation.error}`,
        });
      }
    }),
  id: z.string().optional(),
});
