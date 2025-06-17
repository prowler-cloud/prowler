import { z } from "zod";

import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

import { ProviderType } from "./providers";

export const addRoleFormSchema = z.object({
  name: z.string().min(1, "Name is required"),
  manage_users: z.boolean().default(false),
  manage_account: z.boolean().default(false),
  manage_billing: z.boolean().default(false),
  manage_providers: z.boolean().default(false),
  // manage_integrations: z.boolean().default(false),
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
  // manage_integrations: z.boolean().default(false),
  manage_scans: z.boolean().default(false),
  unlimited_visibility: z.boolean().default(false),
  groups: z.array(z.string()).optional(),
});

export const editScanFormSchema = (currentName: string) =>
  z.object({
    scanName: z
      .string()
      .refine((val) => val === "" || val.length >= 3, {
        message: "The alias must be empty or have at least 3 characters.",
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
    providerType: z.enum(["aws", "azure", "gcp", "kubernetes", "m365"], {
      required_error: "Please select a provider type",
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
    ]),
  );

export const addCredentialsFormSchema = (providerType: string) =>
  z
    .object({
      [ProviderCredentialFields.PROVIDER_ID]: z.string(),
      [ProviderCredentialFields.PROVIDER_TYPE]: z.string(),
      ...(providerType === "aws"
        ? {
            [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: z
              .string()
              .nonempty("AWS Access Key ID is required"),
            [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: z
              .string()
              .nonempty("AWS Secret Access Key is required"),
            [ProviderCredentialFields.AWS_SESSION_TOKEN]: z.string().optional(),
          }
        : providerType === "azure"
          ? {
              [ProviderCredentialFields.CLIENT_ID]: z
                .string()
                .nonempty("Client ID is required"),
              [ProviderCredentialFields.CLIENT_SECRET]: z
                .string()
                .nonempty("Client Secret is required"),
              [ProviderCredentialFields.TENANT_ID]: z
                .string()
                .nonempty("Tenant ID is required"),
            }
          : providerType === "gcp"
            ? {
                [ProviderCredentialFields.CLIENT_ID]: z
                  .string()
                  .nonempty("Client ID is required"),
                [ProviderCredentialFields.CLIENT_SECRET]: z
                  .string()
                  .nonempty("Client Secret is required"),
                [ProviderCredentialFields.REFRESH_TOKEN]: z
                  .string()
                  .nonempty("Refresh Token is required"),
              }
            : providerType === "kubernetes"
              ? {
                  [ProviderCredentialFields.KUBECONFIG_CONTENT]: z
                    .string()
                    .nonempty("Kubeconfig Content is required"),
                }
              : providerType === "m365"
                ? {
                    [ProviderCredentialFields.CLIENT_ID]: z
                      .string()
                      .nonempty("Client ID is required"),
                    [ProviderCredentialFields.CLIENT_SECRET]: z
                      .string()
                      .nonempty("Client Secret is required"),
                    [ProviderCredentialFields.TENANT_ID]: z
                      .string()
                      .nonempty("Tenant ID is required"),
                    [ProviderCredentialFields.USER]: z.string().optional(),
                    [ProviderCredentialFields.PASSWORD]: z.string().optional(),
                  }
                : {}),
    })
    .superRefine((data: Record<string, any>, ctx) => {
      if (providerType === "m365") {
        const hasUser = !!data[ProviderCredentialFields.USER];
        const hasPassword = !!data[ProviderCredentialFields.PASSWORD];

        if (hasUser && !hasPassword) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "If you provide a user, you must also provide a password",
            path: [ProviderCredentialFields.PASSWORD],
          });
        }

        if (hasPassword && !hasUser) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "If you provide a password, you must also provide a user",
            path: [ProviderCredentialFields.USER],
          });
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
            .nonempty("AWS Role ARN is required"),
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
  invitationId: z.string().uuid(),
  invitationEmail: z.string().email(),
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
    email: z
      .string()
      .email({ message: "Please enter a valid email address." })
      .optional(),
    password: z
      .string()
      .min(1, { message: "The password cannot be empty." })
      .optional(),
    company_name: z.string().optional(),
    userId: z.string(),
    role: z.string().optional(),
  });
