import { z } from "zod";

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
    providerId: z.string(),
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
    providerType: z.enum(["aws", "azure", "gcp", "kubernetes"], {
      required_error: "Please select a provider type",
    }),
  })
  .and(
    z.discriminatedUnion("providerType", [
      z.object({
        providerType: z.literal("aws"),
        providerAlias: z.string(),
        providerUid: z.string(),
      }),
      z.object({
        providerType: z.literal("azure"),
        providerAlias: z.string(),
        providerUid: z.string(),
        awsCredentialsType: z.string().optional(),
      }),
      z.object({
        providerType: z.literal("gcp"),
        providerAlias: z.string(),
        providerUid: z.string(),
        awsCredentialsType: z.string().optional(),
      }),
      z.object({
        providerType: z.literal("kubernetes"),
        providerAlias: z.string(),
        providerUid: z.string(),
        awsCredentialsType: z.string().optional(),
      }),
    ]),
  );

export const addCredentialsFormSchema = (providerType: string) =>
  z.object({
    secretName: z.string().optional(),
    providerId: z.string(),
    providerType: z.string(),
    ...(providerType === "aws"
      ? {
          aws_access_key_id: z
            .string()
            .nonempty("AWS Access Key ID is required"),
          aws_secret_access_key: z
            .string()
            .nonempty("AWS Secret Access Key is required"),
          aws_session_token: z.string().optional(),
        }
      : providerType === "azure"
        ? {
            client_id: z.string().nonempty("Client ID is required"),
            client_secret: z.string().nonempty("Client Secret is required"),
            tenant_id: z.string().nonempty("Tenant ID is required"),
          }
        : providerType === "gcp"
          ? {
              client_id: z.string().nonempty("Client ID is required"),
              client_secret: z.string().nonempty("Client Secret is required"),
              refresh_token: z.string().nonempty("Refresh Token is required"),
            }
          : providerType === "kubernetes"
            ? {
                kubeconfig_content: z
                  .string()
                  .nonempty("Kubeconfig Content is required"),
              }
            : {}),
  });

export const addCredentialsRoleFormSchema = (providerType: string) =>
  providerType === "aws"
    ? z.object({
        providerId: z.string(),
        providerType: z.string(),
        role_arn: z.string().optional(),
        aws_access_key_id: z.string().optional(),
        aws_secret_access_key: z.string().optional(),
        aws_session_token: z.string().optional(),
        session_duration: z.number().optional(),
        external_id: z.string().optional(),
        role_session_name: z.string().optional(),
      })
    : z.object({
        providerId: z.string(),
        providerType: z.string(),
      });

export const testConnectionFormSchema = z.object({
  providerId: z.string(),
});

export const launchScanFormSchema = () =>
  z.object({
    providerId: z.string(),
    providerType: z.string(),
    scannerArgs: z
      .object({
        checksToExecute: z.array(z.string()).optional(),
      })
      .optional(),
  });

export const editProviderFormSchema = (currentAlias: string) =>
  z.object({
    alias: z
      .string()
      .refine((val) => val === "" || val.length >= 3, {
        message: "The alias must be empty or have at least 3 characters.",
      })
      .refine((val) => val !== currentAlias, {
        message: "The new alias must be different from the current one.",
      })
      .optional(),
    providerId: z.string(),
  });

export const editInviteFormSchema = z.object({
  invitationId: z.string().uuid(),
  invitationEmail: z.string().email(),
  expires_at: z.string().optional(),
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
  });
