declare global {
  namespace NodeJS {
    interface ProcessEnv {
      // Runtime (Node / Next.js)
      NODE_ENV: "development" | "production" | "test";
      NEXT_RUNTIME?: "nodejs" | "edge";

      // Public client config
      NEXT_PUBLIC_API_BASE_URL: string;
      NEXT_PUBLIC_API_DOCS_URL?: string;
      NEXT_PUBLIC_IS_CLOUD_ENV?: "true" | "false";
      NEXT_PUBLIC_PROWLER_RELEASE_VERSION?: string;
      NEXT_PUBLIC_GOOGLE_TAG_MANAGER_ID?: string;
      NEXT_PUBLIC_SENTRY_DSN?: string;
      NEXT_PUBLIC_SENTRY_ENVIRONMENT?: string;

      // Auth (NextAuth)
      AUTH_URL: string;
      AUTH_SECRET: string;
      AUTH_TRUST_HOST?: "true" | "false";
      NEXTAUTH_URL?: string;

      // Sentry (server / build)
      SENTRY_DSN?: string;
      SENTRY_ENVIRONMENT?: string;
      SENTRY_RELEASE?: string;
      SENTRY_ORG?: string;
      SENTRY_PROJECT?: string;
      SENTRY_AUTH_TOKEN?: string;

      // Social OAuth
      SOCIAL_GOOGLE_OAUTH_CLIENT_ID?: string;
      SOCIAL_GOOGLE_OAUTH_CLIENT_SECRET?: string;
      SOCIAL_GOOGLE_OAUTH_CALLBACK_URL?: string;
      SOCIAL_GITHUB_OAUTH_CLIENT_ID?: string;
      SOCIAL_GITHUB_OAUTH_CLIENT_SECRET?: string;
      SOCIAL_GITHUB_OAUTH_CALLBACK_URL?: string;

      // Feature integrations
      PROWLER_MCP_SERVER_URL?: string;
      // JSON-encoded array, parsed in actions/feeds
      RSS_FEED_SOURCES?: string;

      // Environment detection
      CI?: string;
      DOCKER?: string;
      KUBERNETES_SERVICE_HOST?: string;

      // E2E test credentials (Playwright only)
      E2E_ADMIN_USER?: string;
      E2E_ADMIN_PASSWORD?: string;
      E2E_NEW_USER_PASSWORD?: string;
      E2E_MANAGE_CLOUD_PROVIDERS_USER?: string;
      E2E_MANAGE_CLOUD_PROVIDERS_PASSWORD?: string;
      E2E_INVITE_AND_MANAGE_USERS_USER?: string;
      E2E_INVITE_AND_MANAGE_USERS_PASSWORD?: string;
      E2E_UNLIMITED_VISIBILITY_USER?: string;
      E2E_UNLIMITED_VISIBILITY_PASSWORD?: string;
      E2E_MANAGE_INTEGRATIONS_USER?: string;
      E2E_MANAGE_INTEGRATIONS_PASSWORD?: string;
      E2E_MANAGE_ACCOUNT_USER?: string;
      E2E_MANAGE_ACCOUNT_PASSWORD?: string;
      E2E_MANAGE_SCANS_USER?: string;
      E2E_MANAGE_SCANS_PASSWORD?: string;
      E2E_ORGANIZATION_ID?: string;

      // E2E AWS
      E2E_AWS_PROVIDER_ACCOUNT_ID?: string;
      E2E_AWS_PROVIDER_ACCESS_KEY?: string;
      E2E_AWS_PROVIDER_SECRET_KEY?: string;
      E2E_AWS_PROVIDER_ROLE_ARN?: string;
      E2E_AWS_ORGANIZATION_ID?: string;
      E2E_AWS_ORGANIZATION_ROLE_ARN?: string;

      // E2E Azure
      E2E_AZURE_SUBSCRIPTION_ID?: string;
      E2E_AZURE_CLIENT_ID?: string;
      E2E_AZURE_SECRET_ID?: string;
      E2E_AZURE_TENANT_ID?: string;

      // E2E Microsoft 365
      E2E_M365_DOMAIN_ID?: string;
      E2E_M365_CLIENT_ID?: string;
      E2E_M365_TENANT_ID?: string;
      E2E_M365_SECRET_ID?: string;
      E2E_M365_CERTIFICATE_CONTENT?: string;

      // E2E GCP
      E2E_GCP_PROJECT_ID?: string;
      E2E_GCP_BASE64_SERVICE_ACCOUNT_KEY?: string;

      // E2E Kubernetes
      E2E_KUBERNETES_CONTEXT?: string;
      E2E_KUBERNETES_KUBECONFIG_PATH?: string;

      // E2E GitHub
      E2E_GITHUB_USERNAME?: string;
      E2E_GITHUB_PERSONAL_ACCESS_TOKEN?: string;
      E2E_GITHUB_APP_ID?: string;
      E2E_GITHUB_BASE64_APP_PRIVATE_KEY?: string;
      E2E_GITHUB_ORGANIZATION?: string;
      E2E_GITHUB_ORGANIZATION_ACCESS_TOKEN?: string;

      // E2E Oracle Cloud
      E2E_OCI_TENANCY_ID?: string;
      E2E_OCI_USER_ID?: string;
      E2E_OCI_FINGERPRINT?: string;
      E2E_OCI_KEY_CONTENT?: string;
      E2E_OCI_REGION?: string;

      // E2E Alibaba Cloud
      E2E_ALIBABACLOUD_ACCOUNT_ID?: string;
      E2E_ALIBABACLOUD_ACCESS_KEY_ID?: string;
      E2E_ALIBABACLOUD_ACCESS_KEY_SECRET?: string;
      E2E_ALIBABACLOUD_ROLE_ARN?: string;

      // E2E Google Workspace
      E2E_GOOGLEWORKSPACE_CUSTOMER_ID?: string;
      E2E_GOOGLEWORKSPACE_SERVICE_ACCOUNT_JSON?: string;
      E2E_GOOGLEWORKSPACE_DELEGATED_USER?: string;
    }
  }
}

export {};
