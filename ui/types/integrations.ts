export interface JiraIntegrationFormType {
  projectKey: string;
  issueType: string;
  authMethod: "basic" | "oauth2";
  
  // Basic Auth fields
  domain?: string;
  userEmail?: string;
  apiToken?: string;
  
  // OAuth2 fields
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
}

export interface JiraIntegration {
  id: string;
  integration_type: "jira";
  enabled: boolean;
  connected?: boolean;
  config: {
    project_key: string;
    issue_type: string;
    auth_method: "basic" | "oauth2";
    domain?: string;
    user_email?: string;
    api_token?: string;
    client_id?: string;
    client_secret?: string;
    redirect_uri?: string;
  };
  inserted_at: string;
  updated_at: string;
}

export interface Integration {
  id: string;
  integration_type: "jira" | "slack" | "amazon_s3" | "aws_security_hub";
  enabled: boolean;
  connected?: boolean;
  config: Record<string, any>;
  inserted_at: string;
  updated_at: string;
  providers?: {
    id: string;
    alias: string;
    provider: string;
  }[];
}

export interface JiraProject {
  key: string;
  name: string;
}

export interface JiraIssueType {
  id: string;
  name: string;
  description?: string;
}