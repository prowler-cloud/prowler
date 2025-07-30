"use client";

import { Control } from "react-hook-form";

import {
  GitHubPersonalAccessTokenForm,
  GitHubOAuthAppForm,
  GitHubAppForm,
} from "../select-credentials-type/github";

interface GitHubCredentialsFormProps {
  control: Control<any>;
  credentialsType?: string;
}

export const GitHubCredentialsForm = ({
  control,
  credentialsType,
}: GitHubCredentialsFormProps) => {
  switch (credentialsType) {
    case "personal_access_token":
      return <GitHubPersonalAccessTokenForm control={control} />;
    case "oauth_app":
      return <GitHubOAuthAppForm control={control} />;
    case "github_app":
      return <GitHubAppForm control={control} />;
    default:
      return null;
  }
};