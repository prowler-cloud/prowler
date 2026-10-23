import type { ReactNode } from "react";

import {
  GithubIcon,
  GoogleIcon,
  GoogleMonoIcon,
  MicrosoftIcon,
} from "@/components/icons/Icons";
import {
  Button,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import { CustomLink } from "@/components/shadcn/custom/custom-link";
import { appendCallbackState } from "@/lib/auth-callback-url";
import type { IconComponent } from "@/types/components";

type SocialProvider = {
  key: string;
  label: string;
  url?: string;
  isOAuthEnabled?: boolean;
  enabledIcon: IconComponent;
  disabledIcon: IconComponent;
  disabledDocs: {
    message: string;
    href: string;
  };
};

const SocialButton = ({
  provider,
  isDisabled,
  disabledTooltipContent,
}: {
  provider: SocialProvider;
  isDisabled: boolean;
  disabledTooltipContent: ReactNode;
}) => {
  const button = (
    <Button
      variant="outline"
      aria-label={provider.label}
      className={isDisabled ? "w-full" : "flex-1"}
      asChild={!isDisabled}
      disabled={isDisabled}
    >
      {isDisabled ? (
        <span className="flex items-center justify-center">
          {provider.isOAuthEnabled ? (
            <provider.enabledIcon aria-hidden="true" />
          ) : (
            <provider.disabledIcon aria-hidden="true" />
          )}
        </span>
      ) : (
        <a href={provider.url} className="flex items-center justify-center">
          <provider.enabledIcon aria-hidden="true" />
        </a>
      )}
    </Button>
  );

  if (!isDisabled) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>{button}</TooltipTrigger>
        <TooltipContent side="top">{provider.label}</TooltipContent>
      </Tooltip>
    );
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="flex flex-1">{button}</span>
      </TooltipTrigger>
      <TooltipContent side="top" className="w-96">
        {provider.isOAuthEnabled ? (
          disabledTooltipContent
        ) : (
          <div className="flex-inline text-sm">
            {provider.disabledDocs.message}{" "}
            <CustomLink href={provider.disabledDocs.href}>
              Read the docs
            </CustomLink>
          </div>
        )}
      </TooltipContent>
    </Tooltip>
  );
};

export const SocialButtons = ({
  googleAuthUrl,
  githubAuthUrl,
  microsoftAuthUrl,
  callbackUrl = "/",
  isGoogleOAuthEnabled,
  isGithubOAuthEnabled,
  isMicrosoftOAuthEnabled,
  isDisabled = false,
  disabledTooltipContent,
}: {
  googleAuthUrl?: string;
  githubAuthUrl?: string;
  microsoftAuthUrl?: string;
  callbackUrl?: string;
  isGoogleOAuthEnabled?: boolean;
  isGithubOAuthEnabled?: boolean;
  isMicrosoftOAuthEnabled?: boolean;
  isDisabled?: boolean;
  disabledTooltipContent?: ReactNode;
}) => {
  const googleUrl = googleAuthUrl
    ? appendCallbackState(googleAuthUrl, callbackUrl)
    : undefined;
  const githubUrl = githubAuthUrl
    ? appendCallbackState(githubAuthUrl, callbackUrl)
    : undefined;
  const microsoftUrl = microsoftAuthUrl
    ? appendCallbackState(microsoftAuthUrl, callbackUrl)
    : undefined;
  const socialDisabledTooltip =
    disabledTooltipContent || "Social login is currently unavailable.";

  const providers: SocialProvider[] = [
    {
      key: "google",
      label: "Continue with Google",
      url: googleUrl,
      isOAuthEnabled: isGoogleOAuthEnabled,
      enabledIcon: GoogleIcon,
      disabledIcon: GoogleMonoIcon,
      disabledDocs: {
        message: "Social Login with Google is not enabled.",
        href: "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-social-login/#google-oauth-configuration",
      },
    },
    {
      key: "github",
      label: "Continue with Github",
      url: githubUrl,
      isOAuthEnabled: isGithubOAuthEnabled,
      enabledIcon: GithubIcon,
      disabledIcon: GithubIcon,
      disabledDocs: {
        message: "Social Login with Github is not enabled.",
        href: "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-social-login/#github-oauth-configuration",
      },
    },
    {
      key: "microsoft",
      label: "Continue with Microsoft",
      url: microsoftUrl,
      isOAuthEnabled: isMicrosoftOAuthEnabled,
      enabledIcon: MicrosoftIcon,
      disabledIcon: MicrosoftIcon,
      disabledDocs: {
        message: "Social Login with Microsoft is not enabled.",
        href: "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-social-login/#microsoft-entra-id-oauth-configuration",
      },
    },
  ];

  return (
    <>
      {providers.map((provider) => (
        <SocialButton
          key={provider.key}
          provider={provider}
          isDisabled={isDisabled || !provider.isOAuthEnabled || !provider.url}
          disabledTooltipContent={socialDisabledTooltip}
        />
      ))}
    </>
  );
};
