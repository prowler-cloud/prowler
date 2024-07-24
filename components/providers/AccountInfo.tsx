import React from "react";

import {
  AwsProvider,
  AzureProvider,
  GoogleCloudProvider,
  WifiIcon,
  WifiOffIcon,
} from "../icons";

interface AccountInfoProps {
  connected: boolean;
  provider: "aws" | "azure" | "gcp";
  accountName: string;
  accountId: string;
}

export const AccountInfo: React.FC<AccountInfoProps> = ({
  connected,
  provider,
  accountName,
  accountId,
}) => {
  const getIcon = () => {
    return connected ? <WifiIcon size={22} /> : <WifiOffIcon size={22} />;
  };

  const getProviderLogo = () => {
    switch (provider) {
      case "aws":
        return <AwsProvider width={35} height={35} />;
      case "azure":
        return <AzureProvider width={35} height={35} />;

      case "gcp":
        return <GoogleCloudProvider width={35} height={35} />;
      default:
        return null;
    }
  };

  return (
    <div className="max-w-fit">
      <div className="flex items-center space-x-4">
        <div className="flex-shrink-0">{getIcon()}</div>
        <div className="flex-shrink-0 mx-2">{getProviderLogo()}</div>
        <div className="flex flex-col">
          <span className="text-md font-semibold">{accountName}</span>
          <span className="text-sm text-gray-500">{accountId}</span>
        </div>
      </div>
    </div>
  );
};
