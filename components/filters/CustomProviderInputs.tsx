import React from "react";

import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
} from "../icons/providers-badge";

export const CustomProviderInputAWS = () => {
  return (
    <div className="flex gap-x-2 items-center">
      <AWSProviderBadge width={30} height={30} />
      <p className="text-sm">Amazon Web Services</p>
    </div>
  );
};

export const CustomProviderInputAzure = () => {
  return (
    <div className="flex gap-x-2 items-center">
      <AzureProviderBadge width={30} height={30} />
      <p className="text-sm">Azure</p>
    </div>
  );
};

export const CustomProviderInputGCP = () => {
  return (
    <div className="flex gap-x-2 items-center">
      <GCPProviderBadge width={30} height={30} />
      <p className="text-sm">Google Cloud Platform</p>
    </div>
  );
};
