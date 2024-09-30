import React from "react";

import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  KS8ProviderBadge,
} from "../icons/providers-badge";

export const CustomProviderInputAWS = () => {
  return (
    <div className="flex gap-x-2 items-center">
      <AWSProviderBadge width={25} height={25} />
      <p className="text-sm">Amazon Web Services</p>
    </div>
  );
};

export const CustomProviderInputAzure = () => {
  return (
    <div className="flex gap-x-2 items-center">
      <AzureProviderBadge width={25} height={25} />
      <p className="text-sm">Azure</p>
    </div>
  );
};

export const CustomProviderInputGCP = () => {
  return (
    <div className="flex gap-x-2 items-center">
      <GCPProviderBadge width={25} height={25} />
      <p className="text-sm">Google Cloud Platform</p>
    </div>
  );
};

export const CustomProviderInputKubernetes = () => {
  return (
    <div className="flex gap-x-2 items-center">
      <KS8ProviderBadge width={25} height={25} />
      <p className="text-sm">Kubernetes</p>
    </div>
  );
};
