import {
  AlibabaCloudProviderBadge,
  AWSProviderBadge,
  AzureProviderBadge,
  CloudflareProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  IacProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
  MongoDBAtlasProviderBadge,
  OpenStackProviderBadge,
  OracleCloudProviderBadge,
} from "../icons/providers-badge";

export const CustomProviderInputAWS = () => {
  return (
    <div className="flex items-center gap-x-2">
      <AWSProviderBadge width={25} height={25} />
      <p className="text-sm">Amazon Web Services</p>
    </div>
  );
};

export const CustomProviderInputAzure = () => {
  return (
    <div className="flex items-center gap-x-2">
      <AzureProviderBadge width={25} height={25} />
      <p className="text-sm">Azure</p>
    </div>
  );
};

export const CustomProviderInputM365 = () => {
  return (
    <div className="flex items-center gap-x-2">
      <M365ProviderBadge width={25} height={25} />
      <p className="text-sm">Microsoft 365</p>
    </div>
  );
};

export const CustomProviderInputMongoDBAtlas = () => {
  return (
    <div className="flex items-center gap-x-2">
      <MongoDBAtlasProviderBadge width={25} height={25} />
      <p className="text-sm">MongoDB Atlas</p>
    </div>
  );
};

export const CustomProviderInputGCP = () => {
  return (
    <div className="flex items-center gap-x-2">
      <GCPProviderBadge width={25} height={25} />
      <p className="text-sm">Google Cloud Platform</p>
    </div>
  );
};

export const CustomProviderInputKubernetes = () => {
  return (
    <div className="flex items-center gap-x-2">
      <KS8ProviderBadge width={25} height={25} />
      <p className="text-sm">Kubernetes</p>
    </div>
  );
};

export const CustomProviderInputGitHub = () => {
  return (
    <div className="flex items-center gap-x-2">
      <GitHubProviderBadge width={25} height={25} />
      <p className="text-sm">GitHub</p>
    </div>
  );
};

export const CustomProviderInputIac = () => {
  return (
    <div className="flex items-center gap-x-2">
      <IacProviderBadge width={25} height={25} />
      <p className="text-sm">Infrastructure as Code</p>
    </div>
  );
};

export const CustomProviderInputOracleCloud = () => {
  return (
    <div className="flex items-center gap-x-2">
      <OracleCloudProviderBadge width={25} height={25} />
      <p className="text-sm">Oracle Cloud Infrastructure</p>
    </div>
  );
};

export const CustomProviderInputAlibabaCloud = () => {
  return (
    <div className="flex items-center gap-x-2">
      <AlibabaCloudProviderBadge width={25} height={25} />
      <p className="text-sm">Alibaba Cloud</p>
    </div>
  );
};

export const CustomProviderInputCloudflare = () => {
  return (
    <div className="flex items-center gap-x-2">
      <CloudflareProviderBadge width={25} height={25} />
      <p className="text-sm">Cloudflare</p>
    </div>
  );
};

export const CustomProviderInputOpenStack = () => {
  return (
    <div className="flex items-center gap-x-2">
      <OpenStackProviderBadge width={25} height={25} />
      <p className="text-sm">OpenStack</p>
    </div>
  );
};
