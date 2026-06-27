import {
  AlertTriangle,
  Bot,
  Box,
  Braces,
  CircleAlert,
  FileKey2,
  Globe2,
  Info,
  KeyRound,
  Route,
  Server,
  Shield,
  ShieldCheck,
  Siren,
  Tags,
  UserCog,
  Users,
  Waypoints,
} from "lucide-react";
import type { ElementType } from "react";

import {
  AlibabaCloudProviderBadge,
  AWSProviderBadge,
  AzureProviderBadge,
  CloudflareProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  GoogleWorkspaceProviderBadge,
  IacProviderBadge,
  ImageProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
  MongoDBAtlasProviderBadge,
  OktaProviderBadge,
  OpenStackProviderBadge,
  OracleCloudProviderBadge,
  VercelProviderBadge,
} from "@/components/icons/providers-badge";
import {
  AmazonEC2Icon,
  AmazonRDSIcon,
  AmazonS3Icon,
  AmazonVPCIcon,
  AWSIAMIcon,
  AWSLambdaIcon,
} from "@/components/icons/services/IconServices";
import type { GraphNode, GraphNodePropertyValue } from "@/types/attack-paths";

import { formatNodeLabel } from "./format";

export const NODE_CATEGORY = {
  FINDING: "finding",
  INTERNET: "internet",
  ACCOUNT: "account",
  STORAGE: "storage",
  NETWORK: "network",
  COMPUTE: "compute",
  IDENTITY: "identity",
  SECRET: "secret",
  MISC: "misc",
} as const;

export type NodeCategory = (typeof NODE_CATEGORY)[keyof typeof NODE_CATEGORY];

interface KnownNodeVisualMapping {
  category: NodeCategory;
  description: string;
  Icon: ElementType;
}

export interface NodeVisual extends KnownNodeVisualMapping {
  displayName: string;
  fallbackUsed: boolean;
}

const KNOWN_NODE_VISUALS = {
  awsaccount: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "AWS Account",
    Icon: AWSProviderBadge,
  },
  azureaccount: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Azure Account",
    Icon: AzureProviderBadge,
  },
  azuretenant: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Azure Tenant",
    Icon: AzureProviderBadge,
  },
  gcpaccount: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Google Cloud Account",
    Icon: GCPProviderBadge,
  },
  gcpproject: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Google Cloud Project",
    Icon: GCPProviderBadge,
  },
  googlecloudaccount: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Google Cloud Account",
    Icon: GCPProviderBadge,
  },
  kubernetescluster: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Kubernetes Cluster",
    Icon: KS8ProviderBadge,
  },
  k8scluster: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Kubernetes Cluster",
    Icon: KS8ProviderBadge,
  },
  githubaccount: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "GitHub Account",
    Icon: GitHubProviderBadge,
  },
  githuborganization: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "GitHub Organization",
    Icon: GitHubProviderBadge,
  },
  m365tenant: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Microsoft 365 Tenant",
    Icon: M365ProviderBadge,
  },
  googleworkspace: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Google Workspace",
    Icon: GoogleWorkspaceProviderBadge,
  },
  iac: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Infrastructure as Code",
    Icon: IacProviderBadge,
  },
  containerregistry: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Container Registry",
    Icon: ImageProviderBadge,
  },
  oraclecloudaccount: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Oracle Cloud Account",
    Icon: OracleCloudProviderBadge,
  },
  mongodbatlas: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "MongoDB Atlas",
    Icon: MongoDBAtlasProviderBadge,
  },
  alibabacloudaccount: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Alibaba Cloud Account",
    Icon: AlibabaCloudProviderBadge,
  },
  cloudflareaccount: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Cloudflare Account",
    Icon: CloudflareProviderBadge,
  },
  openstackaccount: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "OpenStack Account",
    Icon: OpenStackProviderBadge,
  },
  vercelaccount: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Vercel Account",
    Icon: VercelProviderBadge,
  },
  oktaaccount: {
    category: NODE_CATEGORY.ACCOUNT,
    description: "Okta Account",
    Icon: OktaProviderBadge,
  },
  s3bucket: {
    category: NODE_CATEGORY.STORAGE,
    description: "S3 Bucket",
    Icon: AmazonS3Icon,
  },
  s3: {
    category: NODE_CATEGORY.STORAGE,
    description: "S3",
    Icon: AmazonS3Icon,
  },
  vpc: {
    category: NODE_CATEGORY.NETWORK,
    description: "VPC",
    Icon: AmazonVPCIcon,
  },
  subnet: {
    category: NODE_CATEGORY.NETWORK,
    description: "Subnet",
    Icon: Waypoints,
  },
  securitygroup: {
    category: NODE_CATEGORY.NETWORK,
    description: "Security Group",
    Icon: Shield,
  },
  ec2securitygroup: {
    category: NODE_CATEGORY.NETWORK,
    description: "EC2 Security Group",
    Icon: Shield,
  },
  ippermissioninbound: {
    category: NODE_CATEGORY.NETWORK,
    description: "Inbound IP Permission",
    Icon: Shield,
  },
  iprange: {
    category: NODE_CATEGORY.NETWORK,
    description: "IP Range",
    Icon: Globe2,
  },
  elasticipaddress: {
    category: NODE_CATEGORY.NETWORK,
    description: "Elastic IP Address",
    Icon: Globe2,
  },
  ec2privateip: {
    category: NODE_CATEGORY.NETWORK,
    description: "EC2 Private IP",
    Icon: Waypoints,
  },
  networkinterface: {
    category: NODE_CATEGORY.NETWORK,
    description: "Network Interface",
    Icon: Waypoints,
  },
  internetgateway: {
    category: NODE_CATEGORY.NETWORK,
    description: "Internet Gateway",
    Icon: Route,
  },
  defaultgateway: {
    category: NODE_CATEGORY.NETWORK,
    description: "Default Gateway",
    Icon: Route,
  },
  loadbalancer: {
    category: NODE_CATEGORY.NETWORK,
    description: "Load Balancer",
    Icon: Route,
  },
  loadbalancerv2: {
    category: NODE_CATEGORY.NETWORK,
    description: "Load Balancer V2",
    Icon: Route,
  },
  elblistener: {
    category: NODE_CATEGORY.NETWORK,
    description: "ELB Listener",
    Icon: Route,
  },
  elbv2listener: {
    category: NODE_CATEGORY.NETWORK,
    description: "ELB V2 Listener",
    Icon: Route,
  },
  ec2instance: {
    category: NODE_CATEGORY.COMPUTE,
    description: "EC2 Instance",
    Icon: AmazonEC2Icon,
  },
  launchtemplate: {
    category: NODE_CATEGORY.COMPUTE,
    description: "Launch Template",
    Icon: Server,
  },
  awslambda: {
    category: NODE_CATEGORY.COMPUTE,
    description: "AWS Lambda",
    Icon: AWSLambdaIcon,
  },
  awssagemakernotebookinstance: {
    category: NODE_CATEGORY.COMPUTE,
    description: "SageMaker Notebook Instance",
    Icon: Bot,
  },
  virtualmachine: {
    category: NODE_CATEGORY.COMPUTE,
    description: "Virtual Machine",
    Icon: AmazonEC2Icon,
  },
  rdsinstance: {
    category: NODE_CATEGORY.STORAGE,
    description: "RDS Instance",
    Icon: AmazonRDSIcon,
  },
  compute: {
    category: NODE_CATEGORY.COMPUTE,
    description: "Compute",
    Icon: Server,
  },
  nic: {
    category: NODE_CATEGORY.COMPUTE,
    description: "NIC",
    Icon: Server,
  },
  iamuser: {
    category: NODE_CATEGORY.IDENTITY,
    description: "IAM User",
    Icon: AWSIAMIcon,
  },
  awsuser: {
    category: NODE_CATEGORY.IDENTITY,
    description: "AWS User",
    Icon: UserCog,
  },
  awsgroup: {
    category: NODE_CATEGORY.IDENTITY,
    description: "AWS Group",
    Icon: Users,
  },
  awsprincipal: {
    category: NODE_CATEGORY.IDENTITY,
    description: "AWS Principal",
    Icon: ShieldCheck,
  },
  iamrole: {
    category: NODE_CATEGORY.IDENTITY,
    description: "IAM Role",
    Icon: AWSIAMIcon,
  },
  awsrole: {
    category: NODE_CATEGORY.IDENTITY,
    description: "AWS Role",
    Icon: ShieldCheck,
  },
  permissionrole: {
    category: NODE_CATEGORY.IDENTITY,
    description: "Permission Role",
    Icon: ShieldCheck,
  },
  awsmanagedpolicy: {
    category: NODE_CATEGORY.IDENTITY,
    description: "AWS Managed Policy",
    Icon: FileKey2,
  },
  awspolicy: {
    category: NODE_CATEGORY.IDENTITY,
    description: "AWS Policy",
    Icon: FileKey2,
  },
  policy: {
    category: NODE_CATEGORY.IDENTITY,
    description: "Policy",
    Icon: FileKey2,
  },
  awspolicystatement: {
    category: NODE_CATEGORY.IDENTITY,
    description: "AWS Policy Statement",
    Icon: Braces,
  },
  policystatement: {
    category: NODE_CATEGORY.IDENTITY,
    description: "Policy Statement",
    Icon: Braces,
  },
  accesskey: {
    category: NODE_CATEGORY.SECRET,
    description: "Access Key",
    Icon: KeyRound,
  },
  secret: {
    category: NODE_CATEGORY.SECRET,
    description: "Secret",
    Icon: KeyRound,
  },
  serviceaccount: {
    category: NODE_CATEGORY.IDENTITY,
    description: "Service Account",
    Icon: Bot,
  },
  awstag: {
    category: NODE_CATEGORY.MISC,
    description: "AWS Tag",
    Icon: Tags,
  },
} as const satisfies Record<string, KnownNodeVisualMapping>;

type KnownNodeLabel = keyof typeof KNOWN_NODE_VISUALS;

const normalizeLabel = (label: string): string =>
  label.toLowerCase().replace(/[^a-z0-9]/g, "");

const isKnownNodeLabel = (label: string): label is KnownNodeLabel =>
  label in KNOWN_NODE_VISUALS;

const isFindingLabel = (label: string): boolean =>
  normalizeLabel(label).includes("finding");

const isInternetLabel = (label: string): boolean =>
  normalizeLabel(label) === "internet";

const FINDING_SEVERITY = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "info",
  INFORMATIONAL: "informational",
} as const;

type FindingSeverity = (typeof FINDING_SEVERITY)[keyof typeof FINDING_SEVERITY];

const FINDING_SEVERITY_ICONS = {
  [FINDING_SEVERITY.CRITICAL]: Siren,
  [FINDING_SEVERITY.HIGH]: AlertTriangle,
  [FINDING_SEVERITY.MEDIUM]: CircleAlert,
  [FINDING_SEVERITY.LOW]: Info,
  [FINDING_SEVERITY.INFO]: Info,
  [FINDING_SEVERITY.INFORMATIONAL]: Info,
} as const satisfies Record<FindingSeverity, ElementType>;

const stringifyProperty = (
  value: GraphNodePropertyValue,
): string | undefined => {
  if (value === null || value === undefined) return undefined;
  if (Array.isArray(value)) return value.join(", ");
  return String(value);
};

const firstDefinedProperty = (
  node: GraphNode,
  keys: string[],
): string | undefined => {
  for (const key of keys) {
    const value = stringifyProperty(node.properties[key]);
    if (value) return value;
  }

  return undefined;
};

const getPrimaryFormattedLabel = (node: GraphNode): string => {
  const primaryLabel = node.labels[0];
  if (!primaryLabel) return "Unknown";
  return formatNodeLabel(primaryLabel.replace(/[_-]/g, " "));
};

const resolveDisplayName = (node: GraphNode): string =>
  firstDefinedProperty(node, ["name", "display_name", "title", "id"]) ??
  getPrimaryFormattedLabel(node);

const resolveFindingDisplayName = (node: GraphNode): string =>
  firstDefinedProperty(node, ["check_title", "title", "name", "id"]) ??
  getPrimaryFormattedLabel(node);

const resolveFindingSeverity = (
  node: GraphNode,
): FindingSeverity | undefined => {
  const severity = firstDefinedProperty(node, ["severity"]);
  if (!severity) return undefined;

  const normalizedSeverity = severity.toLowerCase();
  return normalizedSeverity in FINDING_SEVERITY_ICONS
    ? (normalizedSeverity as FindingSeverity)
    : undefined;
};

const resolveFindingIcon = (node: GraphNode): ElementType => {
  const severity = resolveFindingSeverity(node);
  return severity ? FINDING_SEVERITY_ICONS[severity] : AlertTriangle;
};

const resolveKnownMapping = (
  labels: string[],
): KnownNodeVisualMapping | undefined => {
  for (const label of labels) {
    const normalizedLabel = normalizeLabel(label);
    if (isKnownNodeLabel(normalizedLabel)) {
      return KNOWN_NODE_VISUALS[normalizedLabel];
    }
  }

  return undefined;
};

export const resolveNodeVisual = (node: GraphNode): NodeVisual => {
  if (node.labels.some(isFindingLabel)) {
    return {
      category: NODE_CATEGORY.FINDING,
      displayName: resolveFindingDisplayName(node),
      description: "Prowler Finding",
      Icon: resolveFindingIcon(node),
      fallbackUsed: false,
    };
  }

  if (node.labels.some(isInternetLabel)) {
    return {
      category: NODE_CATEGORY.INTERNET,
      displayName: "Internet",
      description: "Internet",
      Icon: Globe2,
      fallbackUsed: false,
    };
  }

  const knownMapping = resolveKnownMapping(node.labels);
  if (knownMapping) {
    return {
      ...knownMapping,
      displayName: resolveDisplayName(node),
      fallbackUsed: false,
    };
  }

  const fallbackLabel = getPrimaryFormattedLabel(node);

  return {
    category: NODE_CATEGORY.MISC,
    displayName: resolveDisplayName(node),
    description: fallbackLabel,
    Icon: Box,
    fallbackUsed: true,
  };
};
