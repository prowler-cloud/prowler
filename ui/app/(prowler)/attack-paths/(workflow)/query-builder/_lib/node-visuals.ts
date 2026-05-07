import {
  AlertTriangle,
  Box,
  Globe2,
  KeyRound,
  Network,
  Server,
  UserRound,
} from "lucide-react";
import type { ElementType } from "react";

import {
  AmazonEC2Icon,
  AmazonS3Icon,
  AmazonVPCIcon,
  AWSAccountIcon,
  AWSIAMIcon,
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
    Icon: AWSAccountIcon,
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
    Icon: Network,
  },
  securitygroup: {
    category: NODE_CATEGORY.NETWORK,
    description: "Security Group",
    Icon: Network,
  },
  internetgateway: {
    category: NODE_CATEGORY.NETWORK,
    description: "Internet Gateway",
    Icon: Globe2,
  },
  defaultgateway: {
    category: NODE_CATEGORY.NETWORK,
    description: "Default Gateway",
    Icon: Globe2,
  },
  ec2instance: {
    category: NODE_CATEGORY.COMPUTE,
    description: "EC2 Instance",
    Icon: AmazonEC2Icon,
  },
  virtualmachine: {
    category: NODE_CATEGORY.COMPUTE,
    description: "Virtual Machine",
    Icon: AmazonEC2Icon,
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
  iamrole: {
    category: NODE_CATEGORY.IDENTITY,
    description: "IAM Role",
    Icon: AWSIAMIcon,
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
    Icon: UserRound,
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
      Icon: AlertTriangle,
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
