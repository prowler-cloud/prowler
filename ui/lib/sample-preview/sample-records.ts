import {
  type FindingComplianceFrameworksResult,
  WATCHLIST_SCOPE,
} from "@/types/compliance-watchlist";
import type { FindingStatus } from "@/types/components";
import { FINDING_TRIAGE_STATUS } from "@/types/findings-triage";

import { SAMPLE_CHECK_DETAILS } from "./sample-check-details";
import {
  SAMPLE_ACCOUNT,
  SAMPLE_CHECKS,
  SAMPLE_REGIONS,
  type SampleCheck,
} from "./sample-dataset";
import { SAMPLE_ID_PREFIX } from "./sample-guards";

export {
  isSampleId,
  SAMPLE_ID_PREFIX,
  SAMPLE_WRITE_MESSAGE,
} from "./sample-guards";

// One record per sample resource and per sample finding, so every drill-down
// (group rows, finding drawer, resource drawer, issue panel) opens something
// concrete. Every id starts with SAMPLE_ID_PREFIX: real ids are UUIDs, so the
// actions tell sample lookups apart without any other state.

export interface SampleResource {
  id: string;
  uid: string;
  name: string;
  region: string;
  service: string;
  type: string;
}

export interface SampleFinding {
  id: string;
  uid: string;
  check: SampleCheck;
  resource: SampleResource;
  status: FindingStatus;
  delta: "new" | null;
}

// Deterministic AWS-looking ids (i-0…, sg-0…): 17 hex digits after the dash.
const hexId = (prefix: string, seed: number, index: number) => {
  const high = Math.imul(seed + index, 2654435761) >>> 0;
  const low = Math.imul(high ^ seed, 2246822519) >>> 0;
  return `${prefix}-0${high.toString(16).padStart(8, "0")}${low.toString(16).padStart(8, "0")}`;
};

const arn = (service: string, region: string, path: string) =>
  `arn:aws:${service}:${region}:${SAMPLE_ACCOUNT.uid}:${path}`;

interface ResourceKind {
  service: string;
  type: string;
  /** Global resources live in one region, as Prowler reports them. */
  global?: boolean;
  name: (index: number, region: string) => string;
  uid: (name: string, region: string) => string;
}

const named =
  (names: string[], fallback: string) =>
  (index: number): string =>
    names[index] ?? `${fallback}-${index + 1}`;

const RESOURCE_KINDS: Record<string, ResourceKind> = {
  s3_bucket: {
    service: "s3",
    type: "AwsS3Bucket",
    name: named(
      [
        "acme-customer-exports",
        "acme-web-assets",
        "acme-partner-uploads",
        "acme-app-logs",
        "acme-terraform-state",
        "acme-data-lake-raw",
        "acme-backups",
        "acme-ml-datasets",
        "acme-cloudtrail-logs",
        "acme-invoices",
        "acme-build-artifacts",
      ],
      "acme-data",
    ),
    uid: (name) => `arn:aws:s3:::${name}`,
  },
  iam_root_account: {
    service: "iam",
    type: "AwsIamUser",
    global: true,
    name: () => "<root_account>",
    uid: () => `arn:aws:iam::${SAMPLE_ACCOUNT.uid}:root`,
  },
  rds_instance: {
    service: "rds",
    type: "AwsRdsDbInstance",
    name: named(["orders-db", "billing-db", "analytics-db"], "app-db"),
    uid: (name, region) => arn("rds", region, `db:${name}`),
  },
  lambda_function: {
    service: "awslambda",
    type: "AwsLambdaFunction",
    name: named(
      ["orders-sync", "invoice-generator", "thumbnailer", "webhook-relay"],
      "worker",
    ),
    uid: (name, region) => arn("lambda", region, `function:${name}`),
  },
  ec2_instance: {
    service: "ec2",
    type: "AwsEc2Instance",
    name: (index) => hexId("i", 0x3f2a9c1, index),
    uid: (name, region) => arn("ec2", region, `instance/${name}`),
  },
  ec2_security_group: {
    service: "ec2",
    type: "AwsEc2SecurityGroup",
    name: (index) => hexId("sg", 0x1b7d42e, index),
    uid: (name, region) => arn("ec2", region, `security-group/${name}`),
  },
  iam_policy: {
    service: "iam",
    type: "AwsIamPolicy",
    global: true,
    name: named(
      ["ci-deployer", "data-pipeline", "support-access"],
      "app-policy",
    ),
    uid: (name) => `arn:aws:iam::${SAMPLE_ACCOUNT.uid}:policy/${name}`,
  },
  cloudtrail_trail: {
    service: "cloudtrail",
    type: "AwsCloudTrailTrail",
    name: () => "management-events",
    uid: (name, region) => arn("cloudtrail", region, `trail/${name}`),
  },
  iam_user: {
    service: "iam",
    type: "AwsIamUser",
    global: true,
    name: named(
      ["maria.lopez", "deploy-bot", "jon.smith", "ana.garcia"],
      "user",
    ),
    uid: (name) => `arn:aws:iam::${SAMPLE_ACCOUNT.uid}:user/${name}`,
  },
  eks_cluster: {
    service: "eks",
    type: "AwsEksCluster",
    name: named(["prod-platform", "staging-platform"], "cluster"),
    uid: (name, region) => arn("eks", region, `cluster/${name}`),
  },
  ebs_volume: {
    service: "ec2",
    type: "AwsEc2Volume",
    name: (index) => hexId("vol", 0x2c4e8a3, index),
    uid: (name, region) => arn("ec2", region, `volume/${name}`),
  },
  iam_access_key: {
    service: "iam",
    type: "AwsIamUser",
    global: true,
    name: named(
      ["deploy-bot", "legacy-etl", "maria.lopez", "backup-agent"],
      "svc",
    ),
    uid: (name) => `arn:aws:iam::${SAMPLE_ACCOUNT.uid}:user/${name}`,
  },
  guardduty_detector: {
    service: "guardduty",
    type: "AwsGuardDutyDetector",
    name: (_index, region) => `detector-${region}`,
    uid: (name, region) => arn("guardduty", region, `detector/${name}`),
  },
  config_recorder: {
    service: "config",
    type: "AwsConfigConfigurationRecorder",
    name: (_index, region) => `default-${region}`,
    uid: (name, region) => arn("config", region, `recorder/${name}`),
  },
  vpc: {
    service: "vpc",
    type: "AwsEc2Vpc",
    name: (index) => hexId("vpc", 0x5e19b07, index),
    uid: (name, region) => arn("ec2", region, `vpc/${name}`),
  },
  kms_key: {
    service: "kms",
    type: "AwsKmsKey",
    name: (index) =>
      `${(0x8f3a2b1c + index * 104729).toString(16)}-4c1d-9e2f-a7b6-3d5e8f0a1b2c`,
    uid: (name, region) => arn("kms", region, `key/${name}`),
  },
  apigateway_rest_api: {
    service: "apigateway",
    type: "AwsApiGatewayRestApi",
    name: named(["public-api", "partner-api", "internal-api"], "api"),
    uid: (name, region) => `arn:aws:apigateway:${region}::/restapis/${name}`,
  },
  sqs_queue: {
    service: "sqs",
    type: "AwsSqsQueue",
    name: named(
      ["orders", "emails", "webhooks", "invoices", "dead-letter"],
      "queue",
    ),
    uid: (name, region) => arn("sqs", region, name),
  },
  cloudwatch_log_group: {
    service: "cloudwatch",
    type: "AwsLogsLogGroup",
    name: () => "cloudtrail/management-events",
    uid: (name, region) => arn("logs", region, `log-group:${name}`),
  },
  aws_account: {
    service: "account",
    type: "Other",
    global: true,
    name: () => SAMPLE_ACCOUNT.uid,
    uid: () => `arn:aws:iam::${SAMPLE_ACCOUNT.uid}:root`,
  },
};

const resourceKind = (type: string): ResourceKind => {
  const kind = RESOURCE_KINDS[type];
  if (!kind) throw new Error(`No sample resource kind for ${type}`);
  return kind;
};

// Checks of one resource type evaluate the same resources, so the pool is as
// large as the widest check of that type (as sample-overview counts them).
const poolSizes = SAMPLE_CHECKS.reduce<Record<string, number>>(
  (sizes, check) => ({
    ...sizes,
    [check.resourceType]: Math.max(
      sizes[check.resourceType] ?? 0,
      check.failed + check.passed,
    ),
  }),
  {},
);

const RESOURCE_POOLS: Record<string, SampleResource[]> = Object.fromEntries(
  Object.entries(poolSizes).map(([type, size]) => {
    const kind = resourceKind(type);
    return [
      type,
      Array.from({ length: size }, (_, index) => {
        const region = kind.global
          ? SAMPLE_REGIONS[0]
          : SAMPLE_REGIONS[index % SAMPLE_REGIONS.length];
        const name = kind.name(index, region);
        return {
          id: `${SAMPLE_ID_PREFIX}resource-${type}-${index + 1}`,
          uid: kind.uid(name, region),
          name,
          region,
          service: kind.service,
          type: kind.type,
        };
      }),
    ];
  }),
);

export const SAMPLE_RESOURCES: SampleResource[] =
  Object.values(RESOURCE_POOLS).flat();

// The first `failed` resources of the pool fail, so checks of one type fail
// on the same resources (the exposed instance also misses IMDSv2).
export const SAMPLE_FINDINGS: SampleFinding[] = SAMPLE_CHECKS.flatMap((check) =>
  RESOURCE_POOLS[check.resourceType]
    .slice(0, check.failed + check.passed)
    .map((resource, index) => ({
      id: `${SAMPLE_ID_PREFIX}finding-${check.checkId}-${index + 1}`,
      uid: `prowler-aws-${check.checkId}-${SAMPLE_ACCOUNT.uid}-${resource.region}-${resource.name}`,
      check,
      resource,
      status: index < check.failed ? "FAIL" : "PASS",
      delta: index < check.newFailed ? "new" : null,
    })),
);

const FINDINGS_BY_ID = new Map(
  SAMPLE_FINDINGS.map((finding) => [finding.id, finding]),
);

export const getSampleFinding = (id: string) => FINDINGS_BY_ID.get(id);

export const failedSampleFindings = (checkId: string) =>
  SAMPLE_FINDINGS.filter(
    (finding) => finding.check.checkId === checkId && finding.status === "FAIL",
  );

// JSON:API documents, shaped like /findings?include=resources,scan.provider.

const fillName = (text: string, name: string) =>
  text.replaceAll("{name}", name);

const findingItem = (finding: SampleFinding) => {
  const { check, resource } = finding;
  const detail = SAMPLE_CHECK_DETAILS[check.checkId];
  return {
    type: "findings",
    id: finding.id,
    attributes: {
      uid: finding.uid,
      check_id: check.checkId,
      status: finding.status,
      status_extended: fillName(
        finding.status === "FAIL" ? detail.fail : detail.pass,
        resource.name,
      ),
      severity: check.severity,
      delta: finding.delta,
      muted: false,
      muted_reason: null,
      first_seen_at: SAMPLE_ACCOUNT.scannedAt,
      updated_at: SAMPLE_ACCOUNT.scannedAt,
      inserted_at: SAMPLE_ACCOUNT.scannedAt,
      triage_status: FINDING_TRIAGE_STATUS.OPEN,
      raw_result: null,
      // Versioned keys, as the API sends them: the drawer strips the version.
      compliance: Object.fromEntries(
        detail.compliance.map(({ framework, version }) => [
          version ? `${framework}-${version}` : framework,
          [],
        ]),
      ),
      check_metadata: {
        checkid: check.checkId,
        checktitle: check.title,
        checktype: [],
        checkaliases: [],
        provider: "aws",
        servicename: check.service,
        subservicename: "",
        severity: check.severity,
        resourcetype: resource.type,
        resourceidtemplate: "",
        resourcegroup: check.resourceGroup,
        description: detail.description,
        risk: detail.risk,
        notes: "",
        relatedurl: "",
        dependson: [],
        relatedto: [],
        categories: [],
        compliance: null,
        remediation: {
          recommendation: { text: detail.recommendation, url: "" },
          code: {
            cli: detail.cli ? fillName(detail.cli, resource.name) : "",
            other: "",
            nativeiac: "",
            terraform: "",
          },
        },
        additionalurls: [],
      },
    },
    relationships: {
      resources: { data: [{ type: "resources" as const, id: resource.id }] },
      scan: { data: { type: "scans", id: SAMPLE_ACCOUNT.scanId } },
    },
  };
};

const resourceItem = (resource: SampleResource) => ({
  type: "resources",
  id: resource.id,
  attributes: {
    uid: resource.uid,
    name: resource.name,
    region: resource.region,
    service: resource.service,
    type: resource.type,
    tags: {},
    details: null,
    metadata: null,
    inserted_at: SAMPLE_ACCOUNT.scannedAt,
    updated_at: SAMPLE_ACCOUNT.scannedAt,
  },
  relationships: {
    provider: { data: { type: "providers", id: SAMPLE_ACCOUNT.providerId } },
  },
});

const SCAN_ITEM = {
  type: "scans",
  id: SAMPLE_ACCOUNT.scanId,
  attributes: {
    name: "Sample scan",
    trigger: "manual",
    state: "completed",
    unique_resource_count: SAMPLE_RESOURCES.length,
    progress: 100,
    duration: 742,
    started_at: SAMPLE_ACCOUNT.scannedAt,
    completed_at: SAMPLE_ACCOUNT.scannedAt,
    inserted_at: SAMPLE_ACCOUNT.scannedAt,
    scheduled_at: null,
  },
  relationships: {
    provider: { data: { type: "providers", id: SAMPLE_ACCOUNT.providerId } },
  },
};

const PROVIDER_ITEM = {
  type: "providers",
  id: SAMPLE_ACCOUNT.providerId,
  attributes: {
    provider: "aws",
    uid: SAMPLE_ACCOUNT.uid,
    alias: SAMPLE_ACCOUNT.alias,
    connection: { connected: true, last_checked_at: SAMPLE_ACCOUNT.scannedAt },
  },
};

export const sampleFindingsDocument = (findings: SampleFinding[]) => {
  const resources = new Map(
    findings.map(({ resource }) => [resource.id, resource]),
  );
  return {
    data: findings.map(findingItem),
    included: [
      ...Array.from(resources.values()).map(resourceItem),
      SCAN_ITEM,
      PROVIDER_ITEM,
    ],
    meta: { version: "v1" },
  };
};

/** Findings with their resource, scan and provider inlined, like the Overview tables. */
export const sampleExpandedFindings = (findings: SampleFinding[]) =>
  findings.map((finding) => ({
    ...findingItem(finding),
    relationships: {
      scan: SCAN_ITEM,
      resource: resourceItem(finding.resource),
      provider: PROVIDER_ITEM,
    },
  }));

/** /findings?include=resources: the issue panel asks for nothing else. */
export const sampleIssueFindingsDocument = (findings: SampleFinding[]) => ({
  data: findings.map(findingItem),
  included: findings.map(({ resource }) => resourceItem(resource)),
});

export const sampleFindingDocument = (finding: SampleFinding) => {
  const { data, ...rest } = sampleFindingsDocument([finding]);
  return { ...rest, data: data[0] };
};

const paginate = <T>(items: T[], page: number, pageSize: number) => ({
  items: items.slice((page - 1) * pageSize, page * pageSize),
  pagination: {
    page,
    pages: Math.max(1, Math.ceil(items.length / pageSize)),
    count: items.length,
  },
});

type SampleFilterParams = Record<string, string | string[] | undefined>;

// Resource-level filters the Findings page sets, matched per sample finding.
const SAMPLE_FINDING_FILTERS: Record<
  string,
  (finding: SampleFinding) => string | null
> = {
  "filter[region__in]": (finding) => finding.resource.region,
  "filter[resource_type__in]": (finding) => finding.resource.type,
  "filter[delta]": (finding) => finding.delta,
  "filter[delta__in]": (finding) => finding.delta,
  "filter[provider_type__in]": () => "aws",
  "filter[provider_id__in]": () => SAMPLE_ACCOUNT.providerId,
  // The date picker sends YYYY-MM-DD: every sample finding is from one scan.
  "filter[inserted_at]": () => SAMPLE_ACCOUNT.scannedAt.slice(0, 10),
};

const MUTED_FILTER = "filter[muted]";

/** The resource-level filters present in a request, as plain strings. */
export const pickSampleFindingFilters = (
  filters: SampleFilterParams,
): Record<string, string> =>
  Object.fromEntries(
    [...Object.keys(SAMPLE_FINDING_FILTERS), MUTED_FILTER].flatMap((key) => {
      const raw = filters[key];
      const value = Array.isArray(raw) ? raw.join(",") : raw;
      // "false" is the page default: only asking for muted findings narrows.
      if (key === MUTED_FILTER && value !== "true") return [];
      return value ? [[key, value]] : [];
    }),
  );

/** Whether a sample finding passes the picked resource-level filters. */
export const matchesSampleFindingFilters = (
  finding: SampleFinding,
  filters: Record<string, string>,
) =>
  // Sample findings are never muted.
  filters[MUTED_FILTER] !== "true" &&
  Object.entries(filters).every(([key, value]) => {
    const field = SAMPLE_FINDING_FILTERS[key];
    if (!field) return true;
    const actual = field(finding);
    return actual !== null && value.split(",").includes(actual);
  });

/** /finding-groups/{check_id}/resources: failed first, like the API's sort. */
export const sampleFindingGroupResources = ({
  checkId,
  page,
  pageSize,
  status,
  search,
  filters = {},
}: {
  checkId: string;
  page: number;
  pageSize: number;
  status?: string;
  search?: string;
  filters?: Record<string, string>;
}) => {
  const findings = SAMPLE_FINDINGS.filter(
    (finding) =>
      finding.check.checkId === checkId &&
      (!status || status.split(",").includes(finding.status)) &&
      matchesSampleFindingFilters(finding, filters) &&
      (!search ||
        finding.resource.name.toLowerCase().includes(search.toLowerCase())),
  );
  const { items, pagination } = paginate(findings, page, pageSize);
  return {
    data: items.map((finding) => ({
      type: "finding-group-resources",
      id: finding.resource.id,
      attributes: {
        finding_id: finding.id,
        finding_uid: finding.uid,
        resource: {
          uid: finding.resource.uid,
          name: finding.resource.name,
          service: finding.resource.service,
          region: finding.resource.region,
          type: finding.resource.type,
          resource_group: finding.check.resourceGroup,
        },
        provider: {
          type: "aws",
          uid: SAMPLE_ACCOUNT.uid,
          alias: SAMPLE_ACCOUNT.alias,
        },
        status: finding.status,
        status_extended: findingItem(finding).attributes.status_extended,
        severity: finding.check.severity,
        delta: finding.delta,
        muted: false,
        first_seen_at: SAMPLE_ACCOUNT.scannedAt,
        last_seen_at: SAMPLE_ACCOUNT.scannedAt,
        triage_status: FINDING_TRIAGE_STATUS.OPEN,
      },
    })),
    meta: { pagination },
  };
};

/** /findings filtered the way the drawers and the issue graph ask. */
export const sampleFindingsQuery = (
  filters: Record<string, string | string[] | undefined>,
) => {
  const value = (key: string) => {
    const raw = filters[key];
    return Array.isArray(raw) ? raw.join(",") : raw;
  };
  const list = (key: string) => value(key)?.split(",");
  const resourceUid = value("filter[resource_uid]");
  const checkIds = list("filter[check_id]") ?? list("filter[check_id__in]");
  const statuses = list("filter[status]") ?? list("filter[status__in]");
  const regions = list("filter[region__in]");
  const uids = list("filter[uid__in]");
  return SAMPLE_FINDINGS.filter(
    (finding) =>
      (!resourceUid || finding.resource.uid === resourceUid) &&
      (!checkIds || checkIds.includes(finding.check.checkId)) &&
      (!statuses || statuses.includes(finding.status)) &&
      (!regions || regions.includes(finding.resource.region)) &&
      (!uids || uids.includes(finding.uid)),
  );
};

/** The resource drawer's data: the resource's failed findings, no API calls. */
export const sampleResourceDrawerData = (resourceId: string, query = "") => {
  const search = query.trim().toLowerCase();
  const findings = SAMPLE_FINDINGS.filter(
    (finding) =>
      finding.resource.id === resourceId &&
      finding.status === "FAIL" &&
      (!search ||
        `${finding.check.checkId} ${finding.check.title}`
          .toLowerCase()
          .includes(search)),
  );
  return {
    findings: findings.map(findingItem),
    findingsMeta: {
      pagination: { page: 1, pages: 1, count: findings.length },
      version: "v1",
    },
    providerOrg: null,
    resourceTags: {},
  };
};

/** Whether a request is scoped to the sample scan. */
export const isSampleScanFilter = (
  filters: Record<string, string | string[] | undefined> | undefined,
) =>
  filters?.["filter[scan]"] === SAMPLE_ACCOUNT.scanId ||
  // Compliance requirements ask by scan list, with the sample scan alone.
  filters?.["filter[scan__in]"] === SAMPLE_ACCOUNT.scanId;

/** /findings/{id}/compliance-frameworks: the check's frameworks, all watched. */
export const sampleComplianceFrameworks = (
  findingId: string,
): FindingComplianceFrameworksResult => {
  const finding = getSampleFinding(findingId);
  const frameworks = finding
    ? SAMPLE_CHECK_DETAILS[finding.check.checkId].compliance
    : [];
  return {
    frameworks: frameworks.map((framework) => ({
      ...framework,
      id: `${SAMPLE_ID_PREFIX}${framework.complianceId}`,
      providerType: "aws",
      scope: WATCHLIST_SCOPE.PROVIDER,
      inWatchlist: true,
    })),
    unavailable: false,
  };
};

// CloudTrail names per resource type: how it was created, then last changed.
const SAMPLE_EVENT_NAMES: Record<string, [create: string, change: string]> = {
  AwsS3Bucket: ["CreateBucket", "PutBucketPolicy"],
  AwsEc2Instance: ["RunInstances", "ModifyInstanceMetadataOptions"],
  AwsEc2SecurityGroup: ["CreateSecurityGroup", "AuthorizeSecurityGroupIngress"],
  AwsEc2Volume: ["CreateVolume", "AttachVolume"],
  AwsIamUser: ["CreateUser", "CreateAccessKey"],
  AwsIamPolicy: ["CreatePolicy", "CreatePolicyVersion"],
  AwsRdsDbInstance: ["CreateDBInstance", "ModifyDBInstance"],
  AwsLambdaFunction: [
    "CreateFunction20150331",
    "UpdateFunctionConfiguration20150331v2",
  ],
  AwsEksCluster: ["CreateCluster", "UpdateClusterConfig"],
  AwsKmsKey: ["CreateKey", "DisableKeyRotation"],
  AwsSqsQueue: ["CreateQueue", "SetQueueAttributes"],
};

const DAY_MS = 24 * 60 * 60 * 1000;
const daysBeforeScan = (days: number) =>
  new Date(Date.parse(SAMPLE_ACCOUNT.scannedAt) - days * DAY_MS).toISOString();

/** /resources/{id}/events: two CloudTrail write events for the resource. */
export const sampleResourceEvents = (resourceId: string) => {
  const resource = SAMPLE_RESOURCES.find(({ id }) => id === resourceId);
  const names = resource && SAMPLE_EVENT_NAMES[resource.type];
  if (!resource || !names) return [];
  const event = (
    index: number,
    eventName: string,
    actor: string,
    userAgent: string,
    days: number,
  ) => ({
    type: "resource-events" as const,
    id: `${resource.id}-event-${index}`,
    attributes: {
      event_time: daysBeforeScan(days),
      event_name: eventName,
      event_source: `${resource.service === "awslambda" ? "lambda" : resource.service}.amazonaws.com`,
      actor,
      actor_uid: `arn:aws:iam::${SAMPLE_ACCOUNT.uid}:user/${actor}`,
      actor_type: "IAMUser",
      source_ip_address: index === 1 ? "203.0.113.24" : "198.51.100.7",
      user_agent: userAgent,
      request_data: null,
      response_data: null,
      error_code: null,
      error_message: null,
    },
  });
  return [
    event(2, names[1], "maria.lopez", "AWS Internal", 5),
    event(
      1,
      names[0],
      "deploy-bot",
      "APN/1.0 HashiCorp/1.0 Terraform/1.9.5",
      143,
    ),
  ];
};
