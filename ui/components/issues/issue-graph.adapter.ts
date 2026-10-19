import { AttackPathView } from "@/lib/attack-paths/group-graph";
import { GraphEdge, GraphNode } from "@/types/attack-paths";
import { IssueAttributes, IssueFinding } from "@/types/issues";

/** Resources drawn before the rest are left to the list below the graph. */
export const GRAPH_RESOURCE_LIMIT = 12;

// shortcut: covers the resource kinds the issue patterns fold today; anything
// else draws with the renderer's generic icon. Extend when a pattern adds one.
const RESOURCE_LABELS: [RegExp, string][] = [
  [/^arn:aws:s3:/, "S3Bucket"],
  [/^arn:aws:iam::[^:]*:role\//, "AWSRole"],
  [/^arn:aws:iam::[^:]*:user\//, "AWSUser"],
  [/^arn:aws:iam::[^:]*:root$/, "AWSAccount"],
  [/^arn:aws:ec2:.*:instance\//, "EC2Instance"],
  [/^arn:aws:ec2:.*:security-group\//, "EC2SecurityGroup"],
  [/^arn:aws:lambda:/, "AWSLambda"],
  [/^arn:aws:rds:/, "RDSInstance"],
  [/^arn:aws:secretsmanager:/, "Secret"],
  [/\/virtualMachines\//i, "VirtualMachine"],
];

const resourceLabel = (uid: string) =>
  RESOURCE_LABELS.find(([pattern]) => pattern.test(uid))?.[1] ?? "Resource";

/** The last path or ARN segment: what an operator calls the resource. */
const shortName = (uid: string) =>
  uid.split(/[/:]/).filter(Boolean).pop() ?? uid;

/** Folded findings and supporting evidence associate checks with resources, not attack paths. */
export const buildIssueGraph = (
  issue: IssueAttributes,
  resourceUids: string[],
  findings: IssueFinding[] = [],
): AttackPathView => {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const evidence = Object.values(issue.legs ?? {})
    .flatMap((leg) => leg?.evidence ?? [])
    .map((line) => {
      const [checkId, uid] = line.split(" · ");
      return { line, checkId, uid };
    })
    .filter(({ checkId, uid }) => checkId && uid);
  const evidenceResources = new Set(evidence.map(({ uid }) => uid));
  const findingResources = new Set(
    findings.map(({ resourceUid }) => resourceUid),
  );
  const resources = [
    ...resourceUids.filter((uid) => findingResources.has(uid)),
    ...resourceUids.filter(
      (uid) => !findingResources.has(uid) && evidenceResources.has(uid),
    ),
    ...resourceUids.filter(
      (uid) => !findingResources.has(uid) && !evidenceResources.has(uid),
    ),
  ].slice(0, GRAPH_RESOURCE_LIMIT);
  const resourceId = (uid: string) => `resource:${uid}`;

  resources.forEach((uid) => {
    nodes.push({
      id: resourceId(uid),
      labels: [resourceLabel(uid)],
      properties: { id: uid, name: shortName(uid) },
    });
  });

  const shown = new Set(resources);
  const seen = new Set<string>();
  const addFinding = (
    uid: string,
    checkId: string,
    properties: GraphNode["properties"],
  ) => {
    const line = `${checkId} · ${uid}`;
    if (!shown.has(uid) || seen.has(line)) return;
    seen.add(line);
    const id = `finding:${line}`;
    nodes.push({
      id,
      labels: ["ProwlerFinding"],
      properties: {
        id,
        check_id: checkId,
        resource_uid: uid,
        ...properties,
      },
    });
    edges.push({
      id: `${uid}->${id}`,
      source: resourceId(uid),
      target: id,
      type: "HAS_FINDING",
    });
  };

  findings.forEach(({ id, checkId, checkTitle, severity, resourceUid }) =>
    addFinding(resourceUid, checkId, {
      finding_id: id,
      check_title: checkTitle,
      severity,
    }),
  );
  evidence.forEach(({ checkId, uid }) =>
    addFinding(uid, checkId, { check_title: checkId }),
  );

  return { nodes, edges, groupMembers: new Map() };
};
