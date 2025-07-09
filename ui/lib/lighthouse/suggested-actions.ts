export interface SuggestedAction {
  title: string;
  label: string;
  action: string;
  questionRef?: string;
}

export const suggestedActions: SuggestedAction[] = [
  {
    title: "Are there any exposed S3",
    label: "buckets in my AWS accounts?",
    action: "List exposed S3 buckets in my AWS accounts",
    questionRef: "1",
  },
  {
    title: "What is the risk of having",
    label: "RDS databases unencrypted?",
    action: "What is the risk of having RDS databases unencrypted?",
    questionRef: "2",
  },
  {
    title: "What is the CIS 1.10 compliance status",
    label: "of my Kubernetes cluster?",
    action: "What is the CIS 1.10 compliance status of my Kubernetes cluster?",
    questionRef: "3",
  },
  {
    title: "List my highest privileged",
    label: "AWS IAM users with full admin access?",
    action: "List my highest privileged AWS IAM users with full admin access",
    questionRef: "4",
  },
];
