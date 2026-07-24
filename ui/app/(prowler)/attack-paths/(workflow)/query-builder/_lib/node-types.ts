const normalizeNodeLabel = (label: string): string =>
  label.toLowerCase().replace(/[^a-z0-9]/g, "");

export const isProwlerFindingLabel = (label: string): boolean =>
  normalizeNodeLabel(label) === "prowlerfinding";

export const isProwlerFindingNode = (labels: string[]): boolean =>
  labels.some(isProwlerFindingLabel);
