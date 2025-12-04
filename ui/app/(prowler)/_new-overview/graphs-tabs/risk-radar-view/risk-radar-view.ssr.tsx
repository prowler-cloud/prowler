import type { RadarDataPoint } from "@/components/graphs/types";

import { RiskRadarViewClient } from "./risk-radar-view-client";

// Mock data - replace with actual API call
const mockRadarData: RadarDataPoint[] = [
  {
    category: "Amazon Kinesis",
    value: 45,
    change: 2,
    severityData: [
      { name: "Critical", value: 32 },
      { name: "High", value: 65 },
      { name: "Medium", value: 18 },
      { name: "Low", value: 54 },
      { name: "Info", value: 1 },
    ],
  },
  {
    category: "Amazon MQ",
    value: 38,
    change: -1,
    severityData: [
      { name: "Critical", value: 28 },
      { name: "High", value: 58 },
      { name: "Medium", value: 16 },
      { name: "Low", value: 48 },
      { name: "Info", value: 2 },
    ],
  },
  {
    category: "AWS Lambda",
    value: 52,
    change: 5,
    severityData: [
      { name: "Critical", value: 40 },
      { name: "High", value: 72 },
      { name: "Medium", value: 20 },
      { name: "Low", value: 60 },
      { name: "Info", value: 3 },
    ],
  },
  {
    category: "Amazon RDS",
    value: 41,
    change: 3,
    severityData: [
      { name: "Critical", value: 30 },
      { name: "High", value: 60 },
      { name: "Medium", value: 17 },
      { name: "Low", value: 50 },
      { name: "Info", value: 1 },
    ],
  },
  {
    category: "Amazon S3",
    value: 48,
    change: -2,
    severityData: [
      { name: "Critical", value: 36 },
      { name: "High", value: 68 },
      { name: "Medium", value: 19 },
      { name: "Low", value: 56 },
      { name: "Info", value: 2 },
    ],
  },
  {
    category: "Amazon VPC",
    value: 55,
    change: 4,
    severityData: [
      { name: "Critical", value: 42 },
      { name: "High", value: 75 },
      { name: "Medium", value: 21 },
      { name: "Low", value: 62 },
      { name: "Info", value: 3 },
    ],
  },
];

// Helper to simulate loading delay
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function RiskRadarViewSSR() {
  // TODO: Call server action to fetch radar chart data
  await delay(3000); // Simulating server action fetch time

  return <RiskRadarViewClient data={mockRadarData} />;
}
