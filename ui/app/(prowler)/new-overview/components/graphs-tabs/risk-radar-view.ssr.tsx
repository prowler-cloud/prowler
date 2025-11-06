import { RadarChart } from "@/components/graphs/radar-chart";

// Helper to simulate loading delay
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// Mock data - replace with actual API call
const mockRadarData = [
  { category: "Amazon Kinesis", value: 45, change: 2 },
  { category: "Amazon MQ", value: 38, change: -1 },
  { category: "AWS Lambda", value: 52, change: 5 },
  { category: "Amazon RDS", value: 41, change: 3 },
  { category: "Amazon S3", value: 48, change: -2 },
  { category: "Amazon VPC", value: 55, change: 4 },
];

export async function RiskRadarViewSSR() {
  // TODO: Call server action to fetch radar chart data
  await delay(3000); // Simulating server action fetch time

  return (
    <div className="w-full flex-1 overflow-hidden">
      <RadarChart data={mockRadarData} height={460} />
    </div>
  );
}
