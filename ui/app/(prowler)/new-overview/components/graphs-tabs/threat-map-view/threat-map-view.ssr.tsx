import { ThreatMap } from "@/components/graphs/threat-map";

// Mock data - replace with actual API call
const mockThreatMapData = {
  locations: [
    {
      id: "us-east-1",
      name: "US East-1",
      region: "North America",
      coordinates: [-75.1551, 40.2206] as [number, number],
      totalFindings: 455,
      riskLevel: "critical" as const,
      severityData: [
        { name: "Critical", value: 432 },
        { name: "High", value: 1232 },
        { name: "Medium", value: 221 },
        { name: "Low", value: 543 },
        { name: "Info", value: 10 },
      ],
      change: 5,
    },
    {
      id: "eu-west-1",
      name: "EU West-1",
      region: "Europe",
      coordinates: [-6.2597, 53.3498] as [number, number],
      totalFindings: 320,
      riskLevel: "high" as const,
      severityData: [
        { name: "Critical", value: 200 },
        { name: "High", value: 900 },
        { name: "Medium", value: 180 },
        { name: "Low", value: 400 },
        { name: "Info", value: 15 },
      ],
      change: -2,
    },
    {
      id: "ap-southeast-1",
      name: "AP Southeast-1",
      region: "Asia Pacific",
      coordinates: [103.8198, 1.3521] as [number, number],
      totalFindings: 280,
      riskLevel: "high" as const,
      severityData: [
        { name: "Critical", value: 150 },
        { name: "High", value: 800 },
        { name: "Medium", value: 160 },
        { name: "Low", value: 350 },
        { name: "Info", value: 8 },
      ],
      change: 3,
    },
    {
      id: "ca-central-1",
      name: "CA Central-1",
      region: "North America",
      coordinates: [-95.7129, 56.1304] as [number, number],
      totalFindings: 190,
      riskLevel: "high" as const,
      severityData: [
        { name: "Critical", value: 100 },
        { name: "High", value: 600 },
        { name: "Medium", value: 120 },
        { name: "Low", value: 280 },
        { name: "Info", value: 5 },
      ],
      change: 1,
    },
    {
      id: "ap-northeast-1",
      name: "AP Northeast-1",
      region: "Asia Pacific",
      coordinates: [139.6917, 35.6895] as [number, number],
      totalFindings: 240,
      riskLevel: "high" as const,
      severityData: [
        { name: "Critical", value: 120 },
        { name: "High", value: 700 },
        { name: "Medium", value: 140 },
        { name: "Low", value: 320 },
        { name: "Info", value: 12 },
      ],
      change: 4,
    },
  ],
  regions: ["North America", "Europe", "Asia Pacific"],
};

export async function ThreatMapViewSSR() {
  // TODO: Call server action to fetch threat map data

  return (
    <div className="w-full flex-1 overflow-hidden">
      <ThreatMap data={mockThreatMapData} height={350} />
    </div>
  );
}
