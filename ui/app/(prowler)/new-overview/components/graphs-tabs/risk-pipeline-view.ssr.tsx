import { SankeyChart } from "@/components/graphs/sankey-chart";

// Helper to simulate loading delay
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// Mock data - replace with actual API call
const mockSankeyData = {
  nodes: [
    { name: "AWS" },
    { name: "Azure" },
    { name: "Google Cloud" },
    { name: "Critical" },
    { name: "High" },
    { name: "Medium" },
    { name: "Low" },
  ],
  links: [
    { source: 0, target: 3, value: 45 },
    { source: 0, target: 4, value: 120 },
    { source: 0, target: 5, value: 85 },
    { source: 1, target: 3, value: 28 },
    { source: 1, target: 4, value: 95 },
    { source: 1, target: 5, value: 62 },
    { source: 2, target: 3, value: 18 },
    { source: 2, target: 4, value: 72 },
    { source: 2, target: 5, value: 48 },
  ],
};

export async function RiskPipelineViewSSR() {
  // TODO: Call server action to fetch sankey chart data
  await delay(3000); // Simulating server action fetch time

  return (
    <div className="w-full flex-1 overflow-hidden">
      <SankeyChart data={mockSankeyData} height={460} />
    </div>
  );
}
