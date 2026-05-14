const healthResponse = {
  status: "healthy",
  service: "prowler-ui",
} as const;

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  return Response.json(healthResponse);
}
