const healthResponse = {
  status: "healthy",
  service: "prowler-ui",
} as const;

export const dynamic = "force-dynamic";

export async function GET() {
  return Response.json(healthResponse, {
    headers: {
      "Cache-Control": "no-store",
    },
  });
}
