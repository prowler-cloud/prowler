export const dynamic = "force-dynamic";

export async function GET() {
  const body = {
    status: "pass",
    version: "1",
    releaseId: process.env.NEXT_PUBLIC_PROWLER_RELEASE_VERSION || "unknown",
    serviceId: "prowler-ui",
    description: "Prowler UI",
  };

  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/health+json",
      "Cache-Control": "no-store",
    },
  });
}
