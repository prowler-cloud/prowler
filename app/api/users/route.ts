import { NextResponse } from "next/server";

import data from "../../../dataUsers.json";

export async function GET() {
  // Simulate fetching data with a delay
  await new Promise((resolve) => setTimeout(resolve, 2000));

  return NextResponse.json({ users: data });
}
