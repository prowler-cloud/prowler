import { NextResponse } from "next/server";

import { createCache, getCurrentUserId } from "@/lib/lighthouse/cache";

export async function POST() {
  try {
    // Get the current user ID
    const userId = await getCurrentUserId();

    // Initialize the cache
    await createCache(userId);

    return NextResponse.json({
      success: true,
      message: "Cache created successfully",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Error creating cache:", error);

    return NextResponse.json(
      {
        success: false,
        message: `Failed to create cache: ${error instanceof Error ? error.message : "Unknown error"}`,
      },
      { status: 500 },
    );
  }
}
