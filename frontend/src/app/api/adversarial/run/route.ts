import { NextResponse } from "next/server";

// Proxy to the backend adversarial runner instead of spawning a local process.
// The backend endpoint is restricted to local development environments.
const BACKEND_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "/api/backend";

export async function POST() {
  try {
    const url = BACKEND_URL.startsWith("http")
      ? `${BACKEND_URL}/api/adversarial/run`
      : `${BACKEND_URL}/adversarial/run`;

    const response = await fetch(url, { method: "POST" });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return NextResponse.json(
        {
          error:
            errorData?.error?.message ||
            "Adversarial runner endpoint not available on backend",
          code: errorData?.error?.code || "BACKEND_ERROR",
        },
        { status: response.status || 503 }
      );
    }

    const data = await response.json();
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json(
      {
        error: (error instanceof Error ? error.message : "") || "Failed to run adversarial scenarios",
        code: "RUN_ERROR",
      },
      { status: 500 }
    );
  }
}