import { NextResponse } from "next/server";

// Use the Next.js rewrite proxy to avoid CORS
// The backend URL is configured via environment or defaults to localhost:8000
const BACKEND_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "/api/backend";

export async function GET() {
  try {
    // The backend runner writes reports to backend/reports/adversarial_report.json
    // We'll read from there or run the runner if needed
    const url = BACKEND_URL.startsWith("http")
      ? `${BACKEND_URL}/api/adversarial/report`
      : `${BACKEND_URL}/adversarial/report`;

    const response = await fetch(url, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
      cache: "no-store",
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return NextResponse.json(
        {
          error:
            errorData?.error?.message ||
            "Adversarial report endpoint not available on backend",
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
        error: (error instanceof Error ? error.message : "") || "Failed to fetch adversarial report",
        code: "FETCH_ERROR",
      },
      { status: 500 }
    );
  }
}