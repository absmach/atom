"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";

export default function AdminError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const router = useRouter();
  const isAuthError =
    error.message.includes("Unauthorized") ||
    error.message.includes("unauthenticated");

  useEffect(() => {
    if (isAuthError) {
      router.push("/login");
    }
  }, [isAuthError, router]);

  if (isAuthError) {
    return null;
  }

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 text-center">
      <h2 className="text-xl font-semibold">Something went wrong</h2>
      <p className="text-sm text-muted-foreground">
        {error.message ?? "An unexpected error occurred."}
      </p>
      <div className="flex gap-2">
        <Button variant="outline" onClick={reset}>
          Try again
        </Button>
        <Button variant="outline" onClick={() => router.push("/login")}>
          Back to login
        </Button>
      </div>
    </div>
  );
}
