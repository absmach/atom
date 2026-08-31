"use client";

import { useRouter } from "next/navigation";
import * as React from "react";

const MAX_REFRESH_LEEWAY_MS = 5 * 60 * 1000;
const MIN_REFRESH_LEEWAY_MS = 10 * 1000;
const MIN_REFRESH_DELAY_MS = 1000;
const RETRY_DELAY_MS = 30 * 1000;
const REAUTH_PATH = "/login?reauth=1";

export function SessionRefresh({ expiresAt }: { expiresAt: string }) {
  const router = useRouter();
  const [nextExpiresAt, setNextExpiresAt] = React.useState(expiresAt);

  React.useEffect(() => {
    setNextExpiresAt(expiresAt);
  }, [expiresAt]);

  React.useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let inFlight = false;
    let cancelled = false;

    function reauthenticate() {
      router.replace(REAUTH_PATH);
      router.refresh();
    }

    function clearTimer() {
      if (timer) {
        clearTimeout(timer);
        timer = undefined;
      }
    }

    function schedule(delay: number) {
      clearTimer();
      timer = setTimeout(() => {
        void refresh();
      }, delay);
    }

    function scheduleNextRefresh(expiry: string) {
      const expiresMs = Date.parse(expiry);
      if (Number.isNaN(expiresMs)) {
        reauthenticate();
        return;
      }

      const remaining = expiresMs - Date.now();
      if (remaining <= 0) {
        reauthenticate();
        return;
      }

      const leeway = Math.min(
        MAX_REFRESH_LEEWAY_MS,
        Math.max(MIN_REFRESH_LEEWAY_MS, remaining / 2),
      );
      schedule(Math.max(MIN_REFRESH_DELAY_MS, remaining - leeway));
    }

    function scheduleRetry() {
      const expiresMs = Date.parse(nextExpiresAt);
      if (Number.isNaN(expiresMs)) {
        reauthenticate();
        return;
      }

      const latestRetry = expiresMs - Date.now() - MIN_REFRESH_DELAY_MS;
      if (latestRetry <= 0) {
        reauthenticate();
        return;
      }
      schedule(Math.min(RETRY_DELAY_MS, latestRetry));
    }

    async function refresh() {
      if (inFlight || cancelled) return;
      inFlight = true;

      try {
        const response = await fetch("/api/auth/refresh", {
          method: "POST",
          credentials: "same-origin",
        });

        if (cancelled) return;
        if (response.status === 401) {
          reauthenticate();
          return;
        }
        if (!response.ok) {
          scheduleRetry();
          return;
        }

        const payload = (await response.json().catch(() => null)) as {
          expiresAt?: unknown;
        } | null;
        if (typeof payload?.expiresAt !== "string") {
          scheduleRetry();
          return;
        }

        setNextExpiresAt(payload.expiresAt);
      } catch {
        if (!cancelled) scheduleRetry();
      } finally {
        inFlight = false;
      }
    }

    function refreshIfNearExpiry() {
      const expiresMs = Date.parse(nextExpiresAt);
      if (Number.isNaN(expiresMs)) return;
      if (expiresMs - Date.now() <= MAX_REFRESH_LEEWAY_MS) {
        clearTimer();
        void refresh();
      }
    }

    scheduleNextRefresh(nextExpiresAt);
    window.addEventListener("focus", refreshIfNearExpiry);
    document.addEventListener("visibilitychange", refreshIfNearExpiry);

    return () => {
      cancelled = true;
      clearTimer();
      window.removeEventListener("focus", refreshIfNearExpiry);
      document.removeEventListener("visibilitychange", refreshIfNearExpiry);
    };
  }, [nextExpiresAt, router]);

  return null;
}
