import { cookies } from "next/headers";
import { AUTH_COOKIE, AUTH_META_COOKIE } from "@/lib/auth/constants";

export { AUTH_COOKIE, AUTH_META_COOKIE };

export type AtomSession = {
  entityId: string;
  sessionId: string;
  expiresAt: string;
};

export async function getServerToken() {
  const store = await cookies();
  return store.get(AUTH_COOKIE)?.value ?? null;
}

export async function getServerSession(): Promise<AtomSession | null> {
  const store = await cookies();
  const raw = store.get(AUTH_META_COOKIE)?.value;
  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw) as AtomSession;
  } catch {
    return null;
  }
}

export function isExpired(expiresAt: string, now = new Date()) {
  return Number.isNaN(Date.parse(expiresAt)) || new Date(expiresAt) <= now;
}
