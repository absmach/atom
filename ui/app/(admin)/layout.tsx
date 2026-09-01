import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell/app-shell";
import {
  getServerSession,
  getServerToken,
  isExpired,
} from "@/lib/auth/session";
import { getEntityProfile } from "@/lib/entity/profile";

export const dynamic = "force-dynamic";
const REAUTH_PATH = "/login?reauth=1";

export default async function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await getServerSession();
  const token = await getServerToken();
  if (!session || !token || isExpired(session.expiresAt)) {
    redirect(REAUTH_PATH);
  }

  let profile: Awaited<ReturnType<typeof getEntityProfile>>;
  try {
    profile = await getEntityProfile(session.entityId);
  } catch {
    redirect(REAUTH_PATH);
  }
  if (!profile) {
    redirect(REAUTH_PATH);
  }

  return (
    <AppShell
      entityName={profile.name}
      entityKind={profile.kind}
      sessionExpiresAt={session.expiresAt}
    >
      {children}
    </AppShell>
  );
}
