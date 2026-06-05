import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell/app-shell";
import {
  getServerSession,
  getServerToken,
  isExpired,
} from "@/lib/auth/session";
import { getEntityProfile } from "@/lib/entity/profile";

export const dynamic = "force-dynamic";

export default async function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await getServerSession();
  const token = await getServerToken();
  if (!session || !token || isExpired(session.expiresAt)) {
    redirect("/login");
  }

  let profile: Awaited<ReturnType<typeof getEntityProfile>>;
  try {
    profile = await getEntityProfile(session.entityId);
  } catch {
    redirect("/login");
  }
  if (!profile) {
    redirect("/login");
  }

  return (
    <AppShell entityName={profile.name} entityKind={profile.kind}>
      {children}
    </AppShell>
  );
}
