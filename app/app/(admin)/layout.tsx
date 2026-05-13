import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell/app-shell";
import { getServerSession, isExpired } from "@/lib/auth/session";
import { getEntityProfile } from "@/lib/entity/profile";

export const dynamic = "force-dynamic";

export default async function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await getServerSession();
  if (!session || isExpired(session.expiresAt)) {
    redirect("/login");
  }

  const profile = await getEntityProfile(session.entityId);

  return (
    <AppShell
      entityName={profile?.name ?? session.entityId}
      entityKind={profile?.kind}
    >
      {children}
    </AppShell>
  );
}
