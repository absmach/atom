import { CrudWorkspace } from "@/components/crud/crud-workspace";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default async function SettingsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  return (
    <div className="grid gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Session and platform settings</CardTitle>
          <CardDescription>
            Token storage uses httpOnly cookies. The client never reads raw
            Bearer tokens.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Tenant context is non-sensitive and stored separately from Atom
          authentication.
        </CardContent>
      </Card>
      <CrudWorkspace resourceKey="credentials" searchParams={sp} />
      <CrudWorkspace resourceKey="sessions" searchParams={sp} />
    </div>
  );
}
