import { CrudWorkspace } from "@/components/crud/crud-workspace";
import { PolicyBuilder } from "@/components/policy/policy-builder";
import { RelationshipPanel } from "@/components/relationships/relationship-panel";

export default async function PoliciesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  return (
    <div className="grid gap-6">
      <PolicyBuilder />
      <CrudWorkspace resourceKey="policies" searchParams={sp} />
      <RelationshipPanel />
    </div>
  );
}
