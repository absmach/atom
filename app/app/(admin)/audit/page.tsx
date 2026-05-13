import { CrudWorkspace } from "@/components/crud/crud-workspace";

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  return <CrudWorkspace resourceKey="audit" searchParams={sp} />;
}
