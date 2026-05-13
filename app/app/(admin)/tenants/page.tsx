import { CrudWorkspace } from "@/components/crud/crud-workspace";

export default async function TenantsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  return <CrudWorkspace resourceKey="tenants" searchParams={sp} />;
}
