import { CrudWorkspace } from "@/components/crud/crud-workspace";

export default async function CapabilitiesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  return <CrudWorkspace resourceKey="capabilities" searchParams={sp} />;
}
