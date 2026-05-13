import { CrudWorkspace } from "@/components/crud/crud-workspace";

export default async function GroupsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  return <CrudWorkspace resourceKey="groups" searchParams={sp} />;
}
