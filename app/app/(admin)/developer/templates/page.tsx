import { ApiTemplatesWorkspace } from "@/components/developer/api-templates-workspace";

export default async function TemplatesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  return <ApiTemplatesWorkspace searchParams={sp} />;
}
