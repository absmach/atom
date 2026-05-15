import { ApiEndpointsWorkspace } from "@/components/endpoints/api-endpoints-workspace";

export default async function EndpointsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  return <ApiEndpointsWorkspace searchParams={sp} />;
}
