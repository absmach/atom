import { getGraphqlEndpoint } from "@/lib/graphql/client";
import { getServerToken } from "@/lib/auth/session";

const ENTITY_PROFILE_QUERY = `
  query EntityProfile($id: ID!) {
    entity(id: $id) {
      id
      name
      kind
      tenantId
      status
      attributes
    }
  }
`;

export type EntityProfile = {
  id: string;
  name: string;
  kind: string;
  tenantId: string | null;
  status: string;
  attributes: Record<string, unknown>;
};

export async function getEntityProfile(
  entityId: string,
): Promise<EntityProfile | null> {
  const token = await getServerToken();
  if (!token) return null;

  try {
    const response = await fetch(getGraphqlEndpoint(), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        query: ENTITY_PROFILE_QUERY,
        variables: { id: entityId },
        operationName: "EntityProfile",
      }),
      cache: "no-store",
    });

    const payload = await response.json();
    if (!response.ok || payload.errors?.length || !payload.data?.entity) {
      return null;
    }

    return payload.data.entity as EntityProfile;
  } catch {
    return null;
  }
}
