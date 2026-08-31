export const AUTHZ_TARGET_KINDS = [
  "platform",
  "tenant",
  "entity",
  "resource",
  "group",
] as const;

export type AuthzTargetKind = (typeof AUTHZ_TARGET_KINDS)[number];

export type AuthzDebuggerInitialValues = {
  subjectId?: string;
  targetKind?: AuthzTargetKind;
  targetId?: string;
};

type SearchParams = Record<string, string | string[] | undefined>;

export function authzDebuggerHref(
  initialValues: AuthzDebuggerInitialValues,
): string {
  const params = new URLSearchParams();

  if (initialValues.subjectId) {
    params.set("subjectId", initialValues.subjectId);
  }
  if (initialValues.targetKind) {
    params.set("targetKind", initialValues.targetKind);
  }
  if (initialValues.targetId) {
    params.set("targetId", initialValues.targetId);
  }

  const query = params.toString();
  return query ? `/authz?${query}` : "/authz";
}

export function parseAuthzDebuggerInitialValues(
  searchParams: SearchParams,
): AuthzDebuggerInitialValues {
  const subjectId = firstValue(searchParams.subjectId);
  const targetId = firstValue(searchParams.targetId);
  const rawTargetKind = firstValue(searchParams.targetKind);
  const targetKind = AUTHZ_TARGET_KINDS.find((kind) => kind === rawTargetKind);

  return {
    ...(subjectId ? { subjectId } : {}),
    ...(targetKind ? { targetKind } : {}),
    ...(targetId ? { targetId } : {}),
  };
}

function firstValue(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}
