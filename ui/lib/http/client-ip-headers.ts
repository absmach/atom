const CLIENT_IP_HEADERS = [
  "x-forwarded-for",
  "x-real-ip",
  "forwarded",
] as const;

export function clientIpForwardingEnabled() {
  return envBoolDefault("ATOM_UI_FORWARD_CLIENT_IP_HEADERS", false);
}

export function forwardedClientIpHeaders(
  request: Request,
): Record<string, string> {
  if (!clientIpForwardingEnabled()) return {};

  return Object.fromEntries(
    CLIENT_IP_HEADERS.map((name) => [
      name,
      request.headers.get(name)?.trim(),
    ]).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

export function withForwardedClientIpHeaders(
  request: Request,
  headers: Record<string, string>,
) {
  return {
    ...headers,
    ...forwardedClientIpHeaders(request),
  };
}

function envBoolDefault(name: string, defaultValue: boolean) {
  const value = process.env[name]?.trim().toLowerCase();
  if (!value) return defaultValue;
  return ["1", "true", "yes", "on"].includes(value);
}
