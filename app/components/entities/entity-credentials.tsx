"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Download,
  Eye,
  EyeOff,
  FileKey,
  KeyRound,
  Lock,
  RefreshCw,
  Trash2,
} from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { StatusBadge } from "@/components/crud/status-badge";
import { DisplayTimeCell } from "@/components/display-time";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DateTimePicker } from "@/components/ui/date-time-picker";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { graphqlClient } from "@/lib/graphql/client";
import { Action } from "@/lib/utils";

const CREDENTIALS_QUERY = `
  query EntityCredentials($entityId: ID!) {
    credentials(entityId: $entityId) {
      items {
        id
        kind
        status
        identifier
        expiresAt
        createdAt
      }
      total
    }
  }
`;

const CREATE_PASSWORD_MUTATION = `
  mutation CreatePassword($entityId: ID!, $password: String!) {
    createPassword(entityId: $entityId, password: $password)
  }
`;

const CREATE_API_KEY_MUTATION = `
  mutation CreateApiKey($entityId: ID!, $input: CreateApiKeyInput!) {
    createApiKey(entityId: $entityId, input: $input) {
      credentialId
      key
      expiresAt
    }
  }
`;

const REVOKE_CREDENTIAL_MUTATION = `
  mutation RevokeCredential($entityId: ID!, $credentialId: ID!) {
    revokeCredential(entityId: $entityId, credentialId: $credentialId)
  }
`;

const ISSUE_CERTIFICATE_MUTATION = `
  mutation IssueCertificate($input: IssueCertificateInput!) {
    issueCertificate(input: $input) {
      certificate {
        credentialId
        serialNumber
        certificatePem
        expiresAt
      }
      privateKeyPem
    }
  }
`;

const ISSUE_CERTIFICATE_FROM_CSR_MUTATION = `
  mutation IssueCertificateFromCsr($input: IssueCertificateFromCsrInput!) {
    issueCertificateFromCsr(input: $input) {
      certificate {
        credentialId
        serialNumber
        certificatePem
        expiresAt
      }
      privateKeyPem
    }
  }
`;

const RENEW_CERTIFICATE_MUTATION = `
  mutation RenewCertificate($input: RenewCertificateInput!) {
    renewCertificate(input: $input) {
      certificate {
        credentialId
        serialNumber
        certificatePem
        expiresAt
      }
      privateKeyPem
    }
  }
`;

const REVOKE_CERTIFICATE_MUTATION = `
  mutation RevokeCertificate($input: RevokeCertificateInput!) {
    revokeCertificate(input: $input) {
      credentialId
      serialNumber
      status
    }
  }
`;

const CA_CHAIN_QUERY = `
  query CaChain {
    caChain
  }
`;

const CERTIFICATE_QUERY = `
  query Certificate($serialNumber: String!) {
    certificate(serialNumber: $serialNumber) {
      serialNumber
      certificatePem
    }
  }
`;

type Credential = {
  id: string;
  kind: string;
  status: string;
  identifier: string | null;
  expiresAt: string | null;
  createdAt: string;
};

type CredentialKind = "password" | "api_key" | "certificate";

type AddCredentialState =
  | { kind: "password"; password: string; confirm: string }
  | { kind: "api_key"; description: string; expiresAt: string }
  | {
      kind: "certificate";
      commonName: string;
      dnsNames: string;
      ipAddresses: string;
      ttlSecs: string;
      csrPem: string;
    };

type ApiKeyResult = {
  credentialId: string;
  key: string;
  expiresAt: string | null;
};

type CertificateResult = {
  certificate: {
    credentialId: string;
    serialNumber: string;
    certificatePem: string;
    expiresAt: string | null;
  };
  privateKeyPem: string | null;
};

type DownloadableCertificate = {
  serialNumber: string;
  certificatePem: string;
};

export function EntityCredentials({ entityId }: { entityId: string }) {
  const [activeForm, setActiveForm] = React.useState<CredentialKind | null>(
    null,
  );
  const [createdApiKey, setCreatedApiKey] = React.useState<ApiKeyResult | null>(
    null,
  );
  const [createdCertificate, setCreatedCertificate] =
    React.useState<CertificateResult | null>(null);
  const [showPassword, setShowPassword] = React.useState(false);
  const [form, setForm] = React.useState<AddCredentialState>(
    newCredentialForm("password"),
  );

  const { data, error, isFetching, refetch } = useQuery({
    enabled: Boolean(entityId),
    queryKey: ["entity-credentials", entityId],
    queryFn: ({ signal }) =>
      graphqlClient<{ credentials: { items: Credential[]; total: number } }>({
        query: CREDENTIALS_QUERY,
        variables: { entityId },
        signal,
      }),
    staleTime: 15_000,
  });

  const createPassword = useMutation({
    mutationFn: async (password: string) =>
      graphqlClient({
        query: CREATE_PASSWORD_MUTATION,
        variables: { entityId, password },
      }),
    onSuccess: () => {
      toast.success("Password credential created");
      setActiveForm(null);
      void refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const createApiKey = useMutation({
    mutationFn: async (input: { description?: string; expiresAt?: string }) =>
      graphqlClient<{ createApiKey: ApiKeyResult }>({
        query: CREATE_API_KEY_MUTATION,
        variables: { entityId, input },
      }),
    onSuccess: (data) => {
      setCreatedApiKey(data.createApiKey);
      setActiveForm(null);
      void refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const revokeCredential = useMutation({
    mutationFn: async (credentialId: string) =>
      graphqlClient({
        query: REVOKE_CREDENTIAL_MUTATION,
        variables: { entityId, credentialId },
      }),
    onSuccess: () => {
      toast.success("Credential revoked");
      void refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const issueCertificate = useMutation({
    mutationFn: async (input: {
      entityId: string;
      ttlSecs?: number;
      commonName?: string;
      dnsNames?: string[];
      ipAddresses?: string[];
    }) =>
      graphqlClient<{ issueCertificate: CertificateResult }>({
        query: ISSUE_CERTIFICATE_MUTATION,
        variables: { input },
      }),
    onSuccess: (data) => {
      setCreatedCertificate(data.issueCertificate);
      setActiveForm(null);
      void refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const issueCertificateFromCsr = useMutation({
    mutationFn: async (input: {
      entityId: string;
      ttlSecs?: number;
      csrPem: string;
    }) =>
      graphqlClient<{ issueCertificateFromCsr: CertificateResult }>({
        query: ISSUE_CERTIFICATE_FROM_CSR_MUTATION,
        variables: { input },
      }),
    onSuccess: (data) => {
      setCreatedCertificate(data.issueCertificateFromCsr);
      setActiveForm(null);
      void refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const renewCertificate = useMutation({
    mutationFn: async (serialNumber: string) =>
      graphqlClient<{ renewCertificate: CertificateResult }>({
        query: RENEW_CERTIFICATE_MUTATION,
        variables: { input: { serialNumber } },
      }),
    onSuccess: (data) => {
      setCreatedCertificate(data.renewCertificate);
      void refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const revokeCertificate = useMutation({
    mutationFn: async (serialNumber: string) =>
      graphqlClient({
        query: REVOKE_CERTIFICATE_MUTATION,
        variables: { input: { serialNumber } },
      }),
    onSuccess: () => {
      toast.success("Certificate revoked");
      void refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const downloadCertificate = useMutation({
    mutationFn: async (serialNumber: string) =>
      graphqlClient<{ certificate: DownloadableCertificate }>({
        query: CERTIFICATE_QUERY,
        variables: { serialNumber },
      }),
    onSuccess: (data) => {
      downloadCertificatePem(data.certificate);
    },
    onError: (err) => toast.error(err.message),
  });

  const credentials = data?.credentials.items ?? [];

  function openForm(kind: CredentialKind) {
    setShowPassword(false);
    setForm(newCredentialForm(kind));
    setActiveForm(kind);
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (form.kind === "password") {
      if (!form.password) {
        toast.error("Password is required.");
        return;
      }
      if (form.password !== form.confirm) {
        toast.error("Passwords do not match.");
        return;
      }
      createPassword.mutate(form.password);
    } else if (form.kind === "api_key") {
      const input: { description?: string; expiresAt?: string } = {};
      if (form.description.trim()) input.description = form.description.trim();
      if (form.expiresAt.trim()) input.expiresAt = form.expiresAt.trim();
      createApiKey.mutate(input);
    } else {
      const ttlSecs = form.ttlSecs.trim()
        ? Number.parseInt(form.ttlSecs.trim(), 10)
        : undefined;
      if (
        ttlSecs !== undefined &&
        (!Number.isFinite(ttlSecs) || ttlSecs <= 0)
      ) {
        toast.error("TTL must be a positive number of seconds.");
        return;
      }
      if (form.csrPem.trim()) {
        issueCertificateFromCsr.mutate({
          entityId,
          ttlSecs,
          csrPem: form.csrPem.trim(),
        });
        return;
      }
      issueCertificate.mutate({
        entityId,
        ttlSecs,
        commonName: form.commonName.trim() || undefined,
        dnsNames: splitList(form.dnsNames),
        ipAddresses: splitList(form.ipAddresses),
      });
    }
  }

  const isPending =
    createPassword.isPending ||
    createApiKey.isPending ||
    issueCertificate.isPending ||
    issueCertificateFromCsr.isPending;

  return (
    <div className="grid gap-4">
      <div className="flex items-center justify-between">
        <div className="text-sm font-medium">Credentials</div>
        {!activeForm ? (
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              onClick={() => openForm("password")}
              size="sm"
              variant="outline"
            >
              <Lock data-icon="inline-start" className="size-3.5" />
              Add password
            </Button>
            <Button
              onClick={() => openForm("api_key")}
              size="sm"
              variant="outline"
            >
              <KeyRound data-icon="inline-start" className="size-3.5" />
              Add API key
            </Button>
            <Button
              onClick={() => openForm("certificate")}
              size="sm"
              variant="outline"
            >
              <FileKey data-icon="inline-start" className="size-3.5" />
              Issue certificate
            </Button>
          </div>
        ) : null}
      </div>

      {createdApiKey ? (
        <ApiKeyRevealBanner
          apiKey={createdApiKey}
          onDismiss={() => setCreatedApiKey(null)}
        />
      ) : null}

      {createdCertificate ? (
        <CertificateRevealBanner
          certificate={createdCertificate}
          onDismiss={() => setCreatedCertificate(null)}
        />
      ) : null}

      {activeForm ? (
        <div className="rounded-lg border bg-background p-4">
          <div className="mb-3 flex items-center gap-2 text-sm font-medium">
            <CredentialKindIcon kind={activeForm} />
            {newCredentialTitle(activeForm)}
          </div>
          <form className="grid gap-3" onSubmit={handleSubmit}>
            {form.kind === "password" ? (
              <>
                <div className="grid gap-2">
                  <Label htmlFor="cred-password">Password</Label>
                  <div className="relative">
                    <Input
                      autoComplete="new-password"
                      id="cred-password"
                      onChange={(e) =>
                        setForm((prev) =>
                          prev.kind === "password"
                            ? { ...prev, password: e.target.value }
                            : prev,
                        )
                      }
                      required
                      type={showPassword ? "text" : "password"}
                      value={form.password}
                    />
                    <Button
                      className="absolute right-1 top-1/2 -translate-y-1/2"
                      onClick={() => setShowPassword((v) => !v)}
                      size="sm"
                      type="button"
                      variant="ghost"
                    >
                      {showPassword ? (
                        <EyeOff className="size-3.5" />
                      ) : (
                        <Eye className="size-3.5" />
                      )}
                    </Button>
                  </div>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="cred-confirm">Confirm password</Label>
                  <Input
                    autoComplete="new-password"
                    id="cred-confirm"
                    onChange={(e) =>
                      setForm((prev) =>
                        prev.kind === "password"
                          ? { ...prev, confirm: e.target.value }
                          : prev,
                      )
                    }
                    required
                    type={showPassword ? "text" : "password"}
                    value={form.confirm}
                  />
                </div>
              </>
            ) : form.kind === "api_key" ? (
              <>
                <div className="grid gap-2">
                  <Label htmlFor="cred-description">Description</Label>
                  <Input
                    id="cred-description"
                    onChange={(e) =>
                      setForm((prev) =>
                        prev.kind === "api_key"
                          ? { ...prev, description: e.target.value }
                          : prev,
                      )
                    }
                    placeholder="e.g. CI/CD pipeline key"
                    value={form.description}
                  />
                </div>
                <div className="grid gap-2">
                  <Label>Expires at (optional)</Label>
                  <DateTimePicker
                    value={form.expiresAt || undefined}
                    onChange={(v) =>
                      setForm((prev) =>
                        prev.kind === "api_key"
                          ? { ...prev, expiresAt: v }
                          : prev,
                      )
                    }
                    placeholder="No expiry"
                  />
                </div>
              </>
            ) : (
              <>
                <div className="grid gap-2">
                  <Label htmlFor="cert-common-name">Common name</Label>
                  <Input
                    id="cert-common-name"
                    onChange={(e) =>
                      setForm((prev) =>
                        prev.kind === "certificate"
                          ? { ...prev, commonName: e.target.value }
                          : prev,
                      )
                    }
                    placeholder="Defaults to entity ID"
                    value={form.commonName}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="cert-dns">DNS names</Label>
                  <Input
                    id="cert-dns"
                    onChange={(e) =>
                      setForm((prev) =>
                        prev.kind === "certificate"
                          ? { ...prev, dnsNames: e.target.value }
                          : prev,
                      )
                    }
                    placeholder="Comma-separated DNS SANs"
                    value={form.dnsNames}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="cert-ips">IP addresses</Label>
                  <Input
                    id="cert-ips"
                    onChange={(e) =>
                      setForm((prev) =>
                        prev.kind === "certificate"
                          ? { ...prev, ipAddresses: e.target.value }
                          : prev,
                      )
                    }
                    placeholder="Comma-separated IP SANs"
                    value={form.ipAddresses}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="cert-ttl">TTL seconds</Label>
                  <Input
                    id="cert-ttl"
                    inputMode="numeric"
                    onChange={(e) =>
                      setForm((prev) =>
                        prev.kind === "certificate"
                          ? { ...prev, ttlSecs: e.target.value }
                          : prev,
                      )
                    }
                    placeholder="Default"
                    value={form.ttlSecs}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="cert-csr">CSR PEM</Label>
                  <Textarea
                    className="min-h-28 font-mono text-xs"
                    id="cert-csr"
                    onChange={(e) =>
                      setForm((prev) =>
                        prev.kind === "certificate"
                          ? { ...prev, csrPem: e.target.value }
                          : prev,
                      )
                    }
                    placeholder="Paste CSR to sign instead of generating a private key"
                    value={form.csrPem}
                  />
                </div>
              </>
            )}

            <div className="flex justify-end gap-2">
              <Button
                onClick={() => setActiveForm(null)}
                type="button"
                variant="outline"
                size="sm"
              >
                Cancel
              </Button>
              <Button disabled={isPending} size="sm" type="submit">
                Create
              </Button>
            </div>
          </form>
        </div>
      ) : null}

      {isFetching && credentials.length === 0 ? (
        <div className="text-sm text-muted-foreground">
          Loading credentials…
        </div>
      ) : error ? (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {error.message}
        </div>
      ) : credentials.length === 0 ? (
        <div className="rounded-lg border bg-background p-3 text-sm text-muted-foreground">
          No credentials found.
        </div>
      ) : (
        <div className="grid gap-2">
          {credentials.map((cred) => (
            <CredentialRow
              cred={cred}
              key={cred.id}
              onRevoke={() => {
                if (
                  !window.confirm(
                    "Revoke this credential? This cannot be undone.",
                  )
                )
                  return;
                if (cred.kind === "certificate" && cred.identifier) {
                  revokeCertificate.mutate(cred.identifier);
                } else {
                  revokeCredential.mutate(cred.id);
                }
              }}
              onRenew={
                cred.kind === "certificate" && cred.identifier
                  ? () => renewCertificate.mutate(cred.identifier as string)
                  : undefined
              }
              onDownload={
                cred.kind === "certificate" && cred.identifier
                  ? () => downloadCertificate.mutate(cred.identifier as string)
                  : undefined
              }
              revoking={
                revokeCredential.isPending || revokeCertificate.isPending
              }
              renewing={renewCertificate.isPending}
              downloading={downloadCertificate.isPending}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function CredentialRow({
  cred,
  onRevoke,
  onRenew,
  onDownload,
  revoking,
  renewing,
  downloading,
}: {
  cred: Credential;
  onRevoke: () => void;
  onRenew?: () => void;
  onDownload?: () => void;
  revoking: boolean;
  renewing: boolean;
  downloading: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-lg border bg-background p-3">
      <div className="flex min-w-0 items-start gap-2">
        <CredentialKindIcon kind={cred.kind} />
        <div className="grid min-w-0 gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium">
              {credentialKindLabel(cred.kind)}
            </span>
            <StatusBadge value={cred.status} />
          </div>
          {cred.identifier ? (
            <div className="font-mono text-xs text-muted-foreground truncate">
              {cred.identifier}
            </div>
          ) : null}
          <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
            <span>
              Created{" "}
              <DisplayTimeCell action={Action.Created} time={cred.createdAt} />
            </span>
            {cred.expiresAt ? (
              <span>
                Expires{" "}
                <DisplayTimeCell
                  action={Action.Expired}
                  time={cred.expiresAt}
                />
              </span>
            ) : null}
          </div>
        </div>
      </div>
      {cred.status === "active" ? (
        <div className="flex shrink-0 gap-1">
          {onDownload ? (
            <Button
              disabled={downloading}
              onClick={onDownload}
              size="sm"
              variant="ghost"
            >
              <Download className="size-3.5" />
              <span className="sr-only">Download certificate</span>
            </Button>
          ) : null}
          {onRenew ? (
            <Button
              disabled={renewing}
              onClick={onRenew}
              size="sm"
              variant="ghost"
            >
              <RefreshCw className="size-3.5" />
              <span className="sr-only">Renew</span>
            </Button>
          ) : null}
          <Button
            disabled={revoking}
            onClick={onRevoke}
            size="sm"
            variant="ghost"
            className="text-destructive hover:text-destructive"
          >
            <Trash2 className="size-3.5" />
            <span className="sr-only">Revoke</span>
          </Button>
        </div>
      ) : null}
    </div>
  );
}

function CredentialKindIcon({ kind }: { kind: string }) {
  switch (kind) {
    case "password":
      return <Lock className="mt-0.5 size-4 shrink-0 text-muted-foreground" />;
    case "api_key":
      return (
        <KeyRound className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
      );
    default:
      return (
        <FileKey className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
      );
  }
}

function credentialKindLabel(kind: string) {
  switch (kind) {
    case "password":
      return "Password";
    case "api_key":
      return "API Key";
    case "certificate":
      return "Certificate";
    default:
      return kind;
  }
}

function newCredentialForm(kind: CredentialKind): AddCredentialState {
  switch (kind) {
    case "password":
      return { kind: "password", password: "", confirm: "" };
    case "api_key":
      return { kind: "api_key", description: "", expiresAt: "" };
    case "certificate":
      return {
        kind: "certificate",
        commonName: "",
        dnsNames: "",
        ipAddresses: "",
        ttlSecs: "",
        csrPem: "",
      };
  }
}

function newCredentialTitle(kind: CredentialKind) {
  switch (kind) {
    case "password":
      return "Add password";
    case "api_key":
      return "Add API key";
    case "certificate":
      return "Issue certificate";
  }
}

function ApiKeyRevealBanner({
  apiKey,
  onDismiss,
}: {
  apiKey: ApiKeyResult;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = React.useState(false);

  async function copy() {
    await navigator.clipboard.writeText(apiKey.key);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-3 dark:border-yellow-800 dark:bg-yellow-950">
      <div className="mb-2 flex items-center justify-between">
        <div className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
          API key created — copy it now
        </div>
        <Badge variant="outline" className="text-xs">
          shown once
        </Badge>
      </div>
      <p className="mb-2 text-xs text-yellow-700 dark:text-yellow-300">
        This key will not be shown again. Store it securely before dismissing.
      </p>
      <div className="mb-3 flex gap-2">
        <code className="min-w-0 flex-1 break-all rounded bg-yellow-100 px-2 py-1 font-mono text-xs text-yellow-900 dark:bg-yellow-900 dark:text-yellow-100">
          {apiKey.key}
        </code>
        <Button onClick={copy} size="sm" variant="outline">
          {copied ? "Copied!" : "Copy"}
        </Button>
      </div>
      <Button onClick={onDismiss} size="sm" variant="outline">
        Dismiss
      </Button>
    </div>
  );
}

function CertificateRevealBanner({
  certificate,
  onDismiss,
}: {
  certificate: CertificateResult;
  onDismiss: () => void;
}) {
  return (
    <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 dark:border-emerald-800 dark:bg-emerald-950">
      <div className="mb-2 flex items-center justify-between gap-3">
        <div className="text-sm font-medium text-emerald-900 dark:text-emerald-100">
          Certificate issued
        </div>
        <Badge variant="outline" className="text-xs">
          {certificate.privateKeyPem ? "key shown once" : "CSR signed"}
        </Badge>
      </div>
      <div className="mb-3 grid gap-2">
        <code className="break-all rounded bg-emerald-100 px-2 py-1 font-mono text-xs text-emerald-950 dark:bg-emerald-900 dark:text-emerald-100">
          {certificate.certificate.serialNumber}
        </code>
        <div className="flex flex-wrap gap-2">
          <Button
            onClick={() =>
              downloadCertificatePem({
                serialNumber: certificate.certificate.serialNumber,
                certificatePem: certificate.certificate.certificatePem,
              })
            }
            size="sm"
            variant="outline"
          >
            <Download data-icon="inline-start" className="size-3.5" />
            Certificate
          </Button>
          {certificate.privateKeyPem ? (
            <Button
              onClick={() =>
                downloadText(
                  `atom-cert-${certificate.certificate.serialNumber}-key.pem`,
                  certificate.privateKeyPem ?? "",
                )
              }
              size="sm"
              variant="outline"
            >
              <Download data-icon="inline-start" className="size-3.5" />
              Private key
            </Button>
          ) : null}
          <Button onClick={downloadCaChain} size="sm" variant="outline">
            <Download data-icon="inline-start" className="size-3.5" />
            CA chain
          </Button>
        </div>
      </div>
      <Button onClick={onDismiss} size="sm" variant="outline">
        Dismiss
      </Button>
    </div>
  );
}

function splitList(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function downloadText(filename: string, contents: string) {
  const blob = new Blob([contents], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function downloadCertificatePem(certificate: DownloadableCertificate) {
  downloadText(
    `atom-cert-${certificate.serialNumber}.pem`,
    certificate.certificatePem,
  );
}

async function downloadCaChain() {
  const data = await graphqlClient<{ caChain: string }>({
    query: CA_CHAIN_QUERY,
  });
  downloadText("atom-ca-chain.pem", data.caChain);
}
