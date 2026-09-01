"use client";

// @peculiar/x509 pulls in tsyringe for dependency injection, which requires a
// reflect-metadata polyfill at the JS entry point. Without this the module
// throws "tsyringe requires a reflect polyfill" the first time the page hits
// any CSR/certificate parsing path. Import order matters — polyfill first.
import "reflect-metadata";
import {
  Pkcs10CertificateRequest,
  Pkcs10CertificateRequestGenerator,
} from "@peculiar/x509";
import { Loader2 } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { AtomGraphqlError, graphqlClient } from "@/lib/graphql/client";

type MutationResult = { ok: boolean; body: string };

async function runMutation(
  query: string,
  variables: Record<string, unknown>,
): Promise<MutationResult> {
  try {
    const data = await graphqlClient<Record<string, unknown>>({
      query,
      variables,
    });
    return { ok: true, body: JSON.stringify(data, null, 2) };
  } catch (caught) {
    const message =
      caught instanceof AtomGraphqlError
        ? caught.errors.map((entry) => entry.message).join("; ")
        : caught instanceof Error
          ? caught.message
          : "Request failed";
    return { ok: false, body: JSON.stringify({ error: message }, null, 2) };
  }
}

function ResultView({ result }: { result: MutationResult | null }) {
  if (!result) return null;
  return (
    <pre
      className={`mt-3 max-h-64 overflow-auto rounded-md border p-3 font-mono text-xs ${
        result.ok
          ? "border-emerald-500/40 bg-emerald-500/5"
          : "border-destructive/40 bg-destructive/5"
      }`}
    >
      <code>{result.body}</code>
    </pre>
  );
}

export function PkiActionsPanel() {
  // Root and platform intermediate imports are deliberately absent — both
  // belong in operator config (`ATOM_PKI_ROOT_CERT_PATH`,
  // `ATOM_PKI_PLATFORM_INTERMEDIATE_CERT_PATH`,
  // `ATOM_PKI_PLATFORM_INTERMEDIATE_KEY_PATH`), not a click.
  // See docs/content/docs/reference/certificate-lifecycle.mdx.
  return (
    <Tabs defaultValue="provision-tenant" className="grid gap-4">
      <TabsList className="flex-wrap">
        <TabsTrigger value="provision-tenant">Provision Tenant CA</TabsTrigger>
        <TabsTrigger value="issue-cert">Issue from CSR</TabsTrigger>
        <TabsTrigger value="generate-issue">Generate &amp; Issue</TabsTrigger>
        <TabsTrigger value="revoke-cert">Revoke</TabsTrigger>
        <TabsTrigger value="bulk-revoke">Bulk Revoke</TabsTrigger>
        <TabsTrigger value="retire-authority">Retire Authority</TabsTrigger>
      </TabsList>

      <TabsContent value="provision-tenant">
        <ProvisionTenantForm />
      </TabsContent>
      <TabsContent value="issue-cert">
        <IssueCertificateForm />
      </TabsContent>
      <TabsContent value="generate-issue">
        <GenerateAndIssueForm />
      </TabsContent>
      <TabsContent value="revoke-cert">
        <RevokeCertificateForm />
      </TabsContent>
      <TabsContent value="bulk-revoke">
        <BulkRevokeForm />
      </TabsContent>
      <TabsContent value="retire-authority">
        <RetireAuthorityWizard />
      </TabsContent>
    </Tabs>
  );
}

function ProvisionTenantForm() {
  const [tenantId, setTenantId] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<MutationResult | null>(null);

  async function submit() {
    if (!tenantId.trim()) {
      toast.error("Tenant ID required");
      return;
    }
    setBusy(true);
    const outcome = await runMutation(
      `mutation ProvisionTenant($t: ID!) { provisionTenantAuthorityAutomatically(tenantId: $t) { authority { id kind status version subject notAfter ocspUrl crlDistributionPointUrl } validationError } }`,
      { t: tenantId.trim() },
    );
    setResult(outcome);
    setBusy(false);
    if (outcome.ok) toast.success("Tenant authority provisioned");
    else toast.error("Provisioning failed");
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Provision Tenant Authority Automatically</CardTitle>
        <CardDescription>
          One-click provisioning for a tenant intermediate CA using the active
          platform intermediate. Requires an active platform intermediate — the
          operator must have bootstrapped one via
          <code>ATOM_PKI_PLATFORM_INTERMEDIATE_CERT_PATH</code> +
          <code>ATOM_PKI_PLATFORM_INTERMEDIATE_KEY_PATH</code>.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-2">
          <Label htmlFor="provision-tenant-id">Tenant ID</Label>
          <Input
            id="provision-tenant-id"
            value={tenantId}
            onChange={(event) => setTenantId(event.target.value)}
            placeholder="tenant UUID"
          />
        </div>
        <div className="flex justify-end">
          <Button type="button" onClick={() => void submit()} disabled={busy}>
            {busy ? (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            ) : null}
            Provision
          </Button>
        </div>
        <ResultView result={result} />
      </CardContent>
    </Card>
  );
}

type CsrPreview =
  | { ok: true; subject: string; algorithm: string; sanDns: string[] }
  | { ok: false; error: string };

function parseCsr(pem: string): CsrPreview | null {
  const trimmed = pem.trim();
  if (!trimmed) return null;
  try {
    const csr = new Pkcs10CertificateRequest(trimmed);
    const sanExt = csr.getExtension("2.5.29.17");
    const sanDns: string[] = [];
    if (sanExt) {
      // Rough SAN extraction: @peculiar/x509 doesn't expose GeneralNames on
      // CSR extensions directly, so pull dNSName candidates from the raw
      // extension's toString(). Good enough for a "did you paste what you
      // think you pasted" preview.
      const raw = sanExt.toString();
      const matches = raw.match(/dNSName:\s*([^\s,]+)/g);
      if (matches) {
        for (const match of matches) {
          const value = match.replace(/dNSName:\s*/, "").trim();
          if (value) sanDns.push(value);
        }
      }
    }
    return {
      ok: true,
      subject: csr.subject,
      algorithm:
        typeof csr.publicKey.algorithm === "object"
          ? JSON.stringify(csr.publicKey.algorithm)
          : String(csr.publicKey.algorithm),
      sanDns,
    };
  } catch (caught) {
    return {
      ok: false,
      error: caught instanceof Error ? caught.message : "unrecognised CSR",
    };
  }
}

function IssueCertificateForm() {
  const [entityId, setEntityId] = useState("");
  const [ttlSecs, setTtlSecs] = useState("3600");
  const [idempotencyKey, setIdempotencyKey] = useState("");
  const [csrPem, setCsrPem] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<MutationResult | null>(null);
  const csrPreview = useMemo(() => parseCsr(csrPem), [csrPem]);

  async function submit() {
    if (!entityId.trim() || !csrPem.trim()) {
      toast.error("Entity ID and CSR are required");
      return;
    }
    setBusy(true);
    const outcome = await runMutation(
      `mutation IssueFromCsr($in: IssueCertificateFromCsrV2Input!) { issueCertificateFromCsrV2(input: $in) { certificate { credentialId serialNumber status notBefore notAfter fingerprintSha256 issuerId pem } } }`,
      {
        in: {
          entityId: entityId.trim(),
          csrPem,
          ttlSecs: Number(ttlSecs) || 3600,
          idempotencyKey:
            idempotencyKey.trim() ||
            `manual-${new Date().toISOString().replace(/[^0-9]/g, "")}`,
        },
      },
    );
    setResult(outcome);
    setBusy(false);
    if (outcome.ok) toast.success("Certificate issued");
    else toast.error("Issuance failed");
  }

  async function fileUpload(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setCsrPem(await file.text());
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Issue Certificate from CSR</CardTitle>
        <CardDescription>
          Upload a device-generated CSR (PKCS#10). The tenant issuer is selected
          automatically from the entity's tenant scope.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-2 md:grid-cols-3">
          <div className="grid gap-2">
            <Label htmlFor="issue-entity">Entity ID</Label>
            <Input
              id="issue-entity"
              value={entityId}
              onChange={(event) => setEntityId(event.target.value)}
              placeholder="entity UUID"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="issue-ttl">TTL (seconds)</Label>
            <Input
              id="issue-ttl"
              value={ttlSecs}
              onChange={(event) => setTtlSecs(event.target.value)}
              inputMode="numeric"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="issue-idempotency">Idempotency key</Label>
            <Input
              id="issue-idempotency"
              value={idempotencyKey}
              onChange={(event) => setIdempotencyKey(event.target.value)}
              placeholder="auto-generated if blank"
            />
          </div>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="issue-csr-file">Upload CSR file (optional)</Label>
          <Input
            id="issue-csr-file"
            type="file"
            accept=".csr,.pem,.txt"
            onChange={fileUpload}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="issue-csr">CSR PEM</Label>
          <Textarea
            id="issue-csr"
            value={csrPem}
            onChange={(event) => setCsrPem(event.target.value)}
            spellCheck={false}
            className="min-h-40 font-mono text-xs"
            placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"
          />
        </div>
        {csrPreview ? (
          csrPreview.ok ? (
            <div className="grid gap-2 rounded-md border p-3 text-sm">
              <div className="flex items-center gap-2">
                <Badge variant="secondary">CSR parsed</Badge>
                <span className="text-xs text-muted-foreground">
                  Confirm the subject before submitting.
                </span>
              </div>
              <div className="grid grid-cols-[120px_1fr] gap-2 text-xs">
                <span className="text-muted-foreground">Subject</span>
                <span className="break-all font-mono">
                  {csrPreview.subject || "—"}
                </span>
                <span className="text-muted-foreground">Public key</span>
                <span className="break-all font-mono">
                  {csrPreview.algorithm}
                </span>
                {csrPreview.sanDns.length > 0 ? (
                  <>
                    <span className="text-muted-foreground">SAN DNS</span>
                    <span className="break-all font-mono">
                      {csrPreview.sanDns.join(", ")}
                    </span>
                  </>
                ) : null}
              </div>
            </div>
          ) : (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-xs text-destructive">
              CSR failed to parse: {csrPreview.error}
            </div>
          )
        ) : null}
        <div className="flex justify-end">
          <Button type="button" onClick={() => void submit()} disabled={busy}>
            {busy ? (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            ) : null}
            Issue Certificate
          </Button>
        </div>
        <ResultView result={result} />
      </CardContent>
    </Card>
  );
}

const REVOCATION_REASONS = [
  "unspecified",
  "key_compromise",
  "ca_compromise",
  "affiliation_changed",
  "superseded",
  "cessation_of_operation",
  "privilege_withdrawn",
] as const;

function RevokeCertificateForm() {
  const [credentialId, setCredentialId] = useState("");
  const [reason, setReason] = useState<string>("unspecified");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<MutationResult | null>(null);

  async function submit() {
    if (!credentialId.trim()) {
      toast.error("Credential ID required");
      return;
    }
    setBusy(true);
    const outcome = await runMutation(
      `mutation Revoke($in: RevokeCertificateV2Input!) { revokeCertificateV2(input: $in) { certificate { credentialId status } reason revokedAt idempotentReplay } }`,
      { in: { credentialId: credentialId.trim(), reason } },
    );
    setResult(outcome);
    setBusy(false);
    if (outcome.ok) toast.success("Certificate revoked");
    else toast.error("Revoke failed");
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Revoke Certificate</CardTitle>
        <CardDescription>
          Immediately marks the certificate as revoked and stamps the ledger
          with an immutable reason. Idempotent — a second call returns the
          original evidence without rewriting time or reason.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-2 md:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="revoke-cred">Credential ID</Label>
            <Input
              id="revoke-cred"
              value={credentialId}
              onChange={(event) => setCredentialId(event.target.value)}
              placeholder="certificate credential UUID"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="revoke-reason">Reason (RFC 5280)</Label>
            <select
              id="revoke-reason"
              className="h-9 rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            >
              {REVOCATION_REASONS.map((entry) => (
                <option key={entry} value={entry}>
                  {entry}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="flex justify-end">
          <Button
            type="button"
            variant="destructive"
            onClick={() => void submit()}
            disabled={busy}
          >
            {busy ? (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            ) : null}
            Revoke
          </Button>
        </div>
        <ResultView result={result} />
      </CardContent>
    </Card>
  );
}

type RetireStep = "explain" | "begin" | "complete" | "done";

function RetireAuthorityWizard() {
  const [step, setStep] = useState<RetireStep>("explain");
  const [authorityId, setAuthorityId] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<MutationResult | null>(null);

  async function begin() {
    if (!authorityId.trim() || !confirmed) {
      toast.error("Authority ID and confirmation required");
      return;
    }
    setBusy(true);
    const outcome = await runMutation(
      `mutation BeginRetirement($id: ID!) { beginAuthorityRetirement(authorityId: $id) { id status retiringAt } }`,
      { id: authorityId.trim() },
    );
    setResult(outcome);
    setBusy(false);
    if (outcome.ok) {
      try {
        const data = JSON.parse(outcome.body) as {
          beginAuthorityRetirement?: { status?: string };
        };
        setStatus(data.beginAuthorityRetirement?.status ?? null);
      } catch {
        setStatus(null);
      }
      setStep("complete");
      toast.success("Retirement started");
    } else {
      toast.error("Begin failed");
    }
  }

  async function complete() {
    setBusy(true);
    const outcome = await runMutation(
      `mutation CompleteRetirement($id: ID!) { completeAuthorityRetirement(authorityId: $id) { id status retiredAt } }`,
      { id: authorityId.trim() },
    );
    setResult(outcome);
    setBusy(false);
    if (outcome.ok) {
      try {
        const data = JSON.parse(outcome.body) as {
          completeAuthorityRetirement?: { status?: string };
        };
        setStatus(data.completeAuthorityRetirement?.status ?? null);
      } catch {
        setStatus(null);
      }
      setStep("done");
      toast.success("Retirement completed");
    } else {
      toast.error("Complete failed");
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Retire Authority</CardTitle>
        <CardDescription>
          Wizard flow: understand the impact, confirm the target, begin, then
          complete. The retired authority still signs CRLs and OCSP responses
          for its outstanding certificates until they expire — retirement only
          stops <em>new</em> issuance.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <ol className="flex flex-wrap items-center gap-2 text-xs">
          <StepBadge active={step === "explain"} label="1. Impact" />
          <StepBadge
            active={step === "begin" || step === "explain"}
            label="2. Confirm"
          />
          <StepBadge
            active={step === "complete"}
            label="3. Begin"
            done={step === "complete" || step === "done"}
          />
          <StepBadge active={step === "done"} label="4. Complete" />
        </ol>

        {step === "explain" ? (
          <div className="grid gap-3">
            <p className="text-sm">
              Retiring an authority is <strong>irreversible</strong>. Before
              proceeding, understand:
            </p>
            <ul className="ml-5 list-disc space-y-1 text-sm">
              <li>
                New certificate issuance from this authority stops immediately.
              </li>
              <li>Existing certificates remain valid until their expiry.</li>
              <li>
                CRL and OCSP responses continue to be signed by this authority
                for retained certificates.
              </li>
              <li>
                Provision a replacement authority <em>before</em> retiring if
                this issuer is in active use.
              </li>
            </ul>
            <div className="flex justify-end">
              <Button type="button" onClick={() => setStep("begin")}>
                Understood — proceed
              </Button>
            </div>
          </div>
        ) : null}

        {step === "begin" ? (
          <div className="grid gap-3">
            <div className="grid gap-2">
              <Label htmlFor="retire-id">Authority ID</Label>
              <Input
                id="retire-id"
                value={authorityId}
                onChange={(event) => setAuthorityId(event.target.value)}
                placeholder="authority UUID to retire"
              />
            </div>
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(event) => setConfirmed(event.target.checked)}
                className="h-4 w-4"
              />
              I have provisioned a replacement authority if this one is in
              active use.
            </label>
            <div className="flex flex-wrap justify-end gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => setStep("explain")}
                disabled={busy}
              >
                Back
              </Button>
              <Button
                type="button"
                onClick={() => void begin()}
                disabled={busy || !authorityId.trim() || !confirmed}
              >
                {busy ? (
                  <Loader2 data-icon="inline-start" className="animate-spin" />
                ) : null}
                Begin retirement
              </Button>
            </div>
            <ResultView result={result} />
          </div>
        ) : null}

        {step === "complete" ? (
          <div className="grid gap-3">
            <div className="rounded-md border p-3 text-sm">
              <div>
                <span className="text-muted-foreground">Authority:</span>{" "}
                <span className="font-mono text-xs">{authorityId}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Current status:</span>{" "}
                <Badge variant="outline">{status ?? "retiring"}</Badge>
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                The authority is retiring. Ensure no in-flight issuance is still
                using it, then complete retirement.
              </p>
            </div>
            <div className="flex justify-end">
              <Button
                type="button"
                variant="destructive"
                onClick={() => void complete()}
                disabled={busy}
              >
                {busy ? (
                  <Loader2 data-icon="inline-start" className="animate-spin" />
                ) : null}
                Complete retirement
              </Button>
            </div>
            <ResultView result={result} />
          </div>
        ) : null}

        {step === "done" ? (
          <div className="grid gap-3">
            <div className="rounded-md border border-emerald-500/40 bg-emerald-500/5 p-3 text-sm">
              Retirement complete. Authority status:{" "}
              <Badge variant="outline">{status ?? "retired"}</Badge>
            </div>
            <div className="flex justify-end">
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setStep("explain");
                  setAuthorityId("");
                  setConfirmed(false);
                  setStatus(null);
                  setResult(null);
                }}
              >
                Retire another
              </Button>
            </div>
            <ResultView result={result} />
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

function StepBadge({
  active,
  done,
  label,
}: {
  active: boolean;
  done?: boolean;
  label: string;
}) {
  return (
    <Badge
      variant={done ? "secondary" : active ? "default" : "outline"}
      className="whitespace-nowrap"
    >
      {label}
    </Badge>
  );
}

const BULK_REVOKE_MUTATION = `mutation BulkRevoke($in: BulkRevokeCertificatesInput!) {
  bulkRevokeCertificates(input: $in) {
    items { credentialId issuerId entityId tenantId outcome errorCode }
    snapshotAt
    nextCursor
    complete
  }
}`;

function BulkRevokeForm() {
  const [tenantId, setTenantId] = useState("");
  const [issuerId, setIssuerId] = useState("");
  const [principalGroupId, setPrincipalGroupId] = useState("");
  const [reason, setReason] = useState<string>("unspecified");
  const [limit, setLimit] = useState("50");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<MutationResult | null>(null);

  async function submit() {
    if (!tenantId.trim() && !issuerId.trim() && !principalGroupId.trim()) {
      toast.error(
        "Pick at least one scope: tenant, issuer, or principal group",
      );
      return;
    }
    if (!confirmed) {
      toast.error("Confirm the impact first");
      return;
    }
    setBusy(true);
    const input: Record<string, unknown> = { reason };
    if (tenantId.trim()) input.tenantId = tenantId.trim();
    if (issuerId.trim()) input.issuerId = issuerId.trim();
    if (principalGroupId.trim())
      input.principalGroupId = principalGroupId.trim();
    if (limit.trim()) input.limit = Number(limit) || 50;
    const outcome = await runMutation(BULK_REVOKE_MUTATION, { in: input });
    setResult(outcome);
    setBusy(false);
    if (outcome.ok) toast.success("Bulk revoke batch completed");
    else toast.error("Bulk revoke failed");
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Bulk Revoke</CardTitle>
        <CardDescription>
          Revoke every active certificate in a scope: a tenant, an issuer, or a
          principal group. The server paginates with a snapshot — a large scope
          returns a <code>nextCursor</code> and needs re-submission until{" "}
          <code>complete</code> is true.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-2 md:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="bulk-revoke-tenant">Tenant ID (optional)</Label>
            <Input
              id="bulk-revoke-tenant"
              value={tenantId}
              onChange={(event) => setTenantId(event.target.value)}
              placeholder="tenant UUID"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="bulk-revoke-issuer">Issuer ID (optional)</Label>
            <Input
              id="bulk-revoke-issuer"
              value={issuerId}
              onChange={(event) => setIssuerId(event.target.value)}
              placeholder="issuer UUID"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="bulk-revoke-group">
              Principal group ID (optional)
            </Label>
            <Input
              id="bulk-revoke-group"
              value={principalGroupId}
              onChange={(event) => setPrincipalGroupId(event.target.value)}
              placeholder="group UUID"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="bulk-revoke-limit">Batch limit</Label>
            <Input
              id="bulk-revoke-limit"
              value={limit}
              onChange={(event) => setLimit(event.target.value)}
              inputMode="numeric"
            />
          </div>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="bulk-revoke-reason">Reason (RFC 5280)</Label>
          <select
            id="bulk-revoke-reason"
            className="h-9 rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          >
            {REVOCATION_REASONS.map((entry) => (
              <option key={entry} value={entry}>
                {entry}
              </option>
            ))}
          </select>
        </div>
        <label className="flex items-center gap-2 text-xs text-muted-foreground">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
            className="h-4 w-4"
          />
          I understand every active certificate matching the scope above will be
          revoked with reason <strong>{reason}</strong>.
        </label>
        <div className="flex justify-end">
          <Button
            type="button"
            variant="destructive"
            onClick={() => void submit()}
            disabled={busy}
          >
            {busy ? (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            ) : null}
            Run bulk revoke
          </Button>
        </div>
        <ResultView result={result} />
      </CardContent>
    </Card>
  );
}

// In-browser CSR generation. WebCrypto produces a fresh keypair, @peculiar/x509
// serialises it as PKCS#10, and we surface both the CSR PEM (submitted to the
// backend) and the private key PEM (downloaded once — never sent server-side).
async function generateCsrAndKey(input: {
  commonName: string;
  algorithm: "ECDSA_P256" | "RSA_2048";
}): Promise<{ csrPem: string; privateKeyPem: string; publicKeyPem: string }> {
  const alg =
    input.algorithm === "ECDSA_P256"
      ? {
          name: "ECDSA",
          namedCurve: "P-256",
          hash: "SHA-256",
        }
      : {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        };

  const keys = (await window.crypto.subtle.generateKey(alg, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  // SAN DNS entries are intentionally not attached here — SubjectAlternativeName
  // extension typing across @peculiar/x509 releases is not stable enough to rely
  // on, and operators that need SANs can bring their own openssl-produced CSR
  // via the "Issue from CSR" tab.
  const csr = await Pkcs10CertificateRequestGenerator.create({
    name: `CN=${input.commonName}`,
    keys,
    signingAlgorithm: alg,
  });

  const privateKeyRaw = await window.crypto.subtle.exportKey(
    "pkcs8",
    keys.privateKey,
  );
  const publicKeyRaw = await window.crypto.subtle.exportKey(
    "spki",
    keys.publicKey,
  );
  return {
    csrPem: csr.toString("pem"),
    privateKeyPem: derToPem(new Uint8Array(privateKeyRaw), "PRIVATE KEY"),
    publicKeyPem: derToPem(new Uint8Array(publicKeyRaw), "PUBLIC KEY"),
  };
}

function derToPem(der: Uint8Array, label: string): string {
  let base64 = "";
  const chunk = 0x8000;
  for (let i = 0; i < der.length; i += chunk) {
    base64 += String.fromCharCode(...der.subarray(i, i + chunk));
  }
  const b64 = btoa(base64);
  const lines = b64.match(/.{1,64}/g) ?? [b64];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function GenerateAndIssueForm() {
  const [entityId, setEntityId] = useState("");
  const [commonName, setCommonName] = useState("");
  const [algorithm, setAlgorithm] = useState<"ECDSA_P256" | "RSA_2048">(
    "ECDSA_P256",
  );
  const [ttlSecs, setTtlSecs] = useState("3600");
  const [generated, setGenerated] = useState<{
    csrPem: string;
    privateKeyPem: string;
  } | null>(null);
  const [issued, setIssued] = useState<MutationResult | null>(null);
  const [busy, setBusy] = useState(false);

  async function generateAndIssue() {
    if (!entityId.trim() || !commonName.trim()) {
      toast.error("Entity ID and Common Name are required");
      return;
    }
    setBusy(true);
    setGenerated(null);
    setIssued(null);
    try {
      const material = await generateCsrAndKey({
        commonName: commonName.trim(),
        algorithm,
      });
      setGenerated({
        csrPem: material.csrPem,
        privateKeyPem: material.privateKeyPem,
      });
      const outcome = await runMutation(
        `mutation IssueFromCsr($in: IssueCertificateFromCsrV2Input!) { issueCertificateFromCsrV2(input: $in) { certificate { credentialId serialNumber status notBefore notAfter certificatePem } } }`,
        {
          in: {
            entityId: entityId.trim(),
            csrPem: material.csrPem,
            ttlSecs: Number(ttlSecs) || 3600,
            idempotencyKey: `browser-gen-${Date.now()}`,
          },
        },
      );
      setIssued(outcome);
      if (outcome.ok) toast.success("Certificate issued");
      else toast.error("Issuance failed");
    } catch (caught) {
      toast.error(
        caught instanceof Error
          ? caught.message
          : "Browser-side key generation failed",
      );
    } finally {
      setBusy(false);
    }
  }

  function downloadPrivateKey() {
    if (!generated) return;
    const blob = new Blob([generated.privateKeyPem], {
      type: "application/x-pem-file",
    });
    const href = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = href;
    a.download = `${commonName.trim() || "device"}.key.pem`;
    a.click();
    URL.revokeObjectURL(href);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Generate Keypair &amp; Issue</CardTitle>
        <CardDescription>
          Generates a fresh keypair in your browser using WebCrypto, builds a
          PKCS#10 CSR, and issues a certificate. The private key never leaves
          the browser — download it immediately and store it wherever the device
          / service will consume it.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-2 md:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="gen-entity">Entity ID</Label>
            <Input
              id="gen-entity"
              value={entityId}
              onChange={(event) => setEntityId(event.target.value)}
              placeholder="entity UUID"
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="gen-cn">Common Name</Label>
            <Input
              id="gen-cn"
              value={commonName}
              onChange={(event) => setCommonName(event.target.value)}
              placeholder="device-01"
            />
          </div>
        </div>
        <div className="grid gap-2 md:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="gen-alg">Algorithm</Label>
            <select
              id="gen-alg"
              className="h-9 rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
              value={algorithm}
              onChange={(event) =>
                setAlgorithm(event.target.value as "ECDSA_P256" | "RSA_2048")
              }
            >
              <option value="ECDSA_P256">ECDSA P-256</option>
              <option value="RSA_2048">RSA 2048</option>
            </select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="gen-ttl">TTL (seconds)</Label>
            <Input
              id="gen-ttl"
              value={ttlSecs}
              onChange={(event) => setTtlSecs(event.target.value)}
              inputMode="numeric"
            />
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          SAN DNS entries aren't attached from this tab (library typing is
          unstable across versions). If you need SANs, produce the CSR with
          openssl and use the <strong>Issue from CSR</strong> tab.
        </p>
        <div className="flex justify-end">
          <Button
            type="button"
            onClick={() => void generateAndIssue()}
            disabled={busy}
          >
            {busy ? (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            ) : null}
            Generate & Issue
          </Button>
        </div>
        {generated ? (
          <div className="grid gap-3 rounded-md border border-amber-500/40 bg-amber-500/5 p-3">
            <div className="text-sm font-medium text-amber-800 dark:text-amber-300">
              Private key generated — download now, it is not stored
              server-side.
            </div>
            <div className="flex justify-end">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={downloadPrivateKey}
              >
                Download private key
              </Button>
            </div>
          </div>
        ) : null}
        <ResultView result={issued} />
      </CardContent>
    </Card>
  );
}
