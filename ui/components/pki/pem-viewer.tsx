"use client";

import { Copy, Download } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";

// Copyable + downloadable read-only view for PEM blobs (cert, chain, CSR).
// Kept dumb on purpose: no parsing, no highlighting — the payload is
// already text and the browser knows how to render it.
export function PemViewer({
  value,
  filename,
  label,
}: {
  value: string;
  filename: string;
  label?: string;
}) {
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(`${label ?? "PEM"} copied`);
    } catch {
      toast.error("Copy failed");
    }
  }

  function download() {
    const blob = new Blob([value], { type: "application/x-pem-file" });
    const href = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = href;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(href);
  }

  return (
    <div className="grid gap-2">
      <div className="flex items-center justify-between gap-2">
        {label ? (
          <span className="text-sm font-medium">{label}</span>
        ) : (
          <span />
        )}
        <div className="flex gap-2">
          <Button type="button" size="sm" variant="outline" onClick={copy}>
            <Copy data-icon="inline-start" />
            Copy
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={download}>
            <Download data-icon="inline-start" />
            Download
          </Button>
        </div>
      </div>
      <pre className="max-h-80 overflow-auto rounded-md border bg-muted p-3 font-mono text-xs">
        <code>{value}</code>
      </pre>
    </div>
  );
}
