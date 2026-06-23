import * as React from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export type ScopeKind =
  | "platform"
  | "tenant"
  | "object_kind"
  | "object_type"
  | "object"
  | "group"
  | "group_direct_objects"
  | "group_descendant_objects"
  | "group_child_groups"
  | "group_descendant_groups";

export type PolicySummaryProps = {
  effect: "allow" | "deny";
  subjectKind: string;
  subjectName: string;
  grantKind: string;
  grantLabel: string;
  scopeKind: ScopeKind;
  scopeRef?: string;
  conditions: Array<{ path: string; value: string }>;
};

export function PolicySummary({
  effect,
  subjectKind,
  subjectName,
  grantKind,
  grantLabel,
  scopeKind,
  scopeRef,
  conditions,
}: PolicySummaryProps) {
  return (
    <div className="flex flex-wrap items-center gap-x-1.5 gap-y-2 text-sm">
      <EffectBadge effect={effect} className="capitalize" />
      <SubjectKindBadge kind={subjectKind} />
      <Badge variant="secondary">{subjectName}</Badge>
      <span className="text-muted-foreground">to use</span>
      <GrantKindBadge kind={grantKind} />
      <Badge variant="secondary">{grantLabel}</Badge>
      <span className="text-muted-foreground">on</span>
      <ScopeKindBadge kind={scopeKind} />
      {scopeRef ? (
        <Badge variant="outline" className="font-mono text-xs">
          {scopeRef}
        </Badge>
      ) : null}
      {conditions.length > 0 ? (
        <>
          <span className="text-muted-foreground">where</span>
          {conditions.map((c, i) => (
            <React.Fragment key={`${c.path}-${i}`}>
              <Badge variant="outline">
                {c.path} = {c.value}
              </Badge>
              {i < conditions.length - 1 ? (
                <span className="text-muted-foreground">and</span>
              ) : null}
            </React.Fragment>
          ))}
        </>
      ) : null}
    </div>
  );
}

export function EffectBadge({
  effect,
  className,
}: {
  effect: "allow" | "deny";
  className?: string;
}) {
  return effect === "allow" ? (
    <Badge
      className={cn(
        "border-green-500/30 bg-green-500/15 text-green-700 dark:text-green-400",
        className,
      )}
    >
      allow
    </Badge>
  ) : (
    <Badge
      className={cn(
        "border-red-500/30 bg-red-500/15 text-red-700 dark:text-red-400",
        className,
      )}
    >
      deny
    </Badge>
  );
}

export function SubjectKindBadge({ kind }: { kind: string }) {
  return kind === "group" ? (
    <Badge className="border-purple-500/30 bg-purple-500/15 text-purple-700 dark:text-purple-400">
      group
    </Badge>
  ) : (
    <Badge className="border-blue-500/30 bg-blue-500/15 text-blue-700 dark:text-blue-400">
      entity
    </Badge>
  );
}

export function GrantKindBadge({ kind }: { kind: string }) {
  return kind === "role" ? (
    <Badge className="border-indigo-500/30 bg-indigo-500/15 text-indigo-700 dark:text-indigo-400">
      role
    </Badge>
  ) : (
    <Badge className="border-amber-500/30 bg-amber-500/15 text-amber-700 dark:text-amber-400">
      action
    </Badge>
  );
}

export function ScopeKindBadge({ kind }: { kind: ScopeKind }) {
  if (kind === "platform") {
    return (
      <Badge className="border-slate-500/30 bg-slate-500/15 text-slate-700 dark:text-slate-400">
        platform
      </Badge>
    );
  }
  if (kind === "tenant") {
    return (
      <Badge className="border-teal-500/30 bg-teal-500/15 text-teal-700 dark:text-teal-400">
        tenant
      </Badge>
    );
  }
  return (
    <Badge className="border-violet-500/30 bg-violet-500/15 text-violet-700 dark:text-violet-400">
      {kind.replace("_", " ")}
    </Badge>
  );
}
