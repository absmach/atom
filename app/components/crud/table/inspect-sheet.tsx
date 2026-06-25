import { Activity } from "lucide-react";
import Link from "next/link";
import { ActionApplicabilityInspectDetails } from "@/components/actions/action-applicability-inspect-details";
import { DetailFields } from "@/components/crud/table/detail-fields";
import type { Row } from "@/components/crud/table/types";
import { EntityAuditLog } from "@/components/entities/entity-audit-log";
import { EntityCredentials } from "@/components/entities/entity-credentials";
import { EntityInspectDetails } from "@/components/entities/entity-inspect-details";
import { GroupInspectDetails } from "@/components/groups/group-inspect-details";
import { GroupMembersPanel } from "@/components/groups/group-members-panel";
import { PolicyInspectDetails } from "@/components/policy/policy-inspect-details";
import { ProfileInspectDetails } from "@/components/profiles/profile-inspect-details";
import { ResourceInspectDetails } from "@/components/resources/resource-inspect-details";
import { RoleInspectDetails } from "@/components/roles/role-inspect-details";
import { RolePermissionBlocksPanel } from "@/components/roles/role-permission-blocks-panel";
import { RolePrincipalsPanel } from "@/components/roles/role-principals-panel";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { authzDebuggerHref } from "@/lib/authz/debugger-links";
import type { CrudResource } from "@/lib/crud/resources";

export function CrudInspectSheet({
  inspected,
  onClose,
  resource,
}: {
  inspected: Row | null;
  onClose: () => void;
  resource: CrudResource;
}) {
  return (
    <Sheet
      open={Boolean(inspected)}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) onClose();
      }}
    >
      <SheetContent
        className={
          usesWideInspectSheet(resource.key)
            ? "w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!"
            : "w-full overflow-y-auto sm:max-w-xl"
        }
      >
        <SheetHeader>
          <SheetTitle>
            {resource.key === "action-applicability"
              ? "Inspect Action Applicability"
              : `Inspect ${String(inspected?.name ?? inspected?.displayName ?? inspected?.id ?? "")}`}
          </SheetTitle>
          <SheetDescription>
            Detail view for this {resource.title.toLowerCase()} item.
          </SheetDescription>
        </SheetHeader>
        <div className="grid min-w-0 gap-3 px-4 pb-4">
          <InspectBody inspected={inspected} resourceKey={resource.key} />
          <Button onClick={onClose} variant="outline">
            Close
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}

function InspectBody({
  inspected,
  resourceKey,
}: {
  inspected: Row | null;
  resourceKey: string;
}) {
  if (resourceKey === "policies") {
    return <PolicyInspectDetails row={inspected} />;
  }
  if (resourceKey === "profiles") {
    return <ProfileInspectDetails row={inspected} />;
  }
  if (resourceKey === "entities") {
    return (
      <Tabs defaultValue="details">
        <TabsList className="mb-4">
          <TabsTrigger value="details">Details</TabsTrigger>
          <TabsTrigger value="audit">Audit Logs</TabsTrigger>
        </TabsList>
        <TabsContent value="details" className="grid gap-3">
          <EntityInspectDetails row={inspected} />
          <InspectAuthzAction resourceKey={resourceKey} row={inspected} />
          {inspected?.id ? (
            <EntityCredentials entityId={String(inspected.id)} />
          ) : null}
        </TabsContent>
        <TabsContent value="audit">
          {inspected?.id ? (
            <EntityAuditLog entityId={String(inspected.id)} />
          ) : null}
        </TabsContent>
      </Tabs>
    );
  }
  if (resourceKey === "groups") {
    return (
      <>
        <GroupInspectDetails row={inspected} />
        {inspected?.id ? (
          <GroupMembersPanel groupId={String(inspected.id)} />
        ) : null}
      </>
    );
  }
  if (resourceKey === "resources") {
    return (
      <>
        <ResourceInspectDetails row={inspected} />
        <InspectAuthzAction resourceKey={resourceKey} row={inspected} />
      </>
    );
  }
  if (resourceKey === "roles") {
    return (
      <>
        <RoleInspectDetails row={inspected} />
        {inspected?.id ? (
          <>
            <RolePermissionBlocksPanel roleId={String(inspected.id)} />
            <RolePrincipalsPanel
              roleId={String(inspected.id)}
              tenantId={inspected.tenantId ? String(inspected.tenantId) : null}
            />
          </>
        ) : null}
      </>
    );
  }
  if (resourceKey === "action-applicability") {
    return <ActionApplicabilityInspectDetails row={inspected} />;
  }
  return <DetailFields row={inspected} />;
}

function InspectAuthzAction({
  resourceKey,
  row,
}: {
  resourceKey: "entities" | "resources";
  row: Row | null;
}) {
  if (!row?.id) return null;

  const name = String(row.name ?? row.id);
  const isEntity = resourceKey === "entities";
  const href = isEntity
    ? authzDebuggerHref({ subjectId: String(row.id) })
    : authzDebuggerHref({
        targetKind: "resource",
        targetId: String(row.id),
      });

  return (
    <div className="flex flex-col gap-3 rounded-lg border border-dashed bg-muted/20 p-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <div className="text-sm font-medium">Authorization debugger</div>
        <p className="mt-0.5 text-xs text-muted-foreground">
          {isEntity
            ? `Use ${name} as the request subject.`
            : `Use ${name} as the target object.`}
        </p>
      </div>
      <Button asChild className="shrink-0" size="sm" variant="outline">
        <Link href={href}>
          <Activity />
          Check authorization
        </Link>
      </Button>
    </div>
  );
}

function usesWideInspectSheet(resourceKey: string) {
  return [
    "profiles",
    "tenants",
    "entities",
    "groups",
    "roles",
    "policies",
  ].includes(resourceKey);
}
