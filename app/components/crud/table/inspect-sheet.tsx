import { CapabilityInspectDetails } from "@/components/capabilities/capability-inspect-details";
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
import { RoleCapabilitiesPanel } from "@/components/roles/role-capabilities-panel";
import { RoleInspectDetails } from "@/components/roles/role-inspect-details";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
            {resource.key === "capabilities"
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
    return <ResourceInspectDetails row={inspected} />;
  }
  if (resourceKey === "roles") {
    return (
      <>
        <RoleInspectDetails row={inspected} />
        {inspected?.id ? (
          <RoleCapabilitiesPanel roleId={String(inspected.id)} />
        ) : null}
      </>
    );
  }
  if (resourceKey === "capabilities") {
    return <CapabilityInspectDetails row={inspected} />;
  }
  return <DetailFields row={inspected} />;
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
