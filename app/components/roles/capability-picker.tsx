"use client";

import { X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export type PickerCapability = {
  id: string;
  name: string;
  resourceKind: string | null;
};

type Props = {
  all: PickerCapability[];
  selected: string[];
  onAdd: (id: string) => void;
  onRemove: (id: string) => void;
  disabled?: boolean;
};

export function CapabilityPicker({
  all,
  selected,
  onAdd,
  onRemove,
  disabled,
}: Props) {
  const selectedCaps = all.filter((c) => selected.includes(c.id));
  const availableCaps = all.filter((c) => !selected.includes(c.id));

  return (
    <div className="grid gap-2">
      <Label>Capabilities</Label>
      {selectedCaps.length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {selectedCaps.map((cap) => (
            <Badge key={cap.id} variant="secondary" className="gap-1 pr-1">
              {cap.name}
              {cap.resourceKind ? (
                <span className="text-muted-foreground">
                  :{cap.resourceKind}
                </span>
              ) : null}
              <button
                type="button"
                disabled={disabled}
                className="ml-0.5 rounded-sm opacity-70 hover:opacity-100 disabled:cursor-not-allowed"
                onClick={() => onRemove(cap.id)}
              >
                <X className="h-3 w-3" />
                <span className="sr-only">Remove {cap.name}</span>
              </button>
            </Badge>
          ))}
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">No capabilities selected.</p>
      )}
      {availableCaps.length > 0 && (
        <Select
          disabled={disabled}
          value=""
          onValueChange={(id) => {
            if (id) onAdd(id);
          }}
        >
          <SelectTrigger className="w-full">
            <SelectValue placeholder="— add capability —" />
          </SelectTrigger>
          <SelectContent>
            {availableCaps.map((c) => (
              <SelectItem key={c.id} value={c.id}>
                {c.name}
                {c.resourceKind ? ` (${c.resourceKind})` : ""}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
    </div>
  );
}
