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
import {
  type ActionApplicability,
  actionLabel,
  applicabilityValues,
} from "@/lib/access/actions";

export type PickerAction = {
  id: string;
  name: string;
  applicability?: ActionApplicability[] | null;
};

type Props = {
  all: PickerAction[];
  selected: string[];
  onAdd: (id: string) => void;
  onRemove: (id: string) => void;
  disabled?: boolean;
};

export function ActionPicker({
  all,
  selected,
  onAdd,
  onRemove,
  disabled,
}: Props) {
  const selectedActions = all.filter((action) => selected.includes(action.id));
  const availableActions = all.filter(
    (action) => !selected.includes(action.id),
  );

  return (
    <div className="grid gap-2">
      <Label>Actions</Label>
      {selectedActions.length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {selectedActions.map((action) => (
            <Badge key={action.id} variant="secondary" className="gap-1 pr-1">
              {action.name}
              {applicabilityValues(action).length > 0 ? (
                <span className="text-muted-foreground">
                  @{applicabilityValues(action).join(",")}
                </span>
              ) : null}
              <button
                type="button"
                disabled={disabled}
                className="ml-0.5 rounded-sm opacity-70 hover:opacity-100 disabled:cursor-not-allowed"
                onClick={() => onRemove(action.id)}
              >
                <X className="h-3 w-3" />
                <span className="sr-only">Remove {action.name}</span>
              </button>
            </Badge>
          ))}
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">No actions selected.</p>
      )}
      {availableActions.length > 0 && (
        <Select
          disabled={disabled}
          value=""
          onValueChange={(id) => {
            if (id) onAdd(id);
          }}
        >
          <SelectTrigger className="w-full">
            <SelectValue placeholder="— add action —" />
          </SelectTrigger>
          <SelectContent>
            {availableActions.map((action) => (
              <SelectItem key={action.id} value={action.id}>
                {actionLabel(action)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
    </div>
  );
}
