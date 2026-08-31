import type * as React from "react";
import { FormLabel } from "@/components/ui/form";

export function RequiredFormLabel({
  children,
  required,
}: {
  children: React.ReactNode;
  required?: boolean;
}) {
  return (
    <FormLabel>
      {children}
      {required ? <span className="text-destructive"> *</span> : null}
    </FormLabel>
  );
}
