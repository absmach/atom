"use client";

import { Search } from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import { Button } from "@/components/ui/button";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { crudResources } from "@/lib/crud/resources";

export function CommandMenu() {
  const [open, setOpen] = React.useState(false);
  const router = useRouter();

  React.useEffect(() => {
    const down = (event: KeyboardEvent) => {
      if (
        (event.key === "k" && (event.metaKey || event.ctrlKey)) ||
        event.key === "/"
      ) {
        event.preventDefault();
        setOpen((value) => !value);
      }
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  function go(path: string) {
    setOpen(false);
    router.push(path);
  }

  return (
    <>
      <Button
        variant="outline"
        className="h-8 w-full justify-start gap-2 text-muted-foreground sm:w-64"
        onClick={() => setOpen(true)}
      >
        <Search className="size-4" />
        <span>Search workflows</span>
        <kbd className="ml-auto hidden rounded border bg-muted px-1.5 font-mono text-[0.65rem] sm:inline">
          /
        </kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={setOpen}>
        <CommandInput placeholder="Open a workflow..." />
        <CommandList>
          <CommandEmpty>No workflow found.</CommandEmpty>
          <CommandGroup heading="Control plane">
            {[
              { title: "Dashboard", route: "/dashboard" },
              ...crudResources.map((resource) => ({
                title: resource.title,
                route: resource.route,
              })),
              { title: "Authorization debugger", route: "/authz" },
              { title: "Audit logs", route: "/audit" },
              { title: "API endpoints", route: "/endpoints" },
              { title: "Playground", route: "/playground" },
            ].map((item) => (
              <CommandItem
                key={`${item.title}-${item.route}`}
                onSelect={() => go(item.route)}
              >
                {item.title}
              </CommandItem>
            ))}
          </CommandGroup>
        </CommandList>
      </CommandDialog>
    </>
  );
}
