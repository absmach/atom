"use client";

import { KeyRound, List, SlidersHorizontal } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { href: "/actions", label: "Actions", icon: KeyRound },
  { href: "/actions/applicability", label: "Action Applicability", icon: List },
  {
    href: "/actions/guardrails",
    label: "Assignment Guardrails",
    icon: SlidersHorizontal,
  },
];

export function ActionsNav() {
  const pathname = usePathname();

  return (
    <nav className="flex shrink-0 flex-row gap-1 pb-2 md:w-56 md:flex-col md:pb-0 md:pr-2">
      {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
        const isActive = pathname === href;
        return (
          <Link
            key={href}
            href={href}
            className={cn(
              "flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors",
              isActive
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:bg-muted hover:text-foreground",
            )}
          >
            <Icon className="size-4 shrink-0 hidden md:block" />
            <span>{label}</span>
          </Link>
        );
      })}
    </nav>
  );
}
