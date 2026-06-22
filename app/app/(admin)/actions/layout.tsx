import { ActionsNav } from "@/components/actions/actions-nav";

export default function ActionsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-0 flex-col gap-6 md:flex-row">
      <ActionsNav />
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}
