import type { Metadata } from "next";

export const metadata: Metadata = { title: "Dashboard" };

import { DashboardOverview } from "@/components/dashboard/dashboard-overview";

export default function DashboardPage() {
  return <DashboardOverview />;
}
