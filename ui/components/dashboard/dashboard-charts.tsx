"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  Pie,
  PieChart,
  XAxis,
  YAxis,
} from "recharts";
import {
  type ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart";

export type ChartDatum = {
  label: string;
  value: number;
  fill?: string;
};

const ENTITY_KIND_CONFIG = {
  human: { label: "Humans", color: "oklch(0.72 0.15 164)" },
  device: { label: "Devices", color: "oklch(0.70 0.14 220)" },
  service: { label: "Services", color: "oklch(0.68 0.13 290)" },
  workload: { label: "Workloads", color: "oklch(0.74 0.15 55)" },
  application: { label: "Applications", color: "oklch(0.71 0.14 195)" },
} satisfies ChartConfig;

const STATUS_CONFIG = {
  value: { label: "Count", color: "var(--chart-2)" },
} satisfies ChartConfig;

const RISK_CONFIG = {
  value: { label: "Items", color: "var(--chart-4)" },
} satisfies ChartConfig;

const RESOURCE_CONFIG = {
  value: { label: "Resources" },
} satisfies ChartConfig;

const RESOURCE_KIND_COLORS = [
  "oklch(0.72 0.15 164)", // green (on-theme)
  "oklch(0.70 0.14 220)", // blue
  "oklch(0.68 0.13 290)", // purple
  "oklch(0.74 0.15 55)", // amber
  "oklch(0.71 0.14 195)", // teal
  "oklch(0.70 0.14 350)", // rose
];

export function EntityKindDonut({ data }: { data: ChartDatum[] }) {
  if (data.every((item) => item.value === 0)) {
    return <EmptyChartState />;
  }

  return (
    <ChartContainer
      config={ENTITY_KIND_CONFIG}
      className="mx-auto aspect-square max-h-72"
    >
      <PieChart>
        <ChartTooltip content={<ChartTooltipContent hideLabel />} />
        <Pie
          data={data}
          dataKey="value"
          nameKey="label"
          innerRadius={58}
          outerRadius={88}
          paddingAngle={2}
        >
          {data.map((entry) => (
            <Cell key={entry.label} fill={entry.fill} />
          ))}
        </Pie>
      </PieChart>
    </ChartContainer>
  );
}

export function StatusBars({ data }: { data: ChartDatum[] }) {
  return (
    <ChartContainer config={STATUS_CONFIG} className="h-72 w-full">
      <BarChart data={data} layout="vertical" margin={{ left: 12, right: 28 }}>
        <CartesianGrid horizontal={false} />
        <YAxis
          dataKey="label"
          type="category"
          tickLine={false}
          axisLine={false}
          width={84}
        />
        <XAxis type="number" hide />
        <ChartTooltip content={<ChartTooltipContent hideLabel />} />
        <Bar
          dataKey="value"
          radius={4}
          fill="var(--color-value)"
          isAnimationActive={false}
        >
          <LabelList
            dataKey="value"
            position="right"
            className="fill-foreground"
            fontSize={12}
          />
        </Bar>
      </BarChart>
    </ChartContainer>
  );
}

export function RiskBars({ data }: { data: ChartDatum[] }) {
  return (
    <ChartContainer config={RISK_CONFIG} className="h-72 w-full">
      <BarChart data={data} margin={{ top: 12, right: 12, left: 0 }}>
        <CartesianGrid vertical={false} />
        <XAxis
          dataKey="label"
          tickLine={false}
          axisLine={false}
          tickMargin={8}
        />
        <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
        <ChartTooltip content={<ChartTooltipContent hideLabel />} />
        <Bar
          dataKey="value"
          radius={4}
          fill="var(--color-value)"
          isAnimationActive={false}
        />
      </BarChart>
    </ChartContainer>
  );
}

export function ResourceKindBars({ data }: { data: ChartDatum[] }) {
  return (
    <ChartContainer config={RESOURCE_CONFIG} className="h-72 w-full">
      <BarChart data={data} margin={{ top: 12, right: 12, left: 0 }}>
        <CartesianGrid vertical={false} />
        <XAxis
          dataKey="label"
          tickLine={false}
          axisLine={false}
          tickMargin={8}
        />
        <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
        <ChartTooltip content={<ChartTooltipContent hideLabel />} />
        <Bar dataKey="value" radius={4} isAnimationActive={false}>
          {data.map((entry, index) => (
            <Cell
              key={entry.label}
              fill={RESOURCE_KIND_COLORS[index % RESOURCE_KIND_COLORS.length]}
            />
          ))}
        </Bar>
      </BarChart>
    </ChartContainer>
  );
}

function EmptyChartState() {
  return (
    <div className="flex min-h-72 items-center justify-center rounded-md border text-sm text-muted-foreground">
      No data yet
    </div>
  );
}
