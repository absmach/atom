import type { CrudFilter } from "@/lib/crud/resources";

export type Row = Record<string, unknown>;

export type CrudTableProps = {
  filters?: CrudFilter[];
  resourceKey: string;
  rows: Row[];
  total: number;
  page: number;
  limit: number;
  source: "graphql" | "scaffold";
};
