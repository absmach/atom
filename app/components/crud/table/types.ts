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
  /** Filters the list query already applied to `rows` and `total`. */
  serverFilters?: { search?: boolean; status?: boolean };
  /** When false, the deletedAt/deletedBy columns are hidden (live/active view). */
  showDeletedColumns?: boolean;
};
