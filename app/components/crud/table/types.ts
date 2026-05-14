export type Row = Record<string, unknown>;

export type CrudTableProps = {
  resourceKey: string;
  rows: Row[];
  total: number;
  page: number;
  limit: number;
  source: "graphql" | "scaffold";
};
